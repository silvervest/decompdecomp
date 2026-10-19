"""The coordination core under the app's engine (app/engine): who works on what, what counts as a match, and what
everyone has learned.

Every public method here is one agent-facing action. They return plain text because the consumer is an LLM reading
a tool result.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import policy, scoring
from .compiler import compile_source
from .elfobj import FunctionObj, Reloc, extract_function
from .project import compiler_config, compiler_for
from .store import Store

CLAIM_TTL = 30 * 60
# A function an agent just released goes to the back of the queue for this long, for every agent: the next one
# starts on something fresh instead of passing the same function back and forth. Asked for by name, it comes at once.
RELEASE_COOLDOWN = 15 * 60
# The agent that released a function doesn't get it back automatically for this long, or until its run ends (the
# app writes a 'stopped' event when one of its helpers stops). It used to be kept off every function it ever
# released: helper identities are reused by name across runs (claude-haiku-1..8), so on demo_ltcg four Haiku helpers
# found "nothing left to claim" among exactly the ten functions their names gave up on in earlier runs, while a new
# Opus helper claimed at once. After that the function still comes to it last.
SELF_RELEASE_WINDOW = RELEASE_COOLDOWN
MACHINE_AGENTS = ("autopilot", "permuter")  # decompdecomp's own workers: their claims never mean "given up on"
# Twins first (see app/twins.py): a function whose code the game has more than once (boost: how many more times)
# and isn't too big or given up on, best value per instruction first; its twins (boost -1) last, as they match for
# free once it does.
_TWINS = ("(f.boost > 0 AND f.n_insns <= 400 AND f.abandons < 2) DESC, "
          "CASE WHEN f.boost > 0 THEN (f.boost + 1) * 64 / (f.n_insns + 16) ELSE 0 END DESC, f.boost < 0, ")
# Prerequisites (release_function's `needs`, the waits table): a function an agent found needs another one first
# (a callee whose convention or body it depends on, a helper the original inlines) waits, claimed after everything
# else, until that one matches; the one it waits for is claimed first meanwhile; once it matches, the waiting one
# comes first, once (its row goes when it's claimed).
# (two functions waiting for each other don't wait: each one's convention came from the other, a caller and its
# callee in one file, and they match together in one batch compile, so the queue mustn't hold both back for good)
WAITING = ("SELECT w.function_id FROM waits w JOIN functions n ON n.id=w.needs_id WHERE n.status != 'matched' "
           "AND NOT EXISTS (SELECT 1 FROM waits w2 WHERE w2.function_id=w.needs_id AND w2.needs_id=w.function_id)")
READY = "SELECT w.function_id FROM waits w JOIN functions n ON n.id=w.needs_id WHERE n.status = 'matched'"
WANTED = "SELECT w.needs_id FROM waits w JOIN functions b ON b.id=w.function_id WHERE b.status = 'open'"
STRATEGIES = {
    "easiest": _TWINS + "f.abandons > 0, f.n_insns ASC",
    # what nobody gave up on, small first; among functions of about the same size, the files closest to done (a
    # file is linked into the game once all of it matches). Leftovers agents released again and again come last,
    # or a crowd of agents spends its time passing the hardest functions around.
    "finish": _TWINS + "f.abandons ASC, (f.n_insns + 31) / 32 ASC, (SELECT COUNT(*) FROM functions g WHERE "
                       "g.project_id=f.project_id AND g.unit=f.unit AND g.status='open') ASC, f.n_insns ASC",
    # near-misses, the ones given up on least first (else every agent resumes the same stuck one)
    "closest": "f.best_score IS NULL, f.abandons ASC, CAST(f.best_score AS REAL) / (f.n_insns * 100) ASC",
    "hardest": "f.n_insns DESC",
    "random": "RANDOM()",
}


class NetworkError(Exception):
    """An error meant to be shown to the agent as-is."""


def move_on_after(n_insns: int | None) -> int:
    """compile_and_diff's move-on rule: no better in this many compiles in a row. Big functions get longer (a
    quarter of Mario Party 6's agent matches over 64 instructions took more than 4 compiles)."""
    n = n_insns or 0
    return 4 if n < 64 else 6 if n < 128 else 8 if n < 256 else 10


def _no_better(scores: list[int | None]) -> int:
    """How many of the last compiles in a row (oldest first in `scores`) didn't beat the best before them."""
    best, since = None, 0
    for s in scores:
        if s is not None and (best is None or s < best):
            best, since = s, 0
        else:
            since += 1
    return since


# A note that says the function matches (written while a function that later stopped matching counted as matched,
# its best score 0): agents read it over the brief's real score and stopped
_SAYS_MATCHED = re.compile(r"already\s+(?:at\s+)?100\s*%|already\s+match(?:es|ed)\b|\b(?:is|was|now)\s+(?:100\s*%|"
                           r"matched\b|a\s+match\b)|100(?:\.0+)?\s*%\s*(?:match|identical)|\bscore\s+0(?![\d.])|✅\s*MATCH|"
                           r"byte[- ]identical", re.I)
_NEGATED = re.compile(r"\b(?:not|n't|never|no|without)\b[^.;]{0,24}$", re.I)


def stale_note(text: str, status: str) -> str:
    """A note as a brief shows it: one saying the function matches, on a function that doesn't, is marked out of
    date (the note itself stays as it was), so the brief's score is the number agents go by."""
    if status == "matched":
        return text
    for m in _SAYS_MATCHED.finditer(text):
        if not _NEGATED.search(text[max(0, m.start() - 40):m.start()]):
            return ("[out of date: written when the function counted as matched; it doesn't match now, so go by the "
                    "score above] " + text)
    return text


@dataclass
class Agent:
    id: int
    name: str
    owner: str | None
    trusted: bool = False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    return f"{s}s ago" if s < 120 else f"{s // 60}m ago" if s < 7200 else f"{s // 3600}h ago"


class Network:
    def __init__(self, db_path: str | Path, claim_ttl: int = CLAIM_TTL):
        self.store = Store(db_path)
        self.claim_ttl = claim_ttl
        self._pool = ThreadPoolExecutor(max_workers=8)

    # ------------------------------------------------------------------ agents

    def register_agent(self, name: str, owner: str | None = None, *, trusted: bool = True, origin: str = "cli",
                       terms_accepted: bool = False) -> str:
        """Mint an agent token. Operator-created (CLI) agents are trusted; self-registered (web) agents
        start at reputation level 'new' and earn the rest through verified matches."""
        name = name.strip()
        if not name or len(name) > 40 or not all(c.isalnum() or c in "-_." for c in name):
            raise NetworkError("agent name must be 1-40 chars of [A-Za-z0-9-_.]")
        owner = (owner or "").strip()[:60] or None
        token = "dn_" + secrets.token_urlsafe(24)
        now = time.time()
        with self.store.tx() as db:
            if db.execute("SELECT 1 FROM agents WHERE lower(name)=lower(?)", (name,)).fetchone():
                raise NetworkError(f"agent name {name!r} is taken")
            db.execute(
                "INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin,terms_accepted_at) VALUES(?,?,?,?,?,?,?)",
                (name, owner, _hash_token(token), now, int(trusted), origin, now if terms_accepted else None),
            )
        return token

    def authenticate(self, token: str | None) -> Agent:
        if not token:
            raise NetworkError("missing API token: add `--header \"Authorization: Bearer dn_...\"` to your MCP config")
        row = self.store.one("SELECT id,name,owner,trusted FROM agents WHERE token_hash=?", _hash_token(token))
        if row is None:
            raise NetworkError("invalid API token")
        with self.store.tx() as db:
            db.execute("UPDATE agents SET last_seen=? WHERE id=?", (time.time(), row["id"]))
        return Agent(row["id"], row["name"], row["owner"], bool(row["trusted"]))

    def _require_budget(self, agent: Agent) -> None:
        ok, why = policy.compile_budget(self.store, agent.id)
        if not ok:
            raise NetworkError(why)

    def _require_level(self, agent: Agent, what: str) -> None:
        rep = policy.reputation(self.store, agent.id)
        if not rep["level"].can_edit_context:
            raise NetworkError(f"{what} needs reputation level 'member' (one verified match). You are '{rep['level'].name}': "
                               f"match a function first; add_note is open to everyone.")

    # ---------------------------------------------------------------- helpers

    def _project(self, slug: str | None):
        if slug:
            row = self.store.one("SELECT * FROM projects WHERE slug=?", slug)
            if row is None:
                raise NetworkError(f"no project {slug!r}; call list_projects")
            return row
        rows = self.store.all("SELECT * FROM projects")
        if len(rows) == 1:
            return rows[0]
        raise NetworkError("several projects exist; pass `project` (see list_projects)")

    def _function(self, name: str, project: str | None):
        if project is None and "/" in name and "@" not in name.split("/", 1)[0]:  # project/name (fork names hold units)
            project, name = name.split("/", 1)
        if project is None:
            rows = self.store.all("SELECT * FROM functions WHERE name=?", name)
            if len(rows) > 1:
                raise NetworkError(f"{name!r} exists in several projects; pass `project`")
            row = rows[0] if rows else None
        else:
            row = self.store.one(
                "SELECT f.* FROM functions f JOIN projects p ON p.id=f.project_id WHERE p.slug=? AND f.name=?",
                project, name,
            )
        if row is None:
            raise NetworkError(f"no function {name!r}" + (f" in {project!r}" if project else ""))
        return row

    def _context(self, project_id: int, unit: str | None = ""):
        """Latest header for a translation unit, falling back to the project-wide one. Real codebases have
        one header set per source file; small projects just have the project-wide header ('' unit)."""
        unit = unit or ""
        return self.store.one(
            "SELECT * FROM context_versions WHERE project_id=? AND unit IN (?, '') "
            "ORDER BY unit=? DESC, version DESC LIMIT 1", project_id, unit, unit)

    def _unit_contexts(self, project_id: int) -> set[str]:
        return {r["unit"] for r in self.store.all(
            "SELECT DISTINCT unit FROM context_versions WHERE project_id=? AND unit != ''", project_id)}

    def _effective_unit(self, fn, units: set[str]) -> str:
        return fn["unit"] if fn["unit"] in units else ""

    def _target_obj(self, fn, proj) -> FunctionObj:
        return FunctionObj(
            name=fn["name"], arch=proj["arch"], big_endian=bool(proj["big_endian"]), code=fn["target"],
            relocs=[Reloc.from_json(r) for r in json.loads(fn["relocs"])],
        )

    def _expire_claims(self, db) -> None:
        now = time.time()
        own = {r["id"] for r in db.execute("SELECT id FROM agents WHERE name IN (?, ?)", MACHINE_AGENTS)}
        for row in db.execute("SELECT c.function_id, c.agent_id, f.project_id, f.name FROM claims c "
                              "JOIN functions f ON f.id=c.function_id WHERE c.expires_at < ?", (now,)).fetchall():
            if row["agent_id"] in own:  # decompdecomp's own tries (cut short by a restart): nobody gave up on it
                continue
            db.execute("UPDATE functions SET abandons=abandons+1 WHERE id=?", (row["function_id"],))
            self._event(db, row["project_id"], row["agent_id"], "expired", row["name"])
        db.execute("DELETE FROM claims WHERE expires_at < ?", (now,))

    def _event(self, db, project_id, agent_id, kind, detail) -> None:
        db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                   (project_id, agent_id, kind, detail, time.time()))

    def _agent_name(self, agent_id) -> str:
        row = self.store.one("SELECT name FROM agents WHERE id=?", agent_id) if agent_id else None
        return row["name"] if row else "?"

    def _compile(self, proj, header: str, source: str, fn=None):
        """Compiled with the project's compiler, or for `fn` the one its address range is built with."""
        cfg = json.loads(proj["config"])
        if fn is not None and cfg.get("compiler_ranges"):
            cfg = {**cfg, "compiler": compiler_for(cfg, fn["vram"])}
        return compile_source(compiler_config(Path(proj["root"]), cfg), header, source)

    def _evaluate(self, fn, proj, obj: bytes) -> tuple[FunctionObj | None, bool | None, list[str]]:
        """(candidate, verdict, problems) for a compiled object. verdict None means: decide by comparing
        fingerprints. Projects whose targets come from a ROM link the candidate instead (see app.engine)."""
        return extract_function(obj, fn["name"]), None, []

    def _asm_text(self, fn, proj) -> str:
        return fn["asm"]

    def _extra_brief(self, fn, proj) -> list[str]:
        return []

    # ---------------------------------------------------------------- projects

    def list_projects(self) -> str:
        rows = self.store.all(
            """SELECT p.slug, p.name, p.arch, p.description, p.config, COUNT(f.id) AS total,
                      SUM(f.status='matched') AS matched, SUM(f.size) AS bytes,
                      SUM(CASE WHEN f.status='matched' THEN f.size ELSE 0 END) AS matched_bytes
               FROM projects p LEFT JOIN functions f ON f.project_id=p.id GROUP BY p.id ORDER BY p.slug"""
        )
        if not rows:
            return "No projects yet."
        out = []
        for r in rows:
            pct = 100 * (r["matched_bytes"] or 0) / (r["bytes"] or 1)
            legal = json.loads(r["config"]).get("legal", {})
            out.append(f"- {r['slug']}: {r['name']} [{r['arch']}] — {r['matched'] or 0}/{r['total']} functions "
                       f"matched ({pct:.1f}% of code); legal basis: {legal.get('basis')}, contributions licensed "
                       f"{legal.get('license')}\n  {r['description']}".rstrip())
        return "\n".join(out)

    def get_context(self, project: str | None, function: str | None = None) -> str:
        if function:
            fn = self._function(function, project)
            proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
            ctx = self._context(proj["id"], fn["unit"])
        else:
            proj = self._project(project)
            if self._unit_contexts(proj["id"]):
                raise NetworkError(f"{proj['slug']} has one header per source file: pass `function` to get the "
                                   f"header that function compiles against")
            ctx = self._context(proj["id"])
        return (f"// context.h for {proj['slug']} — version {ctx['version']} "
                f"(prepended to every compile as #include \"context.h\")\n{ctx['header']}")

    # ------------------------------------------------------------------ claims

    def claim(self, agent: Agent, project: str | None = None, function: str | None = None,
              strategy: str = "easiest") -> str:
        still = self.still_holding(agent, function)
        fn = self.claim_row(agent, project, function, strategy)
        if fn is None:
            return self.nothing_to_claim(agent, self._project(project))
        return still + self._brief(fn, agent, header="CLAIMED")

    def still_holding(self, agent: Agent, function: str | None) -> str:
        """What to say first when claim_function (no function named) gives an agent the one it already holds: after
        a pushed-back release it still does, and an agent read the same brief coming back as the queue handing it
        back the function it had just released."""
        if function:
            return ""
        held = self.store.one("SELECT f.name, c.claimed_at FROM claims c JOIN functions f ON f.id=c.function_id "
                              "WHERE c.agent_id=?", agent.id)
        if held is None or not self.store.one(
                "SELECT 1 FROM events WHERE agent_id=? AND kind='release_pushed' AND detail=? AND created_at >= ?",
                agent.id, held["name"], held["claimed_at"] or 0):
            return ""  # an ordinary renewal of the claim
        return (f"You still hold {held['name']}: it wasn't released (a pushed-back release_function keeps it yours "
                "until you compile it once more), so this is your claim on it, not a new one. Compile the next step, "
                "then release_function goes through if it's still no better.\n\n")

    def _own_release_cutoff(self, db, agent_id: int, now: float) -> float:
        """Releases by this agent after this time keep it off those functions: the last SELF_RELEASE_WINDOW, and
        only since its run started (its last 'stopped' event)."""
        row = db.execute("SELECT MAX(created_at) AS t FROM events WHERE agent_id=? AND kind='stopped'",
                         (agent_id,)).fetchone()
        return max(now - SELF_RELEASE_WINDOW, (row["t"] if row else None) or 0)

    def nothing_to_claim(self, agent: Agent, proj, scope: str = "") -> str:
        """What a claim that found nothing tells the agent: whether the open functions are held (by whom, for how
        long), ones it set aside itself (which it can still take by name), or really all done. A bare "nothing left"
        sent four helpers away from a project with ten open functions."""
        now = time.time()
        n_open = self.store.one("SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND status='open'",
                                proj["id"])["n"]
        if not n_open:
            return f"Nothing left to claim in {proj['slug']}: every function{scope} matches. 🎉"
        held = self.store.all(
            "SELECT f.name, a.name AS agent, c.expires_at FROM claims c JOIN functions f ON f.id=c.function_id "
            "LEFT JOIN agents a ON a.id=c.agent_id WHERE f.project_id=? AND f.status='open' ORDER BY c.expires_at",
            proj["id"])
        with self.store.tx() as db:
            cutoff = self._own_release_cutoff(db, agent.id, now)
        mine = self.store.all(
            "SELECT DISTINCT f.name FROM functions f JOIN events e ON e.project_id=f.project_id AND e.detail=f.name "
            "WHERE f.project_id=? AND f.status='open' AND e.agent_id=? AND e.kind='release' AND e.created_at > ? "
            "AND f.id NOT IN (SELECT function_id FROM claims) ORDER BY f.name", proj["id"], agent.id, cutoff)
        lines = [f"Nothing to claim in {proj['slug']} right now: {n_open} function{'s' * (n_open != 1)} "
                 f"{'are' if n_open != 1 else 'is'} open, but none is free for you."]
        if held:
            shown = ", ".join(f"{r['name']} ({r['agent'] or '?'}, {max(0, int(r['expires_at'] - now)) // 60} min left)"
                              for r in held[:10])
            lines.append(f"{len(held)} held by other agents: {shown}{', ...' if len(held) > 10 else ''}. Each is "
                         "free again when its agent matches or releases it, or when its lease runs out.")
        if mine:
            names = [r["name"] for r in mine]
            lines.append(f"{len(names)} you released yourself in the last {SELF_RELEASE_WINDOW // 60} minutes: "
                         f"{', '.join(names[:10])}{', ...' if len(names) > 10 else ''}. They come back to you later. "
                         f"To take one now, call claim_function with function=\"{names[0]}\".")
        return "\n".join(lines)

    def claim_row(self, agent: Agent, project: str | None = None, function: str | None = None,
                  strategy: str = "easiest"):
        """Claim (or renew) a function and return its row, or None when nothing is left."""
        if strategy not in STRATEGIES:
            raise NetworkError(f"strategy must be one of {', '.join(STRATEGIES)}")
        proj = self._project(project) if (project or function is None) else None
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            held = db.execute("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=?",
                              (agent.id,)).fetchone()
            if held is not None:
                if function and held["id"] != self._function(function, proj["slug"] if proj else None)["id"]:
                    want = self._function(function, proj["slug"] if proj else None)["name"]
                    raise NetworkError(f"you already hold {held['name']}; match it or release_function it first (if "
                                       f"{held['name']} needs {want} done first, release_function with "
                                       f"needs=\"{want}\": that records it and hands you {want})")
                fn = held
                db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (now + self.claim_ttl, fn["id"]))
            elif function:
                fn = self._function(function, proj["slug"] if proj else None)
                if fn["status"] == "matched":
                    raise NetworkError(f"{fn['name']} is already matched; use get_function to read its source")
                if fn["status"] == "asm":
                    raise NetworkError(f"{fn['name']} is hand-written assembly: no C compiles to it, so it's left out")
                other = db.execute("SELECT agent_id, expires_at FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
                if other is not None:
                    raise NetworkError(f"{fn['name']} is claimed by {self._agent_name(other['agent_id'])} "
                                       f"for another {int(other['expires_at'] - now) // 60} min")
                db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + self.claim_ttl))
                self._event(db, fn["project_id"], agent.id, "claim", fn["name"])
            else:
                # not what this agent released lately (see SELF_RELEASE_WINDOW); what it released before that last
                # functions waiting for another to match come last (WAITING); the ones they wait for, and those whose
                # wait is over, first (after what the release rules put back)
                fn = db.execute(
                    f"""SELECT f.* FROM functions f WHERE f.project_id=? AND f.status='open'
                        AND f.id NOT IN (SELECT function_id FROM claims)
                        AND f.name NOT IN (SELECT detail FROM events WHERE project_id=? AND agent_id=? AND kind='release'
                                           AND created_at > ?)
                        ORDER BY f.id IN ({WAITING}),
                                 f.name IN (SELECT detail FROM events WHERE project_id=? AND agent_id=? AND kind='release'),
                                 f.name IN (SELECT detail FROM events WHERE project_id=? AND kind='release'
                                            AND created_at > ?),
                                 f.id IN ({READY}) DESC, f.id IN ({WANTED}) DESC, {STRATEGIES[strategy]} LIMIT 1""",
                    (proj["id"], proj["id"], agent.id, self._own_release_cutoff(db, agent.id, now),
                     proj["id"], agent.id, proj["id"], now - RELEASE_COOLDOWN),
                ).fetchone()
                if fn is None:
                    return None
                db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + self.claim_ttl))
                self._event(db, fn["project_id"], agent.id, "claim", fn["name"])
            # a wait that's over has had its turn at the front once it's claimed
            db.execute("DELETE FROM waits WHERE function_id=? AND needs_id IN (SELECT id FROM functions "
                       "WHERE status='matched')", (fn["id"],))
        return fn

    def release(self, agent: Agent, function: str, notes: str, project: str | None = None) -> str:
        fn = self._function(function, project)
        with self.store.tx() as db:
            row = db.execute("SELECT agent_id FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
            if row is None or row["agent_id"] != agent.id:
                raise NetworkError(f"you don't hold a claim on {fn['name']}")
            db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            db.execute("UPDATE functions SET abandons=abandons+1 WHERE id=?", (fn["id"],))
            if notes.strip():
                db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                           (fn["project_id"], fn["id"], agent.id, notes.strip(), time.time()))
            self._event(db, fn["project_id"], agent.id, "release", fn["name"])
        return (f"Released {fn['name']}. Your best attempt and notes are saved so the next agent starts "
                f"where you left off. Call claim_function for a new one.")

    def release_stopped(self, agent_ids, why: str) -> list[str]:
        """The claims of agents whose process is gone, released at once with a note (`why`), instead of holding their
        functions until CLAIM_TTL runs out: after an update or a restart of the app, every open function looked held
        by helpers that had died with it. Not counted as giving up. Each agent also gets a 'stopped' event, which
        ends its run: what it released before no longer keeps it off those functions (SELF_RELEASE_WINDOW).
        Returns the functions released."""
        now, freed = time.time(), []
        with self.store.tx() as db:
            own = {r["id"] for r in db.execute("SELECT id FROM agents WHERE name IN (?, ?)", MACHINE_AGENTS)}
            for aid in agent_ids:
                rows = db.execute("SELECT f.id, f.project_id, f.name FROM claims c JOIN functions f ON f.id=c.function_id "
                                  "WHERE c.agent_id=?", (aid,)).fetchall()
                db.execute("DELETE FROM claims WHERE agent_id=?", (aid,))
                for r in rows:
                    if aid not in own:  # decompdecomp's own tries leave no notes
                        db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                                   (r["project_id"], r["id"], aid, f"Released because its agent stopped ({why}); its "
                                    "attempts are kept.", now))
                    self._event(db, r["project_id"], aid, "stopped", r["name"])
                    freed.append(r["name"])
                if not rows:
                    self._event(db, None, aid, "stopped", "")
        return freed

    def release_local_claims(self, why: str) -> list[str]:
        """When the app starts: none of its own helpers (origin 'local') or workers (autopilot, permuter) is running
        yet, so whatever they hold is left over from the last run. Agents that run elsewhere (the one the user talks
        to, a room's members) may still be working: theirs keep the CLAIM_TTL rule."""
        ids = [r["id"] for r in self.store.all("SELECT id FROM agents WHERE origin='local' OR name IN (?, ?)",
                                               *MACHINE_AGENTS)]
        return self.release_stopped(ids, why)

    def get_function(self, function: str, project: str | None = None, agent: Agent | None = None) -> str:
        return self._brief(self._function(function, project), agent, header="VIEW")

    def _brief(self, fn, agent: Agent | None, header: str) -> str:
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        ctx = self._context(proj["id"], fn["unit"])
        claim = self.store.one("SELECT * FROM claims WHERE function_id=?", fn["id"])
        lines = [f"## {header}: {proj['slug']}/{fn['name']}",
                 f"size {fn['size']} bytes, {fn['n_insns']} instructions, arch {proj['arch']}, "
                 f"context.h v{ctx['version']} ({len(ctx['header'].splitlines())} lines)"]
        cfg = json.loads(proj["config"])
        own = compiler_for(cfg, fn["vram"])
        if own is not cfg.get("compiler"):  # a range built by another compiler than the rest of the game
            lines.append(f"compiled with {own['toolchain']} {' '.join(own['flags'])}: this address range's compiler, "
                         f"not the project's")
        if claim:
            who = "you" if agent and claim["agent_id"] == agent.id else self._agent_name(claim["agent_id"])
            lines.append(f"claimed by {who}, lease expires in {int(claim['expires_at'] - time.time()) // 60} min "
                         f"(each compile_and_diff renews it)")
        if fn["status"] == "matched":
            lines += [f"MATCHED by {self._agent_name(fn['matched_agent_id'])} {_ago(fn['matched_at'])}:",
                      "```c", fn["matched_source"].strip(), "```"]
        lines += ["", "### Target assembly", "```asm", scoring.compact_asm(self._asm_text(fn, proj)), "```"]
        lines += self._extra_brief(fn, proj)
        if fn["status"] != "matched":
            if fn["best_source"]:
                lines += ["", f"### Best attempt so far: score {fn['best_score']} by "
                              f"{self._agent_name(fn['best_agent_id'])} ({fn['attempts']} attempts total) — "
                              f"start from this", "```c", fn["best_source"].strip(), "```"]
            elif fn["seed"]:
                lines += ["", "### Machine-generated starting point (m2c: expect wrong types and names; "
                              "the context header helps)", "```c",
                          fn["seed"].strip(), "```"]
        notes = self.store.all(
            "SELECT n.text, n.created_at, a.name FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.function_id=? ORDER BY n.id DESC LIMIT 8", fn["id"])
        if notes:
            lines += ["", "### Notes from previous agents on this function"]
            lines += [f"- ({n['name']}, {_ago(n['created_at'])}) {stale_note(n['text'], fn['status'])}" for n in notes]
        lines += self.dependency_brief(fn)
        pnotes = self.store.all(
            "SELECT n.text, a.name FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.project_id=? AND n.function_id IS NULL ORDER BY n.id DESC LIMIT 5", proj["id"])
        if pnotes:
            lines += ["", "### Project-wide notes (latest)"] + [f"- ({n['name']}) {n['text']}" for n in pnotes]
        if fn["unit"] and fn["unit"] in self._unit_contexts(proj["id"]):
            lines.insert(2, f"source unit {fn['unit']}: call get_context with function=\"{fn['name']}\" for its header")
        if header == "CLAIMED":
            lines += ["", "Next: read context.h with get_context, write C for this function, and iterate with "
                          "compile_and_diff until score is 0. Submit only the function body (plus any helper "
                          "declarations); context.h is included automatically."]
        return "\n".join(lines)

    # --------------------------------------------------------- compile & diff

    def compile_and_diff(self, agent: Agent, function: str, source: str, project: str | None = None) -> str:
        return self.attempt(agent, function, source, project)["text"]

    def attempt(self, agent: Agent, function: str, source: str, project: str | None = None) -> dict:
        """Compile, score and record one attempt. Returns {"text", "score", "matched"} (score None: didn't compile)."""
        self._require_budget(agent)
        fn = self._function(function, project)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        now = time.time()

        # Claim bookkeeping first: you can't score (or get credit) on someone else's function.
        with self.store.tx() as db:
            self._expire_claims(db)
            claim = db.execute("SELECT agent_id FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
            scratch = fn["status"] == "matched"
            if not scratch:
                if claim is None:
                    held = db.execute("SELECT 1 FROM claims WHERE agent_id=?", (agent.id,)).fetchone()
                    if held:
                        raise NetworkError("you hold another claim; release it before working on a different function")
                    db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + self.claim_ttl))
                    self._event(db, fn["project_id"], agent.id, "claim", fn["name"])
                elif claim["agent_id"] != agent.id:
                    raise NetworkError(f"{fn['name']} is claimed by {self._agent_name(claim['agent_id'])}")
                else:
                    db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (now + self.claim_ttl, fn["id"]))

        ctx = self._context(proj["id"], fn["unit"])
        result = self._compile(proj, ctx["header"], source, fn)

        if not result.ok:
            self._record(fn, agent, None, source, ctx["version"])
            return {"text": f"❌ COMPILE ERROR (context v{ctx['version']})\n{result.log.strip()}", "score": None, "matched": False}

        cand, verdict, problems = self._evaluate(fn, proj, result.obj)
        if cand is None:
            self._record(fn, agent, None, source, ctx["version"])
            return {"text": f"❌ Compiled, but the object has no function named `{fn['name']}`. "
                            f"Define it with exactly that name (non-static).", "score": None, "matched": False}
        d = scoring.diff(self._target_obj(fn, proj), cand)
        if verdict is not None:
            d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
        matched_now = d.bytes_match and not scratch
        self._record(fn, agent, d.score, source, ctx["version"], matched=matched_now)

        if scratch:
            head = f"(scratch — {fn['name']} was already matched) score {d.score}"
        elif d.bytes_match:
            return {"text": f"✅ MATCH! {fn['name']} is byte-identical to the target ({fn['n_insns']} instructions). "
                            f"Credited to {agent.name}; your claim is released. Call claim_function for the next one."
                            f"{self.dependents_note(fn['id'])}",
                    "score": 0, "matched": True}
        else:
            best = self.store.one("SELECT best_score FROM functions WHERE id=?", fn["id"])["best_score"]
            head = (f"score {d.score} ({scoring.percent_text(d.percent)} match) — best so far {best}. "
                    f"Target {len([r for r in d.rows if r[1]])} insns, yours {len([r for r in d.rows if r[2]])}.")
            if d.rows and all(m == " " for m, _, _ in d.rows):
                head += ("\nNOT A MATCH YET: every instruction reads the same, but the bytes differ"
                         + (" because of the linking notes at the end: fix those." if problems else
                            ": an encoding the listing doesn't show (branch form, an immediate, a relocation)."))
        warn = f"\ncompiler output:\n{result.log.strip()}" if result.log.strip() else ""
        if problems:
            warn += "\nwhen linking your code at the function's address:\n" + "\n".join(f"- {p}" for p in problems)
        return {"text": f"{head}\n{d.render()}{warn}{self.stall_note(fn['id'], agent.id)}", "score": d.score, "matched": False}

    def stall_note(self, function_id: int, agent_id: int, after: int | None = None) -> str:
        """A nudge once an agent's last `after` compiles of a function didn't beat its best: functions that match
        mostly do in the first few tries, and the agent's time is better spent on the next one. Big functions get
        longer (a quarter of Mario Party 6's agent matches over 64 instructions took more than 4 compiles, and
        those functions hold most of the code left)."""
        if after is None:
            row = self.store.one("SELECT n_insns FROM functions WHERE id=?", function_id)
            after = move_on_after(row["n_insns"] if row else 0)
        rows = self.store.all("SELECT score FROM attempts WHERE function_id=? AND agent_id=? ORDER BY id DESC LIMIT 16",
                              function_id, agent_id)
        since = _no_better([r["score"] for r in reversed(rows)])
        if since < after:
            return ""
        return (f"\n\n⏭ No better in your last {since} compiles. release_function with notes (what you tried, what's "
                "left) and claim the next one: functions that match mostly do in the first few tries, and this one "
                "keeps your best attempt for whoever comes next.")

    def claim_progress(self, agent: Agent, fn) -> dict | None:
        """This agent's claim on `fn` as release_function judges it: compiles since it claimed it, how many in a row
        were no better than its best, and compile_and_diff's move-on rule (stall_note's). None: no claim."""
        claim = self.store.one("SELECT claimed_at FROM claims WHERE function_id=? AND agent_id=?", fn["id"], agent.id)
        if claim is None:
            return None
        start = claim["claimed_at"] or 0
        rows = self.store.all("SELECT score FROM attempts WHERE function_id=? AND agent_id=? AND created_at >= ? "
                              "ORDER BY id", fn["id"], agent.id, start)
        scores = [r["score"] for r in rows]
        return {"claimed_at": start, "compiles": len(scores), "no_better": _no_better(scores),
                "after": move_on_after(fn["n_insns"]),
                "best": min((s for s in scores if s is not None), default=None)}

    # ---------------------------------------------------------- prerequisites

    def wait_for(self, agent: Agent, fn, needs) -> None:
        """Record that `fn` needs `needs` done first (see WAITING)."""
        with self.store.tx() as db:
            db.execute("INSERT OR REPLACE INTO waits(function_id, needs_id, agent_id, created_at) VALUES(?,?,?,?)",
                       (fn["id"], needs["id"], agent.id, time.time()))
            self._event(db, fn["project_id"], agent.id, "waits", f"{fn['name']} -> {needs['name']}")

    def dependency_brief(self, fn) -> list[str]:
        """For a brief: what this function waits for, and what waits for it."""
        out = []
        row = self.store.one("SELECT n.name, n.status, a.name AS agent FROM waits w JOIN functions n ON n.id=w.needs_id "
                             "LEFT JOIN agents a ON a.id=w.agent_id WHERE w.function_id=?", fn["id"])
        if row is not None and fn["status"] != "matched":
            if row["status"] == "matched":
                out += ["", f"### {row['name']} matches now: {row['agent'] or 'an agent'} found this function needs it "
                            f"first (a callee or an inlined helper): read its code (get_function) and use it here."]
            elif self.store.one("SELECT 1 FROM waits WHERE function_id=(SELECT id FROM functions WHERE name=? AND "
                                "project_id=?) AND needs_id=?", row["name"], fn["project_id"], fn["id"]):
                out += ["", f"### Needs {row['name']}, which needs this one: they depend on each other (a caller and its "
                            "callee, each one's convention coming from the other), so work on them together: "
                            f"compile_and_diff(function=\"{fn['name']}, {row['name']}\", source=both definitions)."]
            else:
                out += ["", f"### Waits for {row['name']}: {row['agent'] or 'an agent'} found this function needs it "
                            f"first (a callee or an inlined helper), so it's claimed after everything else until "
                            f"{row['name']} matches. Work on it if you can; else release_function with "
                            f"needs=\"{row['name']}\"."]
        waiting = self.store.all("SELECT b.name FROM waits w JOIN functions b ON b.id=w.function_id WHERE w.needs_id=? "
                                 "AND b.status='open' ORDER BY b.name LIMIT 8", fn["id"])
        if waiting and fn["status"] != "matched":
            out += ["", f"### Waited for by {', '.join(r['name'] for r in waiting)}: they need this one first, so "
                        "matching it unblocks them."]
        return out

    def dependents_note(self, function_id: int) -> str:
        """For a match: the functions that were waiting for it."""
        rows = self.store.all("SELECT b.name FROM waits w JOIN functions b ON b.id=w.function_id WHERE w.needs_id=? "
                              "AND b.status='open' ORDER BY b.name LIMIT 6", function_id)
        if not rows:
            return ""
        return (f"\nWaiting for this one: {', '.join(r['name'] for r in rows)}. They come first in the queue now; "
                f"claim_function(function=\"{rows[0]['name']}\") takes one next.")

    def _record(self, fn, agent: Agent, score: int | None, source: str, ctx_version: int, matched: bool = False,
                compiled: bool | None = None, via: str = "agent"):
        now = time.time()
        compiled = score is not None if compiled is None else compiled
        with self.store.tx() as db:
            db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,context_version,source,created_at,via) "
                       "VALUES(?,?,?,?,?,?,?,?)", (fn["id"], agent.id, score, compiled, ctx_version, source, now, via))
            db.execute("UPDATE functions SET attempts=attempts+1 WHERE id=?", (fn["id"],))
            if score is not None:
                db.execute("UPDATE functions SET best_score=?, best_source=?, best_agent_id=? "
                           "WHERE id=? AND status='open' AND (best_score IS NULL OR best_score > ?)",
                           (score, source, agent.id, fn["id"], score))
            if matched:
                db.execute("UPDATE functions SET status='matched', matched_source=?, matched_agent_id=?, "
                           "matched_at=?, best_score=0, best_source=? WHERE id=?",
                           (source, agent.id, now, source, fn["id"]))
                db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
                self._event(db, fn["project_id"], agent.id, "match", fn["name"])
        if matched:
            self.on_match(self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"]), fn["id"], agent)

    def on_match(self, proj, function_id: int, agent: Agent | None = None) -> None:
        """A function just matched (subclasses try its code on its twins)."""

    # -------------------------------------------------------- shared context

    def edit_context(self, agent: Agent, project: str | None, old: str, new: str, message: str,
                     function: str | None = None) -> str:
        """Exact-string edit of a header. Accepted only if every already-matched function compiled against
        that header still matches with the new one — that's the project's test suite."""
        self._require_level(agent, "Editing the shared header")
        if function:
            fn = self._function(function, project)
            proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
            unit = self._effective_unit(fn, self._unit_contexts(proj["id"]))
        else:
            proj = self._project(project)
            if self._unit_contexts(proj["id"]):
                raise NetworkError(f"{proj['slug']} has one header per source file: pass `function` to edit the "
                                   f"header that function compiles against")
            unit = ""
        if not message.strip():
            raise NetworkError("give a short commit message explaining the change")
        for _ in range(3):
            ctx = self._context(proj["id"], unit)
            header = ctx["header"]
            if old:
                from .textedit import replace_once

                new_header = replace_once(header, old, new, "the header")
            else:
                new_header = header.rstrip("\n") + "\n\n" + new.strip("\n") + "\n"
            members = self._matched_using(proj, unit)
            broken = self.regression_test(proj, new_header, only=members)
            if broken:
                listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
                return (f"❌ REJECTED: the edit breaks {len(broken)} already-matched function(s), so the header "
                        f"stays at v{ctx['version']}.\n{listing}")
            with self.store.tx() as db:
                if self._latest_version(db, proj["id"], unit) != ctx["version"]:
                    continue  # someone else committed meanwhile: re-apply on top and re-test
                version = self._next_version(db, proj["id"])
                db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                           "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, new_header, agent.id, message.strip(), time.time(), unit))
                self._event(db, proj["id"], agent.id, "context", f"v{version}{f' ({unit})' if unit else ''}: {message.strip()}")
            return f"✅ header is now v{version} (all {len(members)} matched functions that use it still match)."
        raise NetworkError("the header is being edited heavily right now; re-read it and retry")

    def rename_symbol(self, agent: Agent, project: str | None, old: str, new: str, message: str = "") -> str:
        """Project-wide refactor: rename an identifier (field, type, global, function param...) in every
        header *and* in every matched source / best attempt, then regression-test the result.
        The rename is textual (whole words), so it is meant for unique names like `unk_1C` or `func_80012345`."""
        self._require_level(agent, "Renaming across the project")
        proj = self._project(project)
        ident = re.compile(r"^[A-Za-z_]\w*$")
        if not (ident.match(old) and ident.match(new)):
            raise NetworkError("old and new must be C identifiers")
        word = re.compile(rf"\b{re.escape(old)}\b")
        for _ in range(3):
            units = self._unit_contexts(proj["id"])
            current = {u: self._context(proj["id"], u) for u in ({""} | units)}
            changed = {u: word.sub(new, c["header"]) for u, c in current.items() if word.search(c["header"])}
            if not changed:
                raise NetworkError(f"`{old}` does not occur in any header")
            matched = self.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
            rewritten = {r["id"]: word.sub(new, r["matched_source"]) for r in matched}
            header_for = lambda fn: changed.get(self._effective_unit(fn, units), current[self._effective_unit(fn, units)]["header"])  # noqa: B023  called within this pass of the loop
            broken = self.regression_test(proj, None, sources=rewritten, only=matched, header_for=header_for)
            if broken:
                listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
                return f"❌ REJECTED: renaming breaks {len(broken)} matched function(s).\n{listing}"
            msg = message.strip() or f"rename {old} -> {new}"
            with self.store.tx() as db:
                n_matched = db.execute("SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND status='matched'",
                                       (proj["id"],)).fetchone()["n"]
                if n_matched != len(matched) or any(self._latest_version(db, proj["id"], u) != current[u]["version"]
                                                    for u in changed):
                    continue
                for u, header in changed.items():
                    version = self._next_version(db, proj["id"])
                    db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                               "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, header, agent.id, msg, time.time(), u))
                for fid, src in rewritten.items():
                    db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?", (src, src, fid))
                for r in db.execute("SELECT id, best_source FROM functions WHERE project_id=? AND status='open' "
                                    "AND best_source IS NOT NULL", (proj["id"],)).fetchall():
                    db.execute("UPDATE functions SET best_source=? WHERE id=?", (word.sub(new, r["best_source"]), r["id"]))
                self._event(db, proj["id"], agent.id, "context", f"{msg} ({len(changed)} header(s))")
            return (f"✅ renamed `{old}` -> `{new}` in {len(changed)} header(s) and in {len(rewritten)} matched "
                    f"sources; all still match.")
        raise NetworkError("headers are being edited heavily right now; retry")

    def _latest_version(self, db, project_id: int, unit: str) -> int | None:
        row = db.execute("SELECT MAX(version) AS v FROM context_versions WHERE project_id=? AND unit=?",
                         (project_id, unit)).fetchone()
        return row["v"]

    def _next_version(self, db, project_id: int) -> int:
        return (db.execute("SELECT MAX(version) AS v FROM context_versions WHERE project_id=?",
                           (project_id,)).fetchone()["v"] or 0) + 1

    def _matched_using(self, proj, unit: str) -> list:
        units = self._unit_contexts(proj["id"])
        return [f for f in self.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
                if self._effective_unit(f, units) == unit]

    def regression_test(self, proj, header: str | None, sources: dict[int, str] | None = None,
                        only: list | None = None, header_for=None) -> list[tuple[str, str]]:
        matched = only if only is not None else self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])

        def check(fn) -> tuple[str, str] | None:
            res = self._compile(proj, header_for(fn) if header_for else header,
                                (sources or {}).get(fn["id"], fn["matched_source"]), fn)
            if not res.ok:
                return fn["name"], "no longer compiles: " + res.log.strip().splitlines()[0][:200] if res.log.strip() else "compile failed"
            cand, verdict, _ = self._evaluate(fn, proj, res.obj)
            if verdict is None and cand is not None:
                want = self._target_obj(fn, proj).fingerprint()
                verdict = cand.fingerprint() == want
            if cand is None or not verdict:
                return fn["name"], "compiles but no longer matches"
            return None

        if not matched:  # nothing to protect, but the header must at least parse
            if header is None:
                return []
            res = self._compile(proj, header, "")
            return [] if res.ok else [("<header>", res.log.strip()[:300])]
        return [b for b in self._pool.map(check, matched) if b]

    # ------------------------------------------------------------------ notes

    def add_note(self, agent: Agent, project: str | None, text: str, function: str | None = None) -> str:
        proj = self._project(project)
        fn = self._function(function, proj["slug"]) if function else None
        if not text.strip():
            raise NetworkError("empty note")
        with self.store.tx() as db:
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fn["id"] if fn else None, agent.id, text.strip()[:4000], time.time()))
        return "Noted. Other agents will see it" + (f" when they open {fn['name']}." if fn else " in their briefings.")

    def search_notes(self, project: str | None, query: str) -> str:
        proj = self._project(project)
        rows = self.store.all(
            "SELECT n.text, n.created_at, a.name AS agent, f.name AS fn FROM notes n "
            "LEFT JOIN agents a ON a.id=n.agent_id LEFT JOIN functions f ON f.id=n.function_id "
            "WHERE n.project_id=? AND n.text LIKE ? ORDER BY n.id DESC LIMIT 20", proj["id"], f"%{query}%")
        if not rows:
            return f"No notes matching {query!r}."
        return "\n".join(f"- [{r['fn'] or 'project'}] ({r['agent']}, {_ago(r['created_at'])}) {r['text']}" for r in rows)

    # ------------------------------------------------------------- the project as a whole

    def remove_project(self, slug: str) -> int:
        proj = self._project(slug)
        with self.store.tx() as db:
            ids = [r["id"] for r in db.execute("SELECT id FROM functions WHERE project_id=?", (proj["id"],))]
            for table in ("claims", "attempts"):
                db.executemany(f"DELETE FROM {table} WHERE function_id=?", [(i,) for i in ids])
            for table in ("notes", "events", "context_versions", "functions", "symbols", "twin_misses"):
                db.execute(f"DELETE FROM {table} WHERE project_id=?", (proj["id"],))
            db.execute("DELETE FROM projects WHERE id=?", (proj["id"],))
        return len(ids)

    def learnings(self, slug: str, budget: int = 2500) -> str:
        """The project-wide notes agents left (newest first, within `budget` characters), for every new session:
        what one agent works out about the compiler or the project, the next one starts with."""
        proj = self._project(slug)
        out, used = [], 0
        for r in self.store.all("SELECT text FROM notes WHERE project_id=? AND function_id IS NULL ORDER BY id DESC LIMIT 40",
                                proj["id"]):
            text = " ".join(r["text"].split())[:600]
            if used + len(text) > budget:
                break
            out.append(f"- {text}")
            used += len(text)
        return "\n".join(out)

