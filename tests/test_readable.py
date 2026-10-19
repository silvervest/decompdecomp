"""Matched code made readable (app/readable.py): a rewrite with names, types and a comment is kept when the function
still matches byte for byte, refused otherwise, and the project counts how much of its matched code is readable."""

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError

from .test_app_engine import CLAMP
from .test_rom import ROM, built  # noqa: F401  (fixture that builds the demo ROM)

READABLE = """/* Keeps value between low and high (both included). */
s32 clamp_s32(s32 value, s32 low, s32 high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}"""

BROKEN = READABLE.replace("value > high", "value >= high")


@pytest.fixture
def matched(built, tmp_path):  # noqa: F811
    net = RomNetwork(tmp_path / "decomp.db", tmp_path)
    slug = net.import_rom(ROM, confirmed=True, log=lambda *_: None)
    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.split_function(agent, slug, "func_800007C4", "0x800007D0")
    assert net.compile_and_diff(agent, "func_800007D0", CLAMP, slug).startswith("✅ MATCH")
    assert net.rename_symbol(agent, slug, "func_800007D0", "clamp_s32").startswith("✅")
    return net, slug, agent


def test_a_readable_rewrite_that_still_matches_is_kept(matched):
    net, slug, agent = matched
    brief = net.readability.claim(agent, slug)
    assert "clamp_s32" in brief and "must still match byte for byte" in brief
    assert net.readability.submit(agent, slug, "clamp_s32", BROKEN).startswith("❌ It no longer matches")
    assert net.overview(slug)["readable"] == 0
    assert net.readability.submit(agent, slug, "clamp_s32", READABLE).startswith("✅ clamp_s32 is readable now")
    fn = net._function("clamp_s32", slug)
    assert fn["status"] == "matched" and "Keeps value between" in fn["matched_source"] and fn["readable"] == 1
    assert net.overview(slug)["readable"] == 1


def test_the_same_c_again_is_no_rewrite(matched):
    net, slug, agent = matched
    with pytest.raises(NetworkError, match="already"):
        net.readability.submit(agent, slug, "clamp_s32", net._function("clamp_s32", slug)["matched_source"])


def test_polish_takes_starred_then_big_functions_and_leaves_stubs(matched):
    """Smallest first, a helper spent its first session on empty functions: there's nothing to explain in them."""
    from decompnet.app import readable

    net, slug, agent = matched
    pid = net._project(slug)["id"]
    rows = net.store.all("SELECT id, name, n_insns FROM functions WHERE project_id=? AND status!='matched' "
                         "ORDER BY n_insns", pid)
    stub = next(r for r in rows if r["n_insns"] < readable.MIN_INSNS)
    big = next(r for r in reversed(rows) if r["n_insns"] <= readable.MAX_INSNS)
    with net.store.tx() as db:
        for r in (stub, big):
            db.execute("UPDATE functions SET status='matched', matched_source='/* as it matched */' WHERE id=?", (r["id"],))
    assert big["name"] in net.readability.claim(agent, slug)
    net.release(agent, big["name"], "", slug)
    net.store.conn.execute("UPDATE functions SET boost=1 WHERE name='clamp_s32' AND project_id=?", (pid,))
    other, _ = net.local_agent("claude-opus-5.5-2")
    assert "clamp_s32" in net.readability.claim(other, slug)
    assert stub["name"] not in net.readability.claim(agent, slug)
