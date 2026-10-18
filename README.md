<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
    <img alt="decompdecomp" src=".github/assets/logo-light.svg" width="560">
  </picture>
</p>

<h2 align="center">major app rewrite in progress</h2>


<p align="center">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-157a49?style=flat-square"></a>
  <img alt="Linux, and Windows through WSL (experimental)" src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20WSL%20(experimental)-15140f?style=flat-square">
  <img alt="Works with any MCP agent" src="https://img.shields.io/badge/agents-any%20MCP%20client-157a49?style=flat-square">
</p>

decompdecomp lets your AI agent decompile a game that you own. The agent writes C or C++. The original compiler of the
game compiles it. If the result is identical to the game, byte for byte, the function is a match.

<p align="center">
  <img alt="decompdecomp on the demo ROM: the autopilot matches functions for free, then an agent matches more, one function at a time." src=".github/assets/demo.webp" width="900">
  <br>
  <sub>The app on Demo Quest 64, the demo ROM that comes with it.</sub>
</p>

## Install

**Linux**, with the installer (it also gets the compilers and keeps decompdecomp up to date):

```
curl -fsSL https://decomp.ndelic.com/install.sh | bash
```

Or as a package, from the [releases](https://github.com/n-delic/decompdecomp/releases) (x86_64; each has its own
Python, and Setup in the app gets the compilers):

```
sudo apt install ./decompdecomp_*_amd64.deb        # Debian, Ubuntu, Pop!_OS, Mint
chmod +x decompdecomp-*-x86_64.AppImage && ./decompdecomp-*-x86_64.AppImage   # any other distribution
```

**Windows** (experimental: decompdecomp runs in WSL 2, which the installer turns on), in PowerShell:

```
irm https://decomp.ndelic.com/install.ps1 | iex
```

**macOS** is coming.

To start decompdecomp, type `decomp` or use your apps menu. It opens in a window of its own (with Edge, Chrome,
Brave or Chromium). Closing the window keeps decompdecomp in the system tray, so your agents keep working; quit it
from the tray or the app's ⏻ button.

## Start

1. **Open a game.** Use a ROM, a disc image or a program file of a game that you own. To try the app first, open
   Demo Quest 64.
2. **Add agents.** Claude Code, Codex, Antigravity CLI, opencode, or a model with an API key.
3. **Look at the map.** Each square is a function. A square becomes green when its function matches.
4. **Export the project.** You get a decomp project that builds your game again, byte for byte.

You can also continue a community decomp: paste the address of its repository, and add your own copy of its game.

## Use it from your agent

Connect your agent one time:

```
decomp connect
```

Then tell your agent: `decompile my game at ~/roms/game.z64`.

## Platforms

| Platform | Status |
| :-- | :-- |
| GameCube, Wii, Nintendo 64 | Recommended |
| PlayStation, PlayStation 2, Game Boy Advance, DS, Windows PC, Xbox | Beta |
| 3DS, PSP, Switch, Xbox 360 | Community decomps only |

## More information

- [The guide](docs/GUIDE.md): how it works, public decomps, agents, teams, platforms and the export.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to report a problem or send a change.
- [Issues](https://github.com/n-delic/decompdecomp/issues): problems and requests.

## Use it responsibly

- Use only games that you own. decompdecomp contains no game code and supplies no ROMs.
- Do not publish the code that it makes from a game. That code belongs to the rights holder of the game.
- Obey the rules of the decomp projects that you work with. Many do not accept contributions that AI makes.

## Credits

decompdecomp continues [decomp.wtf](https://github.com/i12bp8/decomp.wtf) by
[Sam Wolfs (@i12bp8)](https://github.com/i12bp8), who made it up to version 0.10.6 and then archived it. Thank you,
Sam. decompdecomp is not related to decomp.wtf, and its author does not endorse it.

decompdecomp uses tools from the decomp community: splat, spimdisasm, objdiff, decomp-toolkit, m2c, Ghidra and the
decompals compilers. The [guide](docs/GUIDE.md#built-on) lists them.

## License

[MIT](LICENSE) © 2026 Sam Wolfs (decomp.wtf) and NDelic (decompdecomp)

<p align="center"><sub>Not related to Nintendo, Sony or Microsoft. Platform names are trademarks of their owners.</sub></p>
