# Cyber shell

The single chrome for every cyber capability. It is a no-build ES-module
package: `index.js` owns structure and behavior, `tokens.css` owns color, type
and geometry. Both mirror `@hanzo/gui`'s `pkgs/ui/shell/src/theme.ts`.

- Monochrome chrome: true-black sidebar, `#0a0a0a` canvas, `#09090b` elevated
  surfaces, hairline `rgb(255 255 255 / .10)` borders, paper-white ink.
- Shape: topbar 40, sidebar 256 (rail 48), control radius 8, card radius 12,
  composer radius 16.
- The launcher (`Cmd/Ctrl+K`) exposes Tasks, Findings, Traffic, Assets, Cloud
  sandbox and Settings from the same shell, so every capability is reached the
  same way.
- Semantic severity colors are the only hues; they carry security meaning.

A host that loads `@hanzo/gui` themes the shell automatically. A host with no
CSS framework still renders correctly because tokens.css is self-contained.
