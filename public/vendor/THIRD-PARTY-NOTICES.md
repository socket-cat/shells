# Third-Party Notices — vendored xterm.js builds

This directory contains pristine upstream builds of the
[xterm.js](https://github.com/xtermjs/xterm.js) terminal emulator and its
addons, distributed under the MIT License. The Shells application code is
AGPL-3.0-or-later; the files listed here remain MIT-licensed upstream code.

The only local modification to any build is the removal of the trailing
`//# sourceMappingURL=…` comment (the `.map` files are not shipped).

| File | Package | Version | Upstream |
|---|---|---|---|
| `xterm.js` | `@xterm/xterm` | 6.0.0 | https://www.npmjs.com/package/@xterm/xterm |
| `xterm-addon-fit.js` | `@xterm/addon-fit` | 0.11.0 | https://www.npmjs.com/package/@xterm/addon-fit |
| `xterm-addon-webgl.js` | `@xterm/addon-webgl` | 0.19.0 | https://www.npmjs.com/package/@xterm/addon-webgl |
| `xterm-addon-canvas.js` | `@xterm/addon-canvas` | 0.7.0 | https://www.npmjs.com/package/@xterm/addon-canvas |
| `xterm-addon-search.js` | `@xterm/addon-search` | 0.16.0 | https://www.npmjs.com/package/@xterm/addon-search |
| `xterm-addon-unicode11.js` | `@xterm/addon-unicode11` | 0.9.0 | https://www.npmjs.com/package/@xterm/addon-unicode11 |
| `xterm-addon-clipboard.js` | `@xterm/addon-clipboard` | 0.2.0 | https://www.npmjs.com/package/@xterm/addon-clipboard |
| `xterm-addon-web-links.js` | `@xterm/addon-web-links` | 0.12.0 | https://www.npmjs.com/package/@xterm/addon-web-links |
| `xterm.css` | `@xterm/xterm` | 6.0.0 | (stylesheet; in-file notice retained) |

## MIT License

Copyright (c) 2019 The xterm.js authors.
Portions of `xterm.js` / `xterm.css` copyright (c) 2012-2013 Christopher Jeffrey
([term.js](https://github.com/chjj/term.js), MIT License).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## Maintenance

When upgrading: download the new `lib/*.js` build from npm, strip the trailing
`//# sourceMappingURL=…` line, and verify the result matches the published
build byte-for-byte apart from that line. Update the version table above.
