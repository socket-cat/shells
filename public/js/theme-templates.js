/**
 * @author Carles Ortega Ragull <ragull@socket.cat> (https://socket.cat)
 * @copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// ── Theme template definitions (SINGLE SOURCE OF TRUTH) ──
// Loaded synchronously in <head> BEFORE the anti-flash inline script and
// before theme.js. Both the first-paint anti-flash (index.html) and
// ShellTheme (theme.js) build their filters from this object, so a template
// change here is picked up everywhere and can never drift.
//
// Each template defines the structural filter with {hue}/{bright}/{contrast}
// placeholders plus a preset — the slider positions that reproduce its look.
// preset order is {hue, brightness, contrast}. 'dark' is the default paint but
// still carries a filter string (theme.js composes it for --theme-filter);
// the anti-flash applies it too, so a dark cold load stays dark.

window.SHELLS_THEME_TEMPLATES = {
  light: {
    label: 'Light',
    base: 'invert(1) hue-rotate({hue}deg) brightness({bright}) contrast({contrast})',
    preset: { hue: 180, brightness: 1, contrast: 1 },
  },
  dark: {
    label: 'Dark',
    base: 'hue-rotate({hue}deg) brightness({bright}) contrast({contrast})',
    preset: { hue: 0, brightness: 1, contrast: 1 },
  },
  sepia: {
    label: 'Sepia',
    base: 'invert(1) hue-rotate({hue}deg) sepia(0.5) saturate(0.75) brightness({bright}) contrast({contrast})',
    preset: { hue: 180, brightness: 0.75, contrast: 1.4 },
  },
  brown: {
    label: 'Dim',
    base: 'sepia(0.3) saturate(0.9) hue-rotate({hue}deg) brightness({bright}) contrast({contrast})',
    preset: { hue: 0, brightness: 0.82, contrast: 1.05 },
  },
};
