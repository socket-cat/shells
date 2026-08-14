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

// ── Layout Management ──

window.ShellLayout = {
  // Grid updates — sets CSS custom properties and data attributes
  updateGrid(sessions, mode) {
    const grid = document.getElementById('shell-grid');
    if (!grid) return;

    // Reset any custom grid track definitions to avoid "stickiness" when count changes
    if (window.GridResizer) {
      window.GridResizer.reset();
    }

    const count = sessions.size;

    // Set data attributes for CSS selectors
    const m = mode || 'auto';
    grid.dataset.layoutMode = m;
    grid.dataset.count = count;

    // Set/remove CSS custom properties based on mode
    if (count >= 5 && m === 'auto') {
      const stackCols = count >= 8 ? 3 : 2;
      const stackRows = Math.ceil((count - 1) / stackCols);
      grid.style.setProperty('--master-span', stackRows);
      grid.style.setProperty('--stack-cols', stackCols);
    } else if (m === 'columns') {
      grid.style.setProperty('--col-count', count);
    } else {
      grid.style.removeProperty('--master-span');
      grid.style.removeProperty('--stack-cols');
      grid.style.removeProperty('--col-count');
    }

    // Load any saved custom sizes for this layout/count if GridResizer is available
    if (window.GridResizer) {
      window.GridResizer.loadSizes();
    }
  },

  // Active/master highlighting — matches by tile.id === `tile-${id}`
  updateActiveHighlight(activeId, masterId) {
    document.querySelectorAll('.shell-tile').forEach(t => {
      t.classList.remove('active', 'is-master');
      if (activeId && t.id === `tile-${activeId}`) t.classList.add('active');
      if (masterId && t.id === `tile-${masterId}`) t.classList.add('is-master');
    });
  },

  // ── Layout Picker (Workspace Layouts) ──
  picker: {
    modes: [
      { id: 'auto', label: 'Auto (Master-Stack)', desc: 'Adaptive layout with a primary master area.' },
      { id: 'columns', label: 'Columns', desc: 'Evenly spaced vertical columns.' },
      { id: 'rows', label: 'Rows', desc: 'Evenly spaced horizontal rows.' },
      { id: 'grid', label: 'Grid', desc: 'Tiled grid of terminals.' },
    ],

    open(triggerEl) {
      const currentId = window.ShellSessions.layoutMode || 'auto';
      const options = this.modes.map((m) => ({
        value: m.id,
        title: m.label,
        description: m.desc,
      }));

      window.TuiDialog.select('Choose layout', options, {
        current: currentId,
        skipFilter: true,
        transparent: true,
        singleColumnNavigation: true,
        applyImmediately: true,
        onApply: (layoutId) => {
          window.ShellSessions.setLayout(layoutId);
        },
      }).then(() => {
        if (triggerEl && typeof triggerEl.focus === 'function') triggerEl.focus();
      });
    },
  },

  // Theme logic has been moved to theme.js
  // Switcher logic has been moved to switcher.js

  get switcher() { return window.ShellSwitcher; },
};
