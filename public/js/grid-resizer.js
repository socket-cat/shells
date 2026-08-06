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

window.GridResizer = {
  isEnabled: false,
  grid: null,
  dragging: null,
  threshold: 6,

  init() {
    if (window.matchMedia('(max-width: 768px)').matches || ('ontouchstart' in window && window.innerWidth <= 768)) {
      this.isEnabled = false;
      return;
    }
    this.isEnabled = true;
    this.grid = document.getElementById('shell-grid');
    if (!this.grid) return;

    this.grid.addEventListener('mousemove', this.onMouseMove.bind(this));
    this.grid.addEventListener('mousedown', this.onMouseDown.bind(this));
    this.grid.addEventListener('dblclick', this.onDoubleClick.bind(this));
    window.addEventListener('mousemove', this.onWindowMouseMove.bind(this));
    window.addEventListener('mouseup', this.onWindowMouseUp.bind(this));
    this.loadSizes();
  },

  getStorageKey() {
    if (!window.ShellSessions || !this.grid) return null;
    const mode = window.ShellSessions.layoutMode;
    const count = this.grid.dataset.count || 1;
    return `shells-layout-sizes-${mode}-${count}`;
  },

  loadSizes() {
    if (!this.isEnabled || !this.grid) return;

    const key = this.getStorageKey();
    if (!key) return;
    
    const saved = localStorage.getItem(key);
    if (saved) {
      try {
        const sizes = JSON.parse(saved);
        
        this.grid.style.removeProperty('grid-template-columns');
        this.grid.style.removeProperty('grid-template-rows');
        
        const naturalCols = this.getTracks('col').length;
        const savedCols = sizes.cols ? sizes.cols.split(' ').length : 0;

        if (savedCols > 0 && savedCols !== naturalCols) {
          console.warn(`[GridResizer] Discarding stale layout for ${key} (Expected ${naturalCols} cols, got ${savedCols})`);
          this.reset();
          return;
        }
        
        if (sizes.cols) this.grid.style.gridTemplateColumns = sizes.cols;
        window.dispatchEvent(new Event('resize'));
      } catch(e) { this.reset(); }
    } else {
      this.reset();
    }
  },

  reset() {
    if (!this.grid) return;
    this.grid.style.removeProperty('grid-template-columns');
    this.grid.style.removeProperty('grid-template-rows');
    window.dispatchEvent(new Event('resize'));
  },

  saveSizes() {
    if (!this.isEnabled || !this.grid) return;
    const key = this.getStorageKey();
    if (!key) return;
    const cols = this.grid.style.gridTemplateColumns;
    if (cols) localStorage.setItem(key, JSON.stringify({ cols }));
  },

  getTracks(type) {
    const style = window.getComputedStyle(this.grid);
    const template = type === 'col' ? style.gridTemplateColumns : style.gridTemplateRows;
    if (!template || template === 'none') return [];
    return template.split(' ').map(parseFloat);
  },

  getLines(type) {
    const tracks = this.getTracks(type);
    const gap = parseFloat(window.getComputedStyle(this.grid).gap) || 2;
    const lines = [];
    let current = type === 'col' ? parseFloat(window.getComputedStyle(this.grid).paddingLeft)||0 : parseFloat(window.getComputedStyle(this.grid).paddingTop)||0;
    for (let i = 0; i < tracks.length - 1; i++) {
      current += tracks[i];
      lines.push({ index: i, pos: current + (gap / 2) });
      current += gap;
    }
    return lines;
  },

  getHoverLine(e) {
    const rect = this.grid.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    for (const line of this.getLines('col')) if (Math.abs(x - line.pos) <= this.threshold) return { type: 'col', index: line.index };
    for (const line of this.getLines('rows')) if (Math.abs(y - line.pos) <= this.threshold) return { type: 'row', index: line.index };
    return null;
  },

  onMouseMove(e) {
    if (this.dragging) return;
    const h = this.getHoverLine(e);
    this.grid.style.cursor = h ? (h.type === 'col' ? 'col-resize' : 'row-resize') : '';
  },

  onMouseDown(e) {
    if (e.button !== 0) return;
    const h = this.getHoverLine(e);
    if (!h) return;
    e.preventDefault(); e.stopPropagation();
    this.dragging = { type: h.type, startPos: h.type === 'col' ? e.clientX : e.clientY, startSizes: this.getTracks(h.type), track1: h.index, track2: h.index + 1 };
    this.applySizes(this.dragging.type, this.dragging.startSizes, 'px');
    document.body.style.cursor = h.type === 'col' ? 'col-resize' : 'row-resize';
    let overlay = document.getElementById('grid-resize-overlay') || document.createElement('div');
    overlay.id = 'grid-resize-overlay';
    Object.assign(overlay.style, { position: 'fixed', top: '0', left: '0', right: '0', bottom: '0', zIndex: '9999', cursor: document.body.style.cursor });
    if (!overlay.parentElement) document.body.appendChild(overlay);
  },

  onWindowMouseMove(e) {
    if (!this.dragging) return;
    e.preventDefault();
    const d = this.dragging, currentPos = d.type === 'col' ? e.clientX : e.clientY, delta = currentPos - d.startPos;
    let newSizes = [...d.startSizes], minSize = 50, maxDelta = newSizes[d.track2] - minSize, minDelta = -(newSizes[d.track1] - minSize);
    const boundedDelta = Math.max(minDelta, Math.min(maxDelta, delta));
    newSizes[d.track1] += boundedDelta; newSizes[d.track2] -= boundedDelta;
    this.applySizes(d.type, newSizes, 'px');
    if (!this._rafId) this._rafId = requestAnimationFrame(() => { window.dispatchEvent(new Event('resize')); this._rafId = null; });
  },

  onWindowMouseUp(e) {
    if (!this.dragging) return;
    e.preventDefault();
    const d = this.dragging, currentSizes = this.getTracks(d.type), total = currentSizes.reduce((a, b) => a + b, 0);
    if (total > 0) {
      const percentageSizes = currentSizes.map(s => ((s / total) * 100).toFixed(2) + '%');
      this.applySizes(d.type, percentageSizes, '');
      this.saveSizes();
    }
    this.dragging = null;
    document.body.style.cursor = this.grid.style.cursor = '';
    let overlay = document.getElementById('grid-resize-overlay');
    if (overlay) overlay.remove();
    window.dispatchEvent(new Event('resize'));
  },

  onDoubleClick(e) {
    if (this.getHoverLine(e)) {
      const key = this.getStorageKey();
      if (key) localStorage.removeItem(key);
      this.reset();
    }
  },

  applySizes(type, sizes, unit) {
    const value = sizes.map(s => s + unit).join(' ');
    if (type === 'col') this.grid.style.gridTemplateColumns = value;
    else this.grid.style.gridTemplateRows = value;
  }
};
