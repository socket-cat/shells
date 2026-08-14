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

// ── Mobile Keyboard Picker ──

window.ShellKeyboard = {
  _shift: false,
  _ctrl: false,

  KEYS: [
    { label: 'Tab',  seq: ['\t', '\x1b[Z', '\t'] },
    { label: '←',    seq: ['\x1b[D', '\x1b[1;2D', '\x1b[1;5D'] },
    { label: '↑',    seq: ['\x1b[A', '\x1b[1;2A', '\x1b[1;5A'] },
    { label: '→',    seq: ['\x1b[C', '\x1b[1;2C', '\x1b[1;5C'] },
    { label: '↓',    seq: ['\x1b[B', '\x1b[1;2B', '\x1b[1;5B'] },
    { label: 'Home', seq: ['\x1b[H', '\x1b[1;2H', '\x1b[1;5H'] },
    { label: 'End',  seq: ['\x1b[F', '\x1b[1;2F', '\x1b[1;5F'] },
    { label: 'PgUp', seq: ['\x1b[5~', '\x1b[5;2~', '\x1b[5;5~'] },
    { label: 'PgDn', seq: ['\x1b[6~', '\x1b[6;2~', '\x1b[6;5~'] },
    { label: 'Del',  seq: ['\x1b[3~', '\x1b[3;2~', '\x1b[3;5~'] },
    { label: 'Ins',  seq: ['\x1b[2~', '\x1b[2;2~', '\x1b[2;5~'] },
    { label: 'Bksp', seq: ['\x7f', '\x7f', '\x08'] },
    { label: 'Enter',seq: ['\r', '\r', '\r'] },
  ],

  COMBOS: [
    { label: 'C', data: '\x03' },
    { label: 'D', data: '\x04' },
    { label: 'Z', data: '\x1a' },
    { label: 'L', data: '\x0c' },
    { label: 'O', data: '\x0f' },
    { label: 'R', data: '\x12' },
    { label: 'A', data: '\x01' },
    { label: 'E', data: '\x05' },
    { label: 'K', data: '\x0b' },
    { label: 'U', data: '\x15' },
    { label: 'W', data: '\x17' },
    { label: 'X', data: '\x18' },
  ],

  _seqIndex() {
    if (this._ctrl) return 2;
    if (this._shift) return 1;
    return 0;
  },

  _send(data) {
    if (window.ShellSessions && typeof window.ShellSessions.writeActive === 'function') {
      window.ShellSessions.writeActive(data);
    }
  },

  open(triggerEl) {
    const existing = document.getElementById('keyboard-overlay');
    if (existing) existing.remove();

    this._shift = false;
    this._ctrl = false;

    const overlay = TuiDialog._createOverlay({ id: 'keyboard-overlay', transparent: true, top: true });
    overlay.style.paddingTop = '0';
    const modal = TuiDialog._createDialog('narrow');
    modal.setAttribute('aria-labelledby', 'keyboard-modal-title');

    const close = () => {
      document.removeEventListener('keydown', keyHandler);
      overlay.remove();
      if (triggerEl && typeof triggerEl.focus === 'function') triggerEl.focus();
    };

    const header = TuiDialog._createHeader('Special Keys', close);
    header.querySelector('.tui-dialog-title').id = 'keyboard-modal-title';

    const body = document.createElement('div');
    body.className = 'tui-dialog-body';
    body.style.padding = '0 32px 8px';

    const modRow = document.createElement('div');
    modRow.className = 'keyboard-mod-row';

    const shiftBtn = document.createElement('button');
    shiftBtn.className = 'key-btn key-modifier';
    shiftBtn.type = 'button';
    shiftBtn.textContent = 'Shift';
    shiftBtn.setAttribute('aria-pressed', 'false');

    const ctrlBtn = document.createElement('button');
    ctrlBtn.className = 'key-btn key-modifier';
    ctrlBtn.type = 'button';
    ctrlBtn.textContent = 'Ctrl';
    ctrlBtn.setAttribute('aria-pressed', 'false');

    const escBtn = document.createElement('button');
    escBtn.className = 'key-btn key-modifier';
    escBtn.type = 'button';
    escBtn.textContent = 'Esc';

    modRow.appendChild(shiftBtn);
    modRow.appendChild(ctrlBtn);
    modRow.appendChild(escBtn);

    const updateModUI = () => {
      shiftBtn.classList.toggle('key-modifier-active', this._shift);
      ctrlBtn.classList.toggle('key-modifier-active', this._ctrl);
      shiftBtn.setAttribute('aria-pressed', String(this._shift));
      ctrlBtn.setAttribute('aria-pressed', String(this._ctrl));
    };

    shiftBtn.addEventListener('click', (e) => {
      e.preventDefault();
      this._shift = !this._shift;
      updateModUI();
    });

    ctrlBtn.addEventListener('click', (e) => {
      e.preventDefault();
      this._ctrl = !this._ctrl;
      updateModUI();
    });

    escBtn.addEventListener('click', (e) => {
      e.preventDefault();
      this._send('\x1b');
      this._shift = false;
      this._ctrl = false;
      updateModUI();
    });

    const keyGrid = document.createElement('div');
    keyGrid.className = 'keyboard-grid';

    this.KEYS.forEach((key) => {
      const btn = document.createElement('button');
      btn.className = 'key-btn';
      btn.type = 'button';
      btn.textContent = key.label;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const idx = this._seqIndex();
        this._send(key.seq[idx]);
        this._shift = false;
        this._ctrl = false;
        updateModUI();
      });
      keyGrid.appendChild(btn);
    });

    const comboSection = document.createElement('div');
    comboSection.className = 'keyboard-combo-section';

    const comboLabel = document.createElement('div');
    comboLabel.className = 'keyboard-combo-label';
    comboLabel.textContent = 'Ctrl +';
    comboSection.appendChild(comboLabel);

    const comboGrid = document.createElement('div');
    comboGrid.className = 'keyboard-combo-grid';

    this.COMBOS.forEach((combo) => {
      const btn = document.createElement('button');
      btn.className = 'key-btn key-combo-btn';
      btn.type = 'button';
      btn.textContent = combo.label;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        this._send(combo.data);
        this._shift = false;
        this._ctrl = false;
        updateModUI();
      });
      comboGrid.appendChild(btn);
    });

    comboSection.appendChild(comboGrid);

    const keyHandler = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
      }
    };

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) close();
    });

    let kbTwoFingerStartY = 0;
    overlay.addEventListener('touchstart', (e) => {
      if (e.touches.length === 2) {
        kbTwoFingerStartY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      }
    }, { passive: true });
    overlay.addEventListener('touchmove', (e) => {
      if (e.touches.length !== 2 || !kbTwoFingerStartY) return;
      const avgY = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      if (kbTwoFingerStartY - avgY > 80) {
        kbTwoFingerStartY = 0;
        close();
      }
    }, { passive: true });

    document.addEventListener('keydown', keyHandler);

    body.appendChild(modRow);
    body.appendChild(keyGrid);
    body.appendChild(comboSection);
    modal.appendChild(header);
    modal.appendChild(body);
    overlay.appendChild(modal);
  },
};
