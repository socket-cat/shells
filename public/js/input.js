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

// ── Input Handling ──

(function() {
  const cmdInput = document.getElementById('cmd-input');
  if (!cmdInput) return;

  const resizeCmdInput = () => {
    cmdInput.style.height = 'auto';
    cmdInput.style.height = Math.min(cmdInput.scrollHeight, 120) + 'px';
  };

  const handleEnter = (text = null) => {
    const payload = (text ? text.replace(/\n/g, '\r') : '') + '\r';
    if (window.ShellSessions.writeActive(payload)) {
      cmdInput.value = '';
      resizeCmdInput();
    } else {
      TuiDialog.toast('No active shell', 'error');
    }
  };

  cmdInput.addEventListener('input', () => {
    resizeCmdInput();
  });

  cmdInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const text = cmdInput.value;
      handleEnter(text || null);
    }
  });

  const sendArrow = (seq) => {
    if (!window.ShellSessions.writeActive(seq)) {
      TuiDialog.toast('No active shell', 'error');
    }
  };
  const cmdUp = document.getElementById('cmd-up');
  const cmdDown = document.getElementById('cmd-down');

  // Tapping an arrow must not blur the input: on mobile that hides the
  // native keyboard. We do NOT preventDefault on touch/pointer (that
  // suppresses the click on iOS). Instead the buttons are removed from the
  // tab order (tabindex=-1) so tapping them never steals focus, plus a
  // refocus safety net restores it if a browser still blurs.
  const wireArrow = (btn, seq) => {
    if (!btn) return;
    btn.setAttribute('tabindex', '-1');
    btn.addEventListener('pointerdown', () => {
      btn._inputFocused = document.activeElement === cmdInput;
    });
    btn.addEventListener('click', () => {
      sendArrow(seq);
      if (btn._inputFocused && document.activeElement !== cmdInput) cmdInput.focus();
    });
  };
  wireArrow(cmdUp, '\x1b[A');
  wireArrow(cmdDown, '\x1b[B');
})();
