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

// ── Audio Helpers ── (beep for the task-completion bell)

let sharedAudioCtx = null;
let audioInitialized = false;

function initAudioContext() {
  if (audioInitialized) return;
  try {
    sharedAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (sharedAudioCtx.state === 'suspended') {
      sharedAudioCtx.resume();
    }
    audioInitialized = true;
  } catch (e) {}
}

if (typeof document !== 'undefined') {
  document.addEventListener('click', initAudioContext, { once: true });
  document.addEventListener('touchstart', initAudioContext, { once: true });
  document.addEventListener('keydown', initAudioContext, { once: true });
}

window.playBellSound = function() {
  try {
    if (!sharedAudioCtx || sharedAudioCtx.state === 'closed') return;
    const t = sharedAudioCtx.currentTime;
    const osc = sharedAudioCtx.createOscillator();
    const gain = sharedAudioCtx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, t);
    gain.gain.setValueAtTime(0.0001, t);
    gain.gain.exponentialRampToValueAtTime(0.25, t + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.3);
    osc.connect(gain);
    gain.connect(sharedAudioCtx.destination);
    osc.start(t);
    osc.stop(t + 0.3);
  } catch (e) {}
};
