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

// ── File & Rich Clipboard Paste ──
// Intercepts clipboard paste / drop on xterm tiles to prevent fallback camera
// emojis (📷) and upload files (any type) via /api/paste-image, inserting
// ultra-short paths (/tmp/s-<uid>/xxxx.xlsx) directly into the terminal prompt.

window.ShellSessions = Object.assign(window.ShellSessions, {
  async _handleTerminalPaste(e, term, sessionId) {
    const cd = e.clipboardData;
    if (!cd) return;

    // Collect files (any type) from files, or images from items
    const imageBlobs = Array.from(cd.files || []);
    if (imageBlobs.length === 0) {
      for (const item of Array.from(cd.items || [])) {
        if (item.kind === 'file' && item.type.startsWith('image/')) {
          const file = item.getAsFile();
          if (file) imageBlobs.push(file);
        }
      }
    }

    // Check for rich HTML containing images (inline data URI, blob, or web URL)
    const html = cd.getData('text/html');
    const hasHtmlImages = html && /<img\s+[^>]*src=/i.test(html);

    if (imageBlobs.length === 0 && !hasHtmlImages) {
      // Plain text paste: let xterm handle normally
      return;
    }

    // File detected: suppress fallback camera emoji (📷)
    e.preventDefault();
    e.stopPropagation();

    // Branch A: Rich HTML conversation or email with inline/web images
    if (hasHtmlImages) {
      await this._pasteRichConversation(html, term, sessionId);
      return;
    }

    // Branch B & C: Direct file blobs (with optional caption in text/plain)
    let caption = cd.getData('text/plain') || '';
    caption = caption.replace(/[\uD83D\uDCF7\uD83D\uDCF8]|\[Image\]/gi, '').trim();
    // File managers (Finder/Explorer copy) put the file name in text/plain: not a caption
    if (imageBlobs.some((b) => b.name === caption)) caption = '';

    await this._uploadFiles(imageBlobs, term, sessionId, 'Pasted', caption);
  },

  _handleTerminalDragOver(e) {
    if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files')) {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    }
  },

  async _handleTerminalDrop(e, term, sessionId) {
    const dt = e.dataTransfer;
    if (!dt) return;
    const files = Array.from(dt.files || []);
    if (files.length === 0) return;

    e.preventDefault();
    e.stopPropagation();

    await this._uploadFiles(files, term, sessionId, 'Dropped');
  },

  // Uploads in parallel, then puts all quoted paths on the prompt at once.
  // A sticky toast counts finished files; per-file errors show until the next
  // success, and the final toast says if any were lost.
  async _uploadFiles(files, term, sessionId, verb, caption = '') {
    const toast = (message, variant, duration) => window.TuiDialog && window.TuiDialog.toast && window.TuiDialog.toast({ message, variant, duration });
    const mb = (files.reduce((n, f) => n + f.size, 0) / 1048576).toFixed(1);
    let done = 0;
    const progress = () => toast(`Uploading ${files.length > 1 ? `${done}/${files.length} files` : files[0].name || 'file'} (${mb} MB)…`, 'info', 600000);
    progress();
    const paths = (await Promise.all(files.map(async (f) => {
      const p = await this._uploadPasteImage(f, sessionId);
      done++;
      if (p && done < files.length) progress();
      return p;
    }))).filter(Boolean).map((p) => `"${p}"`);
    if (paths.length === 0) return;
    term.paste((caption ? caption + ' ' : '') + paths.join(' ') + ' ');
    if (paths.length < files.length) toast(`${verb} ${paths.length} of ${files.length} files`, 'error');
    else toast(paths.length === 1 ? `${verb} file as ${paths[0]}` : `${verb} ${paths.length} files`, 'info');
  },

  // Mobile all-in-one: no `capture`, so the OS chooser offers camera, photos
  // and files. Originals go as is; only images over the 10 MB cap are
  // re-encoded (2048 px, q0.85) so big camera shots still fit.
  attachFiles(sessionId) {
    if (!this._attachInput) {
      const input = this._attachInput = document.createElement('input');
      input.type = 'file';
      input.multiple = true;
      input.style.display = 'none';
      input.addEventListener('change', async () => {
        const files = Array.from(input.files || []);
        const sid = this.sessions.has(input.dataset.sid) ? input.dataset.sid : this.activeId; // shell may have closed meanwhile
        const s = this.sessions.get(sid);
        input.value = '';
        if (!files.length || !s || !s.term) return;
        await this._uploadFiles(await Promise.all(files.map((f) => this._shrinkImage(f))), s.term, sid, 'Attached');
      });
      document.body.appendChild(input);
    }
    this._attachInput.dataset.sid = sessionId || '';
    this._attachInput.click();
  },

  async _shrinkImage(file) {
    if (file.size <= 10 * 1048576 || !file.type.startsWith('image/')) return file;
    try {
      const bmp = await createImageBitmap(file); // honours EXIF orientation
      const k = Math.min(1, 2048 / Math.max(bmp.width, bmp.height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.round(bmp.width * k);
      canvas.height = Math.round(bmp.height * k);
      canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height);
      bmp.close();
      const blob = await new Promise((res) => canvas.toBlob(res, 'image/jpeg', 0.85));
      return blob ? new File([blob], file.name.replace(/\.[^.]*$/, '') + '.jpg', { type: 'image/jpeg' }) : file;
    } catch (err) {
      console.error('[attach] downscale failed, sending original:', err);
      return file; // _uploadPasteImage rejects it with the size toast
    }
  },

  // Per-file feedback: size reject and any failure (progress: _uploadFiles).
  async _uploadPasteImage(blob, sessionId) {
    const toast = (msg, kind) => window.TuiDialog && window.TuiDialog.toast && window.TuiDialog.toast(msg, kind);
    const label = blob.name || 'file';
    const mb = (blob.size / 1048576).toFixed(1);
    if (blob.size > 10 * 1048576) {
      toast(`${label} is ${mb} MB, max 10 MB`, 'error');
      return null;
    }
    try {
      return await this._uploadPasteBlob(blob, sessionId);
    } catch (err) {
      console.error('[paste] upload failed:', err);
      // Folders reach here: FileReader cannot read a directory entry
      toast(`Upload of ${label} failed: ${(err && err.message) || 'unreadable (folders are not supported)'}`, 'error');
      return null;
    }
  },

  async _uploadPasteBlob(blob, sessionId) {
    const base64 = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const res = reader.result;
        const comma = res.indexOf(',');
        resolve(comma !== -1 ? res.slice(comma + 1) : res);
      };
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });

    const res = await this.encryptedFetch('/api/paste-image', {
      image: base64,
      name: blob.name || '',
      sessionId: sessionId || this.activeId || '',
    });

    if (!res.ok || !res.data || !res.data.path) {
      const err = (res.data && res.data.error) || res.error || 'upload failed';
      if (window.TuiDialog && window.TuiDialog.toast) {
        window.TuiDialog.toast(`Upload of ${blob.name || 'file'} failed: ${err}`, 'error');
      }
      return null;
    }
    return res.data.path;
  },

  async _pasteRichConversation(html, term, sessionId) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    // Strip non-content elements to avoid leaking CSS/JS/SVG into terminal text
    doc.querySelectorAll('script, style, head, noscript, svg').forEach((el) => el.remove());

    const imgs = Array.from(doc.querySelectorAll('img')).slice(0, 10);
    let uploadedCount = 0;

    await Promise.all(
      imgs.map(async (img) => {
        const src = img.getAttribute('src') || '';
        if (!src) return;

        try {
          let blob = null;
          if (src.startsWith('data:image/')) {
            const comma = src.indexOf(',');
            if (comma !== -1) {
              const meta = src.slice(0, comma);
              const mime = meta.match(/:(.*?);/)?.[1] || 'image/png';
              const isBase64 = meta.includes(';base64');
              const dataPart = src.slice(comma + 1);
              if (isBase64) {
                const cleaned = decodeURIComponent(dataPart).replace(/\s/g, '');
                const bstr = atob(cleaned);
                let n = bstr.length;
                const u8arr = new Uint8Array(n);
                while (n--) u8arr[n] = bstr.charCodeAt(n);
                blob = new Blob([u8arr], { type: mime });
              } else {
                blob = new Blob([decodeURIComponent(dataPart)], { type: mime });
              }
            }
          } else if (src.startsWith('blob:')) {
            try {
              const fetched = await fetch(src);
              if (fetched.ok) blob = await fetched.blob();
            } catch (_) {}
          } else if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//')) {
            try {
              const signal = typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(3000) : undefined;
              const fetched = await fetch(src, { mode: 'cors', signal });
              if (fetched.ok) blob = await fetched.blob();
            } catch (_) {}
          }

          if (blob && blob.size === 0) return;

          let path = null;
          if (blob) {
            path = await this._uploadPasteImage(blob, sessionId);
          } else if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//')) {
            const fullUrl = src.startsWith('//') ? 'https:' + src : src;
            const res = await this.encryptedFetch('/api/paste-image', {
              url: fullUrl,
              sessionId: sessionId || this.activeId || '',
            });
            if (res.ok && res.data && res.data.path) {
              path = res.data.path;
            }
          }

          if (path) {
            uploadedCount++;
            const textNode = doc.createTextNode(` [Image: "${path}"] `);
            img.parentNode?.replaceChild(textNode, img);
          }
        } catch (err) {
          console.error('[paste-conversation] image upload failed:', err);
        }
      })
    );

    doc.querySelectorAll('br').forEach((br) => br.replaceWith('\n'));
    doc.querySelectorAll('p, div, tr, li, h1, h2, h3, h4, h5, h6').forEach((el) => {
      el.after('\n');
    });

    let text = doc.body.innerText || doc.body.textContent || '';
    text = text.replace(/[\uD83D\uDCF7\uD83D\uDCF8]/g, '').replace(/\n{3,}/g, '\n\n').trim();
    if (text) {
      term.paste(text + ' ');
      if (uploadedCount > 0 && window.TuiDialog && window.TuiDialog.toast) {
        window.TuiDialog.toast(`Pasted conversation with ${uploadedCount} image${uploadedCount > 1 ? 's' : ''}`, 'info');
      }
    }
  },
});
