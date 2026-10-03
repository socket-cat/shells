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

// ── Image & Rich Clipboard Paste ──
// Intercepts clipboard paste on xterm tiles to prevent fallback camera
// emojis (📷) and upload images via /api/paste-image, inserting ultra-short
// paths (/tmp/s-<uid>/xxxx.png) directly into the terminal prompt.

window.ShellSessions = Object.assign(window.ShellSessions, {
  async _handleTerminalPaste(e, term, sessionId) {
    const cd = e.clipboardData;
    if (!cd) return;

    // Collect image files from files or items
    const rawFiles = Array.from(cd.files || []);
    const rawItems = Array.from(cd.items || []);
    const imageBlobs = rawFiles.filter((f) => f.type && f.type.startsWith('image/'));
    if (imageBlobs.length === 0) {
      for (const item of rawItems) {
        if (item.type && item.type.startsWith('image/')) {
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

    // Image detected: suppress fallback camera emoji (📷)
    e.preventDefault();
    e.stopPropagation();

    // Branch A: Rich HTML conversation or email with inline/web images
    if (hasHtmlImages) {
      await this._pasteRichConversation(html, term, sessionId);
      return;
    }

    // Branch B & C: Direct image blobs (with optional caption in text/plain)
    let caption = cd.getData('text/plain') || '';
    caption = caption.replace(/[\uD83D\uDCF7\uD83D\uDCF8]|\[Image\]/gi, '').trim();

    const uploadResults = await Promise.all(
      imageBlobs.map(async (blob) => {
        try {
          return await this._uploadPasteImage(blob, sessionId);
        } catch (err) {
          console.error('[paste-image] upload failed:', err);
          return null;
        }
      })
    );
    const uploadedPaths = uploadResults.filter(Boolean).map((p) => `"${p}"`);

    if (uploadedPaths.length === 0) return;

    let pasteText = uploadedPaths.join(' ') + ' ';
    if (caption) {
      pasteText = caption + ' ' + pasteText;
    }
    term.paste(pasteText);
    if (window.TuiDialog && window.TuiDialog.toast) {
      const msg = uploadedPaths.length === 1 ? `Pasted image as ${uploadedPaths[0]}` : `Pasted ${uploadedPaths.length} images`;
      window.TuiDialog.toast(msg, 'info');
    }
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
    const files = Array.from(dt.files || []).filter((f) => f.type && f.type.startsWith('image/'));
    if (files.length === 0) return;

    e.preventDefault();
    e.stopPropagation();

    const uploadResults = await Promise.all(
      files.map(async (file) => {
        try {
          return await this._uploadPasteImage(file, sessionId);
        } catch (err) {
          console.error('[drop-image] upload failed:', err);
          return null;
        }
      })
    );
    const uploadedPaths = uploadResults.filter(Boolean).map((p) => `"${p}"`);
    if (uploadedPaths.length === 0) return;

    term.paste(uploadedPaths.join(' ') + ' ');
    if (window.TuiDialog && window.TuiDialog.toast) {
      const msg = uploadedPaths.length === 1 ? `Dropped image as ${uploadedPaths[0]}` : `Dropped ${uploadedPaths.length} images`;
      window.TuiDialog.toast(msg, 'info');
    }
  },

  async pasteImageFile(file, sessionId) {
    const sid = sessionId || this.activeId;
    const s = sid ? this.sessions.get(sid) : null;
    if (!file || (!s && !this.activeId)) return null;
    try {
      const path = await this._uploadPasteImage(file, sid);
      if (path) {
        if (s && s.term) {
          s.term.paste(`"${path}" `);
        } else if (typeof this.writeActive === 'function') {
          this.writeActive(`"${path}" `);
        }
        if (window.TuiDialog && window.TuiDialog.toast) {
          window.TuiDialog.toast(`Attached image as ${path}`, 'info');
        }
        return path;
      }
    } catch (err) {
      console.error('[pasteImageFile] failed:', err);
    }
    return null;
  },

  async _uploadPasteImage(blob, sessionId) {
    if (!this.cryptoState || !this.cryptoState.apiKey) {
      throw new Error('Encryption not ready');
    }
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
      sessionId: sessionId || this.activeId || '',
    });

    if (!res.ok || !res.data || !res.data.path) {
      const err = (res.data && res.data.error) || res.error || 'upload failed';
      if (window.TuiDialog && window.TuiDialog.toast) {
        window.TuiDialog.toast(`Image paste failed: ${err}`, 'error');
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
