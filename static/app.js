// ─────────────────────────────────────────────────────────────
// Client-Side Explorer Controller (Search, View Toggle, Lightbox)
// ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // 1. Live Instant Search Filter
  const q = document.getElementById('q');
  const clearSearch = document.getElementById('clearSearch');
  const folderItems = [...document.querySelectorAll('.folder-item')];
  const fileRows = [...document.querySelectorAll('.file-row')];
  const folderCountLabel = document.getElementById('folderCountLabel');
  const fileCountLabel = document.getElementById('fileCountLabel');
  const totalCount = document.getElementById('totalCount');

  if (q) {
    q.addEventListener('input', () => {
      const term = q.value.trim().toLowerCase();
      if (clearSearch) clearSearch.style.display = term ? 'grid' : 'none';
      let shownFolders = 0;
      let shownFiles = 0;

      folderItems.forEach(item => {
        const match = item.dataset.name.includes(term);
        item.classList.toggle('hidden', !match);
        if (match) shownFolders++;
      });

      fileRows.forEach(row => {
        const match = row.dataset.name.includes(term);
        row.classList.toggle('hidden', !match);
        if (match) shownFiles++;
      });

      if (folderCountLabel) folderCountLabel.textContent = String(shownFolders).padStart(2, '0');
      if (fileCountLabel) fileCountLabel.textContent = String(shownFiles).padStart(2, '0');
      if (totalCount) totalCount.textContent = (shownFolders + shownFiles) + ' items';
    });
  }

  if (clearSearch && q) {
    clearSearch.addEventListener('click', () => {
      q.value = '';
      q.dispatchEvent(new Event('input'));
      q.focus();
    });
  }

  // 2. View Toggle (Grid vs List)
  const viewToggle = document.getElementById('viewToggle');
  const fileList = document.getElementById('fileList');
  let isGrid = false;

  if (viewToggle && fileList) {
    viewToggle.addEventListener('click', () => {
      isGrid = !isGrid;
      fileList.classList.toggle('grid-mode', isGrid);
      viewToggle.classList.toggle('active', isGrid);
    });
  }

  // 3. Theater Mode Lightbox Media Player
  const lightbox = document.getElementById('lightbox');
  const mediaStage = document.getElementById('mediaStage');
  const lightboxTitle = document.getElementById('lightboxTitle');
  const lightboxMeta = document.getElementById('lightboxMeta');
  const lightboxClose = document.getElementById('lightboxClose');
  const lightboxDownload = document.getElementById('lightboxDownload');

  function closeLightbox() {
    if (lightbox) lightbox.style.display = 'none';
    if (mediaStage) mediaStage.innerHTML = ''; // Stops playback and cleans stream memory immediately
  }

  if (lightboxClose) {
    lightboxClose.addEventListener('click', closeLightbox);
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && lightbox && lightbox.style.display !== 'none') {
      closeLightbox();
    }
  });

  fileRows.forEach(row => {
    row.addEventListener('click', () => {
      const url = row.dataset.url;
      const kind = row.dataset.kind;
      const type = row.dataset.type;
      const size = row.dataset.size;
      const title = row.dataset.title;
      const mime = row.dataset.mime || '';
      const downloadUrl = url + (url.includes('?') ? '&' : '?') + 'download=1';

      if (lightboxTitle) lightboxTitle.textContent = title;
      if (lightboxMeta) lightboxMeta.textContent = type + ' · ' + size;
      if (lightboxDownload) lightboxDownload.href = downloadUrl;
      if (mediaStage) mediaStage.innerHTML = '';

      if (kind === 'video') {
        const vid = document.createElement('video');
        vid.controls = true;
        vid.preload = 'metadata';
        vid.playsInline = true;

        const source = document.createElement('source');
        source.src = url;
        if (mime) source.type = mime;
        vid.appendChild(source);

        // Codec or container error (e.g. MKV, AVI, HEVC, AC-3 unsupported by web browsers)
        vid.addEventListener('error', () => {
          if (mediaStage) {
            mediaStage.innerHTML = `
              <div class="unsupported-codec-notice">
                <div class="codec-badge">FORMAT: .${type}</div>
                <h3>Cannot Play in Web Browser</h3>
                <p>Web browsers natively support <strong>MP4 (H.264/AAC)</strong> and <strong>WebM</strong>.<br>Files with <strong>.${type}</strong> container, <strong>HEVC (H.265)</strong>, or <strong>AC-3/DTS</strong> audio require a desktop player.</p>
                <div class="stage-actions">
                  <a class="stage-btn primary" href="${downloadUrl}" download>Download File (${size})</a>
                  <a class="stage-btn" href="vlc://${encodeURIComponent(window.location.origin + url)}">Open in VLC</a>
                  <button type="button" class="stage-btn secondary" id="copyStreamLinkBtn">Copy Stream URL</button>
                </div>
              </div>
            `;
            const copyBtn = document.getElementById('copyStreamLinkBtn');
            if (copyBtn) {
              copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(window.location.origin + url);
                copyBtn.textContent = 'Copied!';
                setTimeout(() => { copyBtn.textContent = 'Copy Stream URL'; }, 2000);
              });
            }
          }
        });

        if (mediaStage) mediaStage.appendChild(vid);

        const playPromise = vid.play();
        if (playPromise !== undefined) {
          playPromise.catch(() => {
            // Autoplay policy prevented immediate unmuted playback; user can click play
          });
        }
      } else if (kind === 'image') {
        const img = document.createElement('img');
        img.src = url;
        img.alt = title;
        if (mediaStage) mediaStage.appendChild(img);
      } else if (kind === 'audio') {
        const aud = document.createElement('audio');
        aud.src = url;
        aud.controls = true;
        aud.autoplay = true;
        if (mediaStage) mediaStage.appendChild(aud);
      } else {
        window.open(url, '_blank');
        return;
      }

      if (lightbox) lightbox.style.display = 'flex';
    });
  });
});
