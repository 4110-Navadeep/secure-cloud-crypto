/**
 * Secure Cloud — Shared Utilities
 * Toast notifications, file formatting, MIME icons
 */

// ============================================================
// Toast Notifications
// ============================================================

function showToast(message, type = 'info', duration = 4000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ️'}</span><span class="toast-msg">${message}</span>`;
  container.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => toast.classList.add('toast-visible'));

  setTimeout(() => {
    toast.classList.remove('toast-visible');
    toast.classList.add('toast-hide');
    setTimeout(() => toast.remove(), 400);
  }, duration);
}

// ============================================================
// Byte Formatting
// ============================================================

function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

// ============================================================
// MIME Type Icons
// ============================================================

function getMimeIcon(mime) {
  if (!mime) return '📄';
  if (mime.startsWith('image/')) return '🖼️';
  if (mime.startsWith('video/')) return '🎬';
  if (mime.startsWith('audio/')) return '🎵';
  if (mime === 'application/pdf') return '📕';
  if (mime.includes('word') || mime.includes('document')) return '📝';
  if (mime.includes('sheet') || mime.includes('excel')) return '📊';
  if (mime.includes('presentation') || mime.includes('powerpoint')) return '📊';
  if (mime.includes('zip') || mime.includes('archive') || mime.includes('compressed')) return '🗜️';
  if (mime === 'text/plain') return '📃';
  if (mime.includes('json') || mime.includes('javascript') || mime.includes('html') || mime.includes('css')) return '💻';
  return '📄';
}

// ============================================================
// Export to window
// ============================================================
window.showToast = showToast;
window.formatBytes = formatBytes;
window.getMimeIcon = getMimeIcon;
