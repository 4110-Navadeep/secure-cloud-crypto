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
// Local Storage Activity & Statistics Logger
// ============================================================

function logLocalActivity(filename, action, status) {
  try {
    const history = JSON.parse(localStorage.getItem('sc_history') || '[]');
    const newEvent = {
      id: Date.now() + Math.random().toString(36).substr(2, 5),
      filename,
      action, // 'ENCRYPT', 'SIGN', 'VERIFY_SUCCESS', 'VERIFY_FAILED'
      status, // 'success', 'failure'
      timestamp: new Date().toISOString()
    };
    history.unshift(newEvent);
    // Keep last 50 events
    if (history.length > 50) history.pop();
    localStorage.setItem('sc_history', JSON.stringify(history));
    
    // Update stats
    const stats = JSON.parse(localStorage.getItem('sc_stats') || '{"total":0,"encrypted":0,"signed":0,"verified":0}');
    stats.total++;
    if (action === 'ENCRYPT') stats.encrypted++;
    if (action === 'SIGN') stats.signed++;
    if (action === 'VERIFY_SUCCESS' || action === 'VERIFY_FAILED') stats.verified++;
    localStorage.setItem('sc_stats', JSON.stringify(stats));
  } catch (e) {
    console.error('[LOCAL_LOG] Error writing stats:', e);
  }
}

function getLocalStats() {
  try {
    return JSON.parse(localStorage.getItem('sc_stats') || '{"total":0,"encrypted":0,"signed":0,"verified":0}');
  } catch (e) {
    return { total: 0, encrypted: 0, signed: 0, verified: 0 };
  }
}

function getLocalActivity() {
  try {
    return JSON.parse(localStorage.getItem('sc_history') || '[]');
  } catch (e) {
    return [];
  }
}

function clearLocalActivity() {
  localStorage.removeItem('sc_history');
  localStorage.removeItem('sc_stats');
}

// ============================================================
// Export to window
// ============================================================
window.showToast = showToast;
window.formatBytes = formatBytes;
window.getMimeIcon = getMimeIcon;
window.logLocalActivity = logLocalActivity;
window.getLocalStats = getLocalStats;
window.getLocalActivity = getLocalActivity;
window.clearLocalActivity = clearLocalActivity;

// ============================================================
// Mobile Hamburger Menu — runs on all pages
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  const hamburger = document.getElementById('hamburger-btn');
  const navLinks = document.querySelector('.app-nav-links');

  if (hamburger && navLinks) {
    hamburger.addEventListener('click', () => {
      const open = navLinks.classList.toggle('mobile-open');
      hamburger.textContent = open ? '✕' : '☰';
      hamburger.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    // Close menu when a link is clicked
    navLinks.querySelectorAll('.app-nav-link').forEach(link => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('mobile-open');
        hamburger.textContent = '☰';
      });
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (!hamburger.contains(e.target) && !navLinks.contains(e.target)) {
        navLinks.classList.remove('mobile-open');
        hamburger.textContent = '☰';
      }
    });
  }
});
