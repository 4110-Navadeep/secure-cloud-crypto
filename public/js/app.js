/**
 * Secure Cloud — Shared App Utilities
 * Toast notifications, formatting, sidebar, auth guards
 */

// ============================================================
// Toast Notifications
// ============================================================

function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container')
    || (() => {
      const el = document.createElement('div');
      el.id = 'toast-container';
      document.body.appendChild(el);
      return el;
    })();

  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(40px)';
    toast.style.transition = '0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ============================================================
// Formatting Utilities
// ============================================================

function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function formatDateShort(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
  });
}

function timeAgo(dateStr) {
  if (!dateStr) return '';
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function truncate(str, len = 30) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '...' : str;
}

function getMimeIcon(mime) {
  if (!mime) return '📄';
  if (mime.startsWith('image/')) return '🖼️';
  if (mime.startsWith('video/')) return '🎬';
  if (mime.startsWith('audio/')) return '🎵';
  if (mime === 'application/pdf') return '📕';
  if (mime.includes('word')) return '📝';
  if (mime.includes('sheet') || mime.includes('excel')) return '📊';
  if (mime.includes('presentation') || mime.includes('powerpoint')) return '📊';
  if (mime.includes('zip')) return '🗜️';
  if (mime === 'text/plain') return '📃';
  return '📄';
}

function getPermissionLabel(perm) {
  const map = {
    'preview': 'Preview Only',
    'download': 'Download',
    'preview_download': 'Preview & Download',
  };
  return map[perm] || perm;
}

function getStatusBadge(status) {
  const map = {
    'active': '<span class="badge badge-success">● Active</span>',
    'revoked': '<span class="badge badge-danger">● Revoked</span>',
    'expired': '<span class="badge badge-muted">● Expired</span>',
    'pending': '<span class="badge badge-warning">● Pending</span>',
    'success': '<span class="badge badge-success">✓ Success</span>',
    'failure': '<span class="badge badge-danger">✗ Failed</span>',
    'warning': '<span class="badge badge-warning">⚠ Warning</span>',
  };
  return map[status] || `<span class="badge badge-muted">${status}</span>`;
}

// ============================================================
// Auth Utilities
// ============================================================

function getCurrentUser() {
  try {
    const u = localStorage.getItem('sc_user');
    return u ? JSON.parse(u) : null;
  } catch { return null; }
}

function setCurrentUser(user) {
  if (user) {
    localStorage.setItem('sc_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('sc_user');
  }
}

function requireAuth(redirectIfNoAdmin = false) {
  const token = API.getToken();
  const user = getCurrentUser();
  if (!token || !user) {
    window.location.href = '/login.html';
    return null;
  }
  return user;
}

function requireAdmin() {
  const user = requireAuth();
  if (user && user.role !== 'admin') {
    showToast('Administrator access required', 'error');
    window.location.href = '/dashboard.html';
    return null;
  }
  return user;
}

async function logout() {
  try {
    await API.post('/auth/logout');
  } catch {}
  API.setToken(null);
  setCurrentUser(null);
  window.location.href = '/login.html';
}

// ============================================================
// Sidebar Initialization
// ============================================================

function initSidebar(currentPage) {
  const user = getCurrentUser();
  if (!user) return;

  // Set user info
  const avatarEl = document.getElementById('user-avatar');
  const nameEl = document.getElementById('user-name');
  const roleEl = document.getElementById('user-role');

  if (avatarEl) avatarEl.textContent = user.full_name?.charAt(0).toUpperCase() || 'U';
  if (nameEl) nameEl.textContent = user.full_name;
  if (roleEl) roleEl.textContent = user.role.toUpperCase();

  // Highlight active nav item
  const navItems = document.querySelectorAll('.nav-item[data-page]');
  navItems.forEach(item => {
    if (item.dataset.page === currentPage) {
      item.classList.add('active');
    }
  });

  // Hide admin-only items for members
  if (user.role !== 'admin') {
    document.querySelectorAll('.admin-only').forEach(el => el.remove());
  }

  // Mobile menu toggle
  const menuBtn = document.getElementById('mobile-menu-btn');
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');

  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('visible');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('visible');
    });
  }

  // Logout
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logout);
  }
}

// ============================================================
// Check Admin Setup on App Load
// ============================================================

async function checkAndRedirect() {
  const currentPath = window.location.pathname;

  // Skip for setup and register pages
  if (currentPath === '/setup.html' || currentPath === '/register.html') return;

  const data = await fetch('/api/auth/setup-status').then(r => r.json()).catch(() => null);

  if (data?.setupRequired && currentPath !== '/setup.html') {
    window.location.href = '/setup.html';
    return;
  }

  if (!data?.setupRequired && currentPath === '/setup.html') {
    window.location.href = '/login.html';
    return;
  }
}

// ============================================================
// Export
// ============================================================
window.showToast = showToast;
window.formatBytes = formatBytes;
window.formatDate = formatDate;
window.formatDateShort = formatDateShort;
window.timeAgo = timeAgo;
window.truncate = truncate;
window.getMimeIcon = getMimeIcon;
window.getPermissionLabel = getPermissionLabel;
window.getStatusBadge = getStatusBadge;
window.getCurrentUser = getCurrentUser;
window.setCurrentUser = setCurrentUser;
window.requireAuth = requireAuth;
window.requireAdmin = requireAdmin;
window.logout = logout;
window.initSidebar = initSidebar;
window.checkAndRedirect = checkAndRedirect;
