/**
 * Secure Crypt — Sidebar Component & Controller
 * Dynanmic, session-aware workspace sidebar.
 */

function renderSidebar() {
  const user = window.getUser ? window.getUser() : null;
  const loggedIn = !!user;
  const isAdmin = window.isAdmin ? window.isAdmin() : false;

  const userInitials = user && user.name ? user.name.slice(0, 2).toUpperCase() : 'US';
  const userName = user && user.name ? user.name : 'Not Logged In';
  const userRole = user && user.role ? (user.role.includes('admin') ? 'ADMINISTRATOR' : 'USER SESSION') : 'GUEST';

  return `
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-logo">
        <a href="/" class="logo-text" style="text-decoration: none;">
          <span class="logo-icon">🔐</span>
          SECURE <span class="brand-accent" style="color: var(--accent-cyan);">CRYPT</span>
        </a>
        <div class="logo-subtitle">Hybrid Cryptography Workspace</div>
      </div>

      <nav class="sidebar-nav">
        <div class="nav-section">
          <div class="nav-section-label">Overview</div>
          <a href="/dashboard.html" class="nav-item" data-page="dashboard">
            <span class="nav-icon">📊</span> Dashboard
          </a>
          <a href="/my-files.html" class="nav-item" data-page="my-files">
            <span class="nav-icon">📁</span> My Files
          </a>
          ${loggedIn ? `
          <a href="/published-files.html" class="nav-item" data-page="published-files">
            <span class="nav-icon">📢</span> Published Files
          </a>
          ` : ''}
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Core Modules</div>
          <a href="/encrypt.html" class="nav-item" data-page="encrypt">
            <span class="nav-icon">🔒</span> Secure File
          </a>
          <a href="/verify.html" class="nav-item" data-page="verify">
            <span class="nav-icon">🔓</span> Open Package
          </a>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Cryptographic System</div>
          <a href="/how-it-works.html" class="nav-item" data-page="how-it-works">
            <span class="nav-icon">🏗️</span> Architecture
          </a>
          <a href="/key-management.html" class="nav-item" data-page="key-management">
            <span class="nav-icon">🗝️</span> Key Management
          </a>
          <a href="/integrity.html" class="nav-item" data-page="integrity">
            <span class="nav-icon">🛡️</span> Integrity &amp; Authenticity
          </a>
          <a href="/performance.html" class="nav-item" data-page="performance">
            <span class="nav-icon">⚡</span> Performance Evaluation
          </a>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Security &amp; Operations</div>
          <a href="/threat-monitoring.html" class="nav-item" data-page="threat-monitoring">
            <span class="nav-icon">🚨</span> Threat Monitoring
          </a>
          ${loggedIn ? `
          <a href="/access-requests.html" class="nav-item" data-page="access-requests">
            <span class="nav-icon">🔑</span> Access Requests
          </a>
          <a href="/shared-with-me.html" class="nav-item" data-page="shared-with-me">
            <span class="nav-icon">🤝</span> Shared With Me
          </a>
          ` : ''}
          ${isAdmin ? `
          <a href="/admin-panel.html" class="nav-item" data-page="admin">
            <span class="nav-icon">💼</span> Admin Panel
          </a>
          ` : ''}
          <a href="/help.html" class="nav-item" data-page="help">
            <span class="nav-icon">ℹ️</span> Help &amp; Support
          </a>
        </div>
      </nav>

      <div class="sidebar-footer">
        <div class="user-info">
          <div class="user-avatar">${userInitials}</div>
          <div class="user-details" style="display:flex; flex-direction:column; min-width:0;">
            <div class="user-name" style="text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">${userName}</div>
            <div class="user-role" style="font-size:10px; color:var(--text-muted);">${userRole}</div>
            ${loggedIn ? `
            <button type="button" data-action="logout" style="background:none; border:none; padding:0; cursor:pointer; color:#ef4444; font-size:11px; font-weight:600; font-family:inherit; text-decoration:none; margin-top:4px; display:inline;">Logout ↩</button>
            ` : `
            <a href="/login.html" style="color:var(--accent-cyan); font-size:11px; font-weight:600; text-decoration:none; margin-top:4px;">Login →</a>
            `}
          </div>
        </div>
      </div>
    </aside>
    <div class="sidebar-overlay" id="sidebar-overlay"></div>
  `;
}

function initSidebar(currentPage) {
  const placeholder = document.getElementById('sidebar-placeholder');
  if (placeholder) {
    placeholder.innerHTML = renderSidebar();

    // Attach logout handler after sidebar HTML is injected into the DOM.
    // Uses data-action="logout" to target the button without relying on
    // an href or inline onclick attribute.
    const logoutBtn = placeholder.querySelector('[data-action="logout"]');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', function() {
        // Reuse existing auth.js clearSession() to wipe both token and user data
        localStorage.removeItem('sc_auth_token');
        localStorage.removeItem('sc_auth_user');
        window.location.href = '/login.html';
      });
    }
  }

  // Highlight active page
  const navItems = document.querySelectorAll('.nav-item[data-page]');
  navItems.forEach(item => {
    if (item.dataset.page === currentPage) {
      item.classList.add('active');
    }
  });

  // Mobile menu toggle
  const menuBtn = document.getElementById('mobile-menu-btn');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');

  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', () => {
      sidebar.classList.add('open');
      if (overlay) overlay.classList.add('visible');
    });
  }

  if (overlay && sidebar) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('visible');
    });
  }
}

window.renderSidebar = renderSidebar;
window.initSidebar = initSidebar;
