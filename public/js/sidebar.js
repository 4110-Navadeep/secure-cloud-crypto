/**
 * Secure Crypt — Sidebar Component & Controller
 * Stateless local session sidebar.
 */

function renderSidebar() {
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
          <a href="/admin.html" class="nav-item" data-page="admin">
            <span class="nav-icon">💼</span> Admin Panel
          </a>
          <a href="/help.html" class="nav-item" data-page="help">
            <span class="nav-icon">ℹ️</span> Help &amp; Support
          </a>
        </div>
      </nav>

      <div class="sidebar-footer">
        <div class="user-info">
          <div class="user-avatar">WS</div>
          <div class="user-details">
            <div class="user-name">Local Workspace</div>
            <div class="user-role">Stateless Mode</div>
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
