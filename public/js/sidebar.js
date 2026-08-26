/**
 * Sidebar HTML template — injected into all dashboard pages
 */

function renderSidebar() {
  return `
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-logo">
        <div class="logo-text">
          <span class="logo-icon">🔐</span>
          SECURE CLOUD
        </div>
        <div class="logo-subtitle">Hybrid Cryptography</div>
      </div>

      <nav class="sidebar-nav">
        <div class="nav-section">
          <div class="nav-section-label">Overview</div>
          <a href="/dashboard.html" class="nav-item" data-page="dashboard">
            <span class="nav-icon">📊</span> Dashboard
          </a>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Core Modules</div>
          <a href="/encryption.html" class="nav-item" data-page="encryption">
            <span class="nav-icon">🔒</span> Secure File Encryption
          </a>
          <a href="/my-files.html" class="nav-item" data-page="my-files">
            <span class="nav-icon">📁</span> My Files
          </a>
          <a href="/integrity.html" class="nav-item" data-page="integrity">
            <span class="nav-icon">🛡️</span> Integrity &amp; Authenticity
          </a>
          <a href="/sharing.html" class="nav-item" data-page="sharing">
            <span class="nav-icon">🤝</span> File Sharing
          </a>
          <a href="/shared-with-me.html" class="nav-item" data-page="shared-with-me">
            <span class="nav-icon">📨</span> Shared With Me
          </a>
          <a href="/external-package.html" class="nav-item" data-page="external-package">
            <span class="nav-icon">📦</span> Open Secure Package
          </a>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Cryptographic System</div>
          <a href="/key-management.html" class="nav-item" data-page="key-management">
            <span class="nav-icon">🗝️</span> Key Management
          </a>
          <a href="/performance.html" class="nav-item" data-page="performance">
            <span class="nav-icon">⚡</span> Performance Evaluation
          </a>
        </div>

        <div class="nav-section admin-only">
          <div class="nav-section-label">Security</div>
          <a href="/threat-monitoring.html" class="nav-item" data-page="threat-monitoring">
            <span class="nav-icon">🚨</span> Threat Monitoring
          </a>
          <a href="/security-activity.html" class="nav-item" data-page="security-activity">
            <span class="nav-icon">📋</span> Security Activity
          </a>
        </div>

        <div class="nav-section admin-only">
          <div class="nav-section-label">Administration</div>
          <a href="/members.html" class="nav-item" data-page="members">
            <span class="nav-icon">👥</span> Manage Members
          </a>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Account</div>
          <a href="/profile.html" class="nav-item" data-page="profile">
            <span class="nav-icon">👤</span> Profile
          </a>
          <a href="#" class="nav-item" id="logout-btn">
            <span class="nav-icon">🚪</span> Logout
          </a>
        </div>
      </nav>

      <div class="sidebar-footer">
        <div class="user-info">
          <div class="user-avatar" id="user-avatar">U</div>
          <div class="user-details">
            <div class="user-name" id="user-name">Loading...</div>
            <div class="user-role" id="user-role">USER</div>
          </div>
        </div>
      </div>
    </aside>
    <div class="sidebar-overlay" id="sidebar-overlay"></div>
  `;
}

window.renderSidebar = renderSidebar;
