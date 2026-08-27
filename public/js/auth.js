/**
 * Secure Crypt — Authentication & Session Helper
 */

const AUTH_TOKEN_KEY = 'sc_auth_token';
const AUTH_USER_KEY = 'sc_auth_user';

function getToken() {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

function getUser() {
  const user = localStorage.getItem(AUTH_USER_KEY);
  try {
    return user ? JSON.parse(user) : null;
  } catch {
    return null;
  }
}

function saveSession(token, user) {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
  localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem(AUTH_USER_KEY);
}

function logout() {
  clearSession();
  window.location.href = '/login.html';
}

function isLoggedIn() {
  return !!getToken();
}

function isAdmin() {
  const user = getUser();
  return user && (user.role === 'admin' || user.role === 'primary_admin');
}

function isPrimaryAdmin() {
  const user = getUser();
  return user && user.role === 'primary_admin';
}

// Redirect if not logged in
function checkAuthRedirect() {
  const path = window.location.pathname;
  // Pages that don't require auth
  const publicPages = [
    '/login.html', '/register.html', '/admin-login.html',
    '/index.html', '/how-it-works.html', '/',
    '/help.html',
  ];
  const isPublicPage = publicPages.some(p => path.endsWith(p) || path === p);

  if (!isPublicPage && !isLoggedIn()) {
    window.location.href = '/login.html';
    return false;
  }

  // Redirect admin pages for non-admins
  if ((path.endsWith('/admin-panel.html') || path.endsWith('/admin.html')) && !isAdmin()) {
    window.location.href = '/dashboard.html';
    return false;
  }
  return true;
}

// Wrap global fetch to automatically add JWT headers
async function apiFetch(url, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let body = options.body;

  // Auto-serialize plain objects to JSON
  if (body && typeof body === 'object' && !(body instanceof FormData) && !(body instanceof Blob)) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    body = JSON.stringify(body);
  } else if (!(body instanceof FormData)) {
    // String body — ensure Content-Type is set if not FormData
    if (body) headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }

  const response = await fetch(url, { ...options, headers, body });

  if (response.status === 401) {
    clearSession();
    window.location.href = '/login.html';
    throw new Error('Session expired. Please log in again.');
  }

  return response;
}

// Run auth check immediately on page load
checkAuthRedirect();

// Bind helper functions globally
window.getToken = getToken;
window.getUser = getUser;
window.saveSession = saveSession;
window.clearSession = clearSession;
window.logout = logout;
window.isLoggedIn = isLoggedIn;
window.isAdmin = isAdmin;
window.isPrimaryAdmin = isPrimaryAdmin;
window.apiFetch = apiFetch;
