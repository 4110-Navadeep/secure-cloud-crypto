/**
 * Secure Cloud — API Client
 * Centralized fetch wrapper with auth token handling
 */

const API = {
  _token: null,

  getToken() {
    if (!this._token) {
      this._token = localStorage.getItem('sc_token');
    }
    return this._token;
  },

  setToken(token) {
    this._token = token;
    if (token) {
      localStorage.setItem('sc_token', token);
    } else {
      localStorage.removeItem('sc_token');
    }
  },

  async request(method, path, body = null, options = {}) {
    const headers = {
      'Authorization': `Bearer ${this.getToken()}`,
    };

    // Only set Content-Type for JSON bodies (not FormData)
    if (body && !(body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }

    const config = {
      method,
      headers,
      credentials: 'include',
    };

    if (body) {
      config.body = body instanceof FormData ? body : JSON.stringify(body);
    }

    const response = await fetch(`/api${path}`, config);

    if (response.status === 401) {
      // Token expired or invalid — redirect to login
      API.setToken(null);
      localStorage.removeItem('sc_user');
      window.location.href = '/login.html';
      return;
    }

    if (options.rawResponse) return response;

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || data.message || 'Request failed');
      }
      return data;
    }

    // Non-JSON response (e.g., file download)
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || 'Request failed');
    }
    return response;
  },

  get(path, options) { return this.request('GET', path, null, options); },
  post(path, body, options) { return this.request('POST', path, body, options); },
  put(path, body, options) { return this.request('PUT', path, body, options); },
  patch(path, body, options) { return this.request('PATCH', path, body, options); },
  delete(path, options) { return this.request('DELETE', path, null, options); },

  // Download a file from a URL with auth
  async download(path, filename) {
    const response = await fetch(`/api${path}`, {
      headers: { 'Authorization': `Bearer ${this.getToken()}` },
      credentials: 'include',
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({ error: 'Download failed' }));
      throw new Error(data.error || 'Download failed');
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },
};

window.API = API;
