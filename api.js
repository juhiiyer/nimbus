(function(){
  if (typeof window === 'undefined') return;
  const API_BASE = (typeof window.API_BASE_URL !== 'undefined' && window.API_BASE_URL) ? window.API_BASE_URL : '';

  const hdrs = (extra) => {
    const h = Object.assign({ }, extra || {});
    const t = localStorage.getItem('access_token');
    if (t) h['Authorization'] = `Bearer ${t}`;
    return h;
  };

  async function doFetch(path, opts) {
    const url = `${API_BASE}${path}`;
    const res = await fetch(url, opts);
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try { const j = await res.json(); detail = j.detail || JSON.stringify(j); } catch {}
      const err = new Error(detail);
      err.status = res.status; throw err;
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  const API = {
    base: () => API_BASE,
    token: () => localStorage.getItem('access_token'),
    setToken: (token) => { localStorage.setItem('access_token', token); localStorage.setItem('token_type','bearer'); },
    clearToken: () => { localStorage.removeItem('access_token'); localStorage.removeItem('token_type'); },

    health: () => doFetch('/health', { method: 'GET' }),

    register: async (email, password) => {
      const body = JSON.stringify({ email, password });
      const data = await doFetch('/auth/register', { method: 'POST', headers: hdrs({ 'Content-Type': 'application/json' }), body });
      if (data && data.access_token) API.setToken(data.access_token);
      return data;
    },

    login: async (email, password) => {
      const params = new URLSearchParams();
      params.set('username', email);
      params.set('password', password);
      const data = await doFetch('/auth/login', { method: 'POST', headers: hdrs({ 'Content-Type': 'application/x-www-form-urlencoded' }), body: params.toString() });
      if (data && data.access_token) API.setToken(data.access_token);
      return data;
    },

    storageInfo: (service) => doFetch(`/services/storage/${encodeURIComponent(service)}`, { method: 'GET', headers: hdrs() }),

    getUserServices: () => doFetch('/user/services', { method: 'GET', headers: hdrs() }),

    startGoogleOauth: async () => {
      const data = await doFetch('/auth/google/login', { method: 'GET' });
      if (data && data.auth_url) { window.location.href = data.auth_url; return; }
      throw new Error('No auth_url in response');
    },

    startDropboxOauth: async () => {
      const data = await doFetch('/auth/dropbox/login', { method: 'GET' });
      if (data && data.auth_url) { window.location.href = data.auth_url; return; }
      throw new Error('No auth_url in response');
    },

    uploadSimple: async (file, service = 'auto') => {
      if (!API.token()) throw new Error('Not authenticated. Please sign up or log in.');
      const fd = new FormData();
      fd.append('service', service);
      fd.append('file', file, file.name);
      const res = await fetch(`${API_BASE}/services/upload-simple`, {
        method: 'POST',
        headers: hdrs(), // do not set Content-Type; browser will set boundary
        body: fd
      });
      if (!res.ok) {
        let detail = `${res.status} ${res.statusText}`;
        try { const j = await res.json(); detail = j.detail || JSON.stringify(j); } catch {}
        const err = new Error(detail);
        err.status = res.status; throw err;
      }
      return res.json();
    },

    downloadBlob: async (service, fileIdOrPath) => {
      if (!API.token()) throw new Error('Not authenticated. Please sign up or log in.');
      const u = new URL(`${API_BASE}/services/download`);
      u.searchParams.set('service', service);
      u.searchParams.set('file_id', fileIdOrPath);
      const res = await fetch(u.toString(), { headers: hdrs() });
      if (!res.ok) {
        let detail = `${res.status} ${res.statusText}`;
        try { const j = await res.json(); detail = j.detail || JSON.stringify(j); } catch {}
        const err = new Error(detail);
        err.status = res.status; throw err;
      }
      const ct = res.headers.get('content-type') || 'application/octet-stream';
      const cd = res.headers.get('content-disposition') || '';
      let filename = 'download';
      const m = /filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i.exec(cd);
      if (m) filename = decodeURIComponent(m[1] || m[2] || filename);
      const blob = await res.blob();
      return { blob, filename, contentType: ct };
    },

    openFile: async (service, fileIdOrPath, suggestedName) => {
      // Pre-open a tab synchronously to preserve the user gesture (prevents popup blockers)
      const pre = window.open('about:blank', '_blank');
      try {
        const { blob, filename } = await API.downloadBlob(service, fileIdOrPath);
        const url = URL.createObjectURL(blob);
        if (pre) {
          pre.location = url;
        } else {
          // Fallback to programmatic download if popup blocked
          const a = document.createElement('a');
          a.href = url;
          a.download = suggestedName || filename || 'download';
          document.body.appendChild(a);
          a.click();
          a.remove();
        }
        // Revoke after a delay to allow the browser to load the blob
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
      } catch (e) {
        if (pre) pre.close();
        throw e;
      }
    }
  };

  window.NimbusAPI = API;
})();
