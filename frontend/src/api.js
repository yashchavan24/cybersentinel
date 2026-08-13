const TOKEN_KEY = 'cs_token';
export const getToken = () => sessionStorage.getItem(TOKEN_KEY);
export const setToken = t => t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY);

// This reads the Vercel environment variable!
const BASE = import.meta.env.VITE_API_URL || '';

export async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  
  const url = `${BASE}/api${path}`;
  console.log('[API Calling]:', url); // This helps you debug in F12!
  
  const res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
  
  if (res.status === 401 && !path.startsWith('/auth')) { 
    setToken(null); 
    window.location.href = '/login'; 
  }
  
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}