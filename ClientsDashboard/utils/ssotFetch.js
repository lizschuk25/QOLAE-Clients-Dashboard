// ==============================================
// ssotFetch.js — SSOT API Fetch Utility
// ==============================================
// Purpose: Wraps fetch() for all server-to-server calls to the SSOT API
// Injects x-internal-secret header on every request
// Centralises SSOT_BASE_URL so route files don't define it individually
// ==============================================

const SSOT_BASE_URL = process.env.SSOT_BASE_URL || 'https://api.qolae.com';

/**
 * ssotFetch — authenticated fetch to SSOT API
 * @param {string} path — API path (e.g. '/api/clients/consent/sign')
 * @param {object} options — standard fetch options (method, headers, body, etc.)
 * @returns {Promise<Response>} — standard fetch Response
 */
async function ssotFetch(path, options = {}) {
  const INTERNAL_API_SECRET = process.env.INTERNAL_API_SECRET;
  if (!INTERNAL_API_SECRET) {
    throw new Error('INTERNAL_API_SECRET not set in environment');
  }

  const url = `${SSOT_BASE_URL}${path}`;

  const headers = {
    ...options.headers,
    'x-internal-secret': INTERNAL_API_SECRET
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers
    });
    clearTimeout(timeout);
    return response;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

export default ssotFetch;
