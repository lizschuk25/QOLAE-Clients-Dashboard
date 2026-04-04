// ==============================================
// sessionMiddleware.js - Unified Session Validation
// ==============================================
// Author: Liz (with Claude)
// Purpose: SSOT-compliant session validation for ClientsDashboard
// Architecture: All validation via ssotFetch, no local DB
// ==============================================

import ssotFetch from '../utils/ssotFetch.js';
import crypto from 'crypto';

const COOKIE_NAME = 'qolaeClientToken';
const LOGIN_REDIRECT = '/clientsLogin';

const SESSION_CACHE = new Map();
const SESSION_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export const BOOTSTRAP_CACHE = new Map();
export const BOOTSTRAP_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Device fingerprint generation
function generateDeviceFingerprint(request) {
  const userAgent = request.headers['user-agent'] || '';
  const acceptLanguage = request.headers['accept-language'] || '';
  const acceptEncoding = request.headers['accept-encoding'] || '';

  const fingerprint = crypto
    .createHash('sha256')
    .update(`${userAgent}:${acceptLanguage}:${acceptEncoding}`)
    .digest('hex');

  return fingerprint;
}

async function sessionMiddleware(request, reply) {
  // Skip public routes
  const publicRoutes = ['/health', '/status'];
  const urlPath = request.url.split('?')[0];

  if (urlPath.startsWith('/public/') || publicRoutes.includes(urlPath)) {
    return;
  }

  // Read cookie
  const token = request.cookies?.[COOKIE_NAME];

  if (!token) {
    return reply.redirect(LOGIN_REDIRECT);
  }

  // Check session validation cache first
  const cached = SESSION_CACHE.get(token);
  if (cached) {
    if (Date.now() < cached.expiresAt) {
      const deviceFingerprint = generateDeviceFingerprint(request);
      request.user = { ...cached.data.user, deviceFingerprint };
      request.degradedMode = true;
      if (cached.data.warningLevel) {
        reply.header('X-Session-Warning', cached.data.warningLevel);
      }
      return;
    } else {
      SESSION_CACHE.delete(token);
    }
  }

  // Attempt SSOT validation
  let ssotResult;
  let ssotReachable = true;
  try {
    const rawResponse = await ssotFetch('/auth/validateAndRefreshSession/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent']
      })
    });
    ssotResult = await rawResponse.json();
  } catch (err) {
    ssotReachable = false;
  }

  if (!ssotReachable) {
    const stale = SESSION_CACHE.get(token);
    if (stale) {
      const deviceFingerprint = generateDeviceFingerprint(request);
      request.user = { ...stale.data.user, deviceFingerprint };
      request.degradedMode = true;
      return;
    }
    return reply.redirect(LOGIN_REDIRECT);
  }

  if (!ssotResult || !ssotResult.valid) {
    return reply.redirect(LOGIN_REDIRECT);
  }

  SESSION_CACHE.set(token, {
    data: ssotResult,
    expiresAt: Date.now() + SESSION_CACHE_TTL
  });

  const deviceFingerprint = generateDeviceFingerprint(request);
  request.user = { ...ssotResult.user, deviceFingerprint };
  request.degradedMode = false;
  if (ssotResult.warningLevel) {
    reply.header('X-Session-Warning', ssotResult.warningLevel);
  }
}

export default sessionMiddleware;
