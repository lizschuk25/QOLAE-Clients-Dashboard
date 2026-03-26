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

  try {
    // Validate session via SSOT
    const rawResponse = await ssotFetch('/auth/validateAndRefreshSession/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent']
      })
    });
    const response = await rawResponse.json();

    if (!response || !response.valid) {
      return reply.redirect(LOGIN_REDIRECT);
    }

    // Decorate request.user
    const deviceFingerprint = generateDeviceFingerprint(request);

    request.user = {
      ...response.user,
      deviceFingerprint
    };

    // Set warning header if present
    if (response.warningLevel) {
      reply.header('X-Session-Warning', response.warningLevel);
    }

  } catch (err) {
    console.error('Session middleware error:', err.message);
    return reply.redirect(LOGIN_REDIRECT);
  }
}

export default sessionMiddleware;
