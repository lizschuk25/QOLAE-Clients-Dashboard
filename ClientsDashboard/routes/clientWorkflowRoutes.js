// ==============================================
// CLIENTS DASHBOARD - WORKFLOW ROUTES
// ==============================================
// Purpose: Dashboard pages that call SSOT API
// Author: Liz
// Date: 27th December 2025
// Architecture: Calls api.qolae.com for data (SSOT)
// No direct DB queries - SSOT compliant
// ==============================================

// ==============================================
// LOCATION BLOCK A: CONFIGURATION
// ==============================================
import ssotFetch from '../utils/ssotFetch.js';

// Preview cache - stores form data temporarily for server-side preview flow
// Key: clientPin, Value: { formData, pdfBase64, timestamp }
// Auto-expires after 10 minutes
const previewCache = new Map();
const PREVIEW_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Clean expired previews periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of previewCache.entries()) {
        if (now - value.timestamp > PREVIEW_CACHE_TTL) {
            previewCache.delete(key);
        }
    }
}, 60 * 1000); // Check every minute

// ==============================================
// LOCATION BLOCK B: HELPER FUNCTIONS
// ==============================================

// Calculate time ago for notifications
function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);

    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + ' days ago';

    return new Date(date).toLocaleDateString('en-GB');
}

// ==============================================
// LOCATION BLOCK C: AUTHENTICATION MIDDLEWARE
// ==============================================
async function authenticateClient(request, reply) {
    try {
        await request.jwtVerify();

        if (request.user.role !== 'client') {
            throw new Error('Invalid role');
        }
    } catch (error) {
        const loginUrl = process.env.LOGIN_URL || '/clientsLogin';
        return reply.redirect(loginUrl + '?error=Session expired. Please login again.');
    }
}

// API authentication (returns JSON, not redirect)
async function authenticateClientAPI(request, reply) {
    try {
        await request.jwtVerify();

        if (request.user.role !== 'client') {
            throw new Error('Invalid role');
        }
    } catch (error) {
        return reply.code(401).send({
            success: false,
            error: 'Authentication required',
            redirectTo: '/clientsLogin'
        });
    }
}

// ==============================================
// LOCATION BLOCK D: ROUTES EXPORT
// ==============================================
// NOTE: Main /clientsDashboard route is in cd_server.js (uses buildClientBootstrapData)
// This file contains supporting API routes for the dashboard
export default async function clientWorkflowRoutes(fastify, options) {

    // ==============================================
    // LOCATION BLOCK 1: SIGN CONSENT FORM (DIGITAL SIGNATURE)
    // Receives form-urlencoded data with signature as base64 string
    // OR uses cached data from preview flow (confirmFromPreview=true)
    // Calls SSOT API for consent signing
    // ==============================================
    fastify.post('/api/consent/sign', async (request, reply) => {
        try {
            // Verify JWT from cookie
            await request.jwtVerify();

            if (request.user.role !== 'client') {
                return reply.code(401).send({
                    success: false,
                    error: 'Authentication required'
                });
            }

            const { clientPin, clientName } = request.user;
            const formData = request.body;

            fastify.log.info({ event: 'consentSignRequest', clientPin });

            let signatureData;
            let consentData;

            // Check if this is a confirmation from preview flow
            if (formData.confirmFromPreview === 'true') {
                fastify.log.info({ event: 'confirmFromPreview', clientPin });

                // Get cached data from preview
                const cachedPreview = previewCache.get(clientPin);
                if (!cachedPreview) {
                    fastify.log.warn({ event: 'previewCacheExpired', clientPin });
                    return reply.redirect('/clientsDashboard?clientPin=' + clientPin + '&error=Preview expired. Please sign again.');
                }

                // Use cached signature and consent data
                signatureData = cachedPreview.signatureData;
                consentData = cachedPreview.consentData;

                // Clear cache after use
                previewCache.delete(clientPin);

            } else {
                // Standard flow - get data from form submission
                signatureData = formData.clientSignatureData;
                if (!signatureData || signatureData.trim() === '') {
                    fastify.log.warn({ event: 'noSignatureData' });
                    return reply.code(400).send({
                        success: false,
                        error: 'Signature is required'
                    });
                }

                // Extract consent radio values (yes/no pattern)
                consentData = {
                    inaConsentA: formData.inaConsentA === 'yes',
                    inaConsentB: formData.inaConsentB === 'yes',
                    ongoingCaseManagementConsentA: formData.ongoingCaseManagementConsentA === 'yes',
                    ongoingCaseManagementConsentB: formData.ongoingCaseManagementConsentB === 'yes',
                    medicalNotesConsentA: formData.medicalNotesConsentA === 'yes',
                    medicalNotesConsentB: formData.medicalNotesConsentB === 'yes',
                    healthcareCollaborationConsentA: formData.healthcareCollaborationConsentA === 'yes',
                    healthcareCollaborationConsentB: formData.healthcareCollaborationConsentB === 'yes',
                    documentationConsentA: formData.documentationConsentA === 'yes',
                    documentationConsentB: formData.documentationConsentB === 'yes',
                    reportsConsentA: formData.reportsConsentA === 'yes',
                    reportsConsentB: formData.reportsConsentB === 'yes',
                    legalReportingConsent: formData.legalReportingConsent === 'yes',
                    dataProtectionConsent: formData.dataProtectionConsent === 'yes',
                    withdrawalRightsConsent: formData.withdrawalRightsConsent === 'yes',
                    declarationConsent: formData.declarationConsent === 'yes'
                };

                // Validate all required consents are checked
                const allConsentsGiven = Object.values(consentData).every(v => v === true);
                if (!allConsentsGiven) {
                    fastify.log.warn({ event: 'incompleteConsents' });
                    return reply.code(400).send({
                        success: false,
                        error: 'All consent checkboxes must be checked'
                    });
                }
            }

            fastify.log.info({ event: 'consentsValidated' });

            // Call SSOT API to save consent
            const apiResponse = await ssotFetch('/api/clients/consent/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientPin: clientPin,
                    clientName: clientName,
                    signatureData: signatureData,
                    consentData: consentData,
                    ipAddress: request.ip,
                    userAgent: request.headers['user-agent'],
                    signedAt: new Date().toISOString()
                })
            });

            const apiData = await apiResponse.json();

            if (apiData.success) {
                fastify.log.info({ event: 'consentSigned', clientPin });
                // Redirect back to dashboard with success message
                return reply.redirect('/clientsDashboard?clientPin=' + clientPin + '&success=Consent form signed successfully');
            } else {
                fastify.log.error({ event: 'ssotApiError', error: apiData.error });
                return reply.code(apiResponse.status).send({
                    success: false,
                    error: apiData.error || 'Failed to save consent'
                });
            }

        } catch (error) {
            fastify.log.error({ event: 'consentSignError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to sign consent form: ' + error.message
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 2: PREVIEW CONSENT FORM (POST)
    // Generates PDF preview, caches it, and redirects to dashboard with preview visible
    // SERVER-SIDE PATTERN: POST → cache → redirect → GET serves PDF
    // ==============================================
    fastify.post('/api/consent/preview', async (request, reply) => {
        try {
            await request.jwtVerify();

            if (request.user.role !== 'client') {
                return reply.redirect('/clientsDashboard?error=Session expired');
            }

            const { clientPin, clientName } = request.user;
            const formData = request.body;

            fastify.log.info({ event: 'previewRequest', clientPin });

            const signatureData = formData.clientSignatureData;
            if (!signatureData || signatureData.trim() === '') {
                return reply.redirect(`/clientsDashboard?clientPin=${clientPin}&showModal=consent&error=Please sign before previewing`);
            }

            // Extract consent radio values (yes/no pattern)
            const consentData = {
                inaConsentA: formData.inaConsentA === 'yes',
                inaConsentB: formData.inaConsentB === 'yes',
                ongoingCaseManagementConsentA: formData.ongoingCaseManagementConsentA === 'yes',
                ongoingCaseManagementConsentB: formData.ongoingCaseManagementConsentB === 'yes',
                medicalNotesConsentA: formData.medicalNotesConsentA === 'yes',
                medicalNotesConsentB: formData.medicalNotesConsentB === 'yes',
                healthcareCollaborationConsentA: formData.healthcareCollaborationConsentA === 'yes',
                healthcareCollaborationConsentB: formData.healthcareCollaborationConsentB === 'yes',
                documentationConsentA: formData.documentationConsentA === 'yes',
                documentationConsentB: formData.documentationConsentB === 'yes',
                reportsConsentA: formData.reportsConsentA === 'yes',
                reportsConsentB: formData.reportsConsentB === 'yes',
                legalReportingConsent: formData.legalReportingConsent === 'yes',
                dataProtectionConsent: formData.dataProtectionConsent === 'yes',
                withdrawalRightsConsent: formData.withdrawalRightsConsent === 'yes',
                declarationConsent: formData.declarationConsent === 'yes'
            };

            const apiResponse = await ssotFetch('/api/clients/consent/preview', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    clientPin: clientPin,
                    clientName: clientName,
                    signatureData: signatureData,
                    consentData: consentData
                })
            });

            const apiData = await apiResponse.json();

            if (apiData.success) {
                fastify.log.info({ event: 'previewCached', clientPin });

                // Store in preview cache for confirm submission and GET endpoint
                previewCache.set(clientPin, {
                    formData: formData,
                    consentData: consentData,
                    signatureData: signatureData,
                    pdfBase64: apiData.pdfBase64,
                    timestamp: Date.now()
                });

                // SERVER-SIDE REDIRECT: Show preview in modal
                return reply.redirect(`/clientsDashboard?clientPin=${clientPin}&showModal=consent&showPreview=true`);
            } else {
                return reply.redirect(`/clientsDashboard?clientPin=${clientPin}&showModal=consent&error=${encodeURIComponent(apiData.error || 'Preview failed')}`);
            }

        } catch (error) {
            fastify.log.error({ event: 'previewGenerateError', error: error.message });
            return reply.redirect(`/clientsDashboard?error=${encodeURIComponent(error.message)}`);
        }
    });

    // ==============================================
    // LOCATION BLOCK 2B: GET PREVIEW PDF (TOB Pattern)
    // Serves cached PDF for iframe display - browser renders natively
    // ==============================================
    fastify.get('/api/consent/previewPdf', async (request, reply) => {
        try {
            await request.jwtVerify();

            const { clientPin } = request.query;
            const pin = clientPin || request.user.clientPin;

            if (!pin) {
                return reply.code(400).send({ error: 'Client PIN required' });
            }

            // Check preview cache
            if (!previewCache.has(pin)) {
                fastify.log.warn({ event: 'noCachedPreview', pin });
                return reply.code(404).send({ error: 'No preview available' });
            }

            const cachedData = previewCache.get(pin);
            const pdfBuffer = Buffer.from(cachedData.pdfBase64, 'base64');

            fastify.log.info({ event: 'servingCachedPreview', pin });

            return reply
                .type('application/pdf')
                .header('Content-Disposition', `inline; filename="consent-preview-${pin}.pdf"`)
                .send(pdfBuffer);

        } catch (error) {
            fastify.log.error({ event: 'previewServingError', error: error.message });
            return reply.code(500).send({ error: 'Failed to serve preview' });
        }
    });

    // ==============================================
    // LOCATION BLOCK 3: GET NOTIFICATIONS
    // Calls SSOT API
    // ==============================================
    fastify.get('/api/notifications', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { clientPin } = request.user;

        try {
            const apiResponse = await ssotFetch('/api/clients/notifications', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: clientPin })
            });

            const apiData = await apiResponse.json();

            if (apiData.success) {
                return reply.send({
                    success: true,
                    notifications: apiData.notifications.map(n => ({
                        ...n,
                        timeAgo: getTimeAgo(n.createdAt)
                    })),
                    unreadCount: apiData.unreadCount
                });
            }

            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            fastify.log.error({ event: 'notificationsFetchError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch notifications'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 4: MARK NOTIFICATION AS READ
    // Calls SSOT API
    // ==============================================
    fastify.post('/api/notifications/:id/read', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { id } = request.params;
        const { clientPin } = request.user;

        try {
            const apiResponse = await ssotFetch('/api/clients/notifications/read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: clientPin, notificationId: id })
            });

            const apiData = await apiResponse.json();
            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            fastify.log.error({ event: 'notificationMarkReadError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to mark notification as read'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 5: GET UNREAD NOTIFICATION COUNT
    // Calls SSOT API
    // ==============================================
    fastify.get('/api/notifications/count', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { clientPin } = request.user;

        try {
            const apiResponse = await ssotFetch('/api/clients/notifications/count', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: clientPin })
            });

            const apiData = await apiResponse.json();
            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            fastify.log.error({ event: 'notificationCountError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch notification count'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 6: VIEW SIGNED CONSENT FORM
    // Calls SSOT API endpoint to fetch signed consent PDF
    // Handles both Standard and POA pathways via database lookup
    // ==============================================
    fastify.get('/consent/view', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { clientPin } = request.user;

        try {
            fastify.log.info({ event: 'viewSignedConsent', clientPin });

            // Get JWT token from cookie to pass to SSOT API
            const clientToken = request.cookies.qolaeClientToken;

            if (!clientToken) {
                fastify.log.warn({ event: 'noClientToken' });
                return reply.code(401).send({
                    success: false,
                    error: 'Authentication required'
                });
            }

            // Call SSOT API endpoint for signed consent PDF
            fastify.log.info({ event: 'ssotConsentView' });

            const pdfResponse = await ssotFetch('/api/clients/consent/view', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${clientToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!pdfResponse.ok) {
                const errorData = await pdfResponse.json().catch(() => ({}));
                fastify.log.error({ event: 'ssotConsentViewError', status: pdfResponse.status });

                if (pdfResponse.status === 400) {
                    return reply.code(400).send({
                        success: false,
                        error: errorData.error || 'Consent form has not been signed yet'
                    });
                }

                return reply.code(pdfResponse.status).send({
                    success: false,
                    error: errorData.error || 'Signed consent form not found'
                });
            }

            // Get the PDF as a buffer
            const pdfBuffer = await pdfResponse.arrayBuffer();

            // Set headers for PDF viewing (inline)
            reply.header('Content-Type', 'application/pdf');
            reply.header('Content-Disposition', `inline; filename="SignedConsent_${clientPin}.pdf"`);
            reply.header('Content-Length', pdfBuffer.byteLength);

            fastify.log.info({ event: 'servingSignedConsent', clientPin, bytes: pdfBuffer.byteLength });
            return reply.send(Buffer.from(pdfBuffer));

        } catch (error) {
            fastify.log.error({ event: 'consentViewError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to retrieve consent form'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 7: VIEW DOCUMENTS LIBRARY
    // Calls SSOT API for access check
    // ==============================================
    fastify.get('/documents', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { clientPin } = request.user;

        try {
            // Check if Documents Library access is enabled via API
            const apiResponse = await ssotFetch('/api/clients/documentsLibrary/access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: clientPin })
            });

            const apiData = await apiResponse.json();

            if (!apiData.documentsLibraryEnabled) {
                return reply.code(403).send({
                    success: false,
                    error: 'Documents Library access requires signed consent form'
                });
            }

            // TODO: Fetch documents from secure storage
            return reply.send({
                success: false,
                error: 'Documents Library not implemented yet'
            });

        } catch (error) {
            fastify.log.error({ event: 'documentsFetchError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch documents'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 8: VIEW FINAL REPORT
    // Calls SSOT API for access check
    // ==============================================
    fastify.get('/report/view', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { clientPin } = request.user;

        try {
            // Check if report is available via API
            const apiResponse = await ssotFetch('/api/clients/report/access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: clientPin })
            });

            const apiData = await apiResponse.json();

            if (!apiData.finalReportAvailable) {
                return reply.code(403).send({
                    success: false,
                    error: 'Final report is not yet available'
                });
            }

            // TODO: Fetch report from secure storage
            return reply.send({
                success: false,
                error: 'Report viewing not implemented yet'
            });

        } catch (error) {
            fastify.log.error({ event: 'reportFetchError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch report'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 9: CLIENT PROFILE / BOOTSTRAP DATA
    // Calls SSOT API
    // ==============================================
    fastify.get('/api/client/profile', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { clientPin } = request.user;

        try {
            const apiResponse = await ssotFetch('/api/clients/profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin: clientPin })
            });

            const apiData = await apiResponse.json();
            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            fastify.log.error({ event: 'clientProfileError', error: error.message });
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch client profile'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 10: LOGOUT
    // ==============================================
    fastify.get('/logout', async (request, reply) => {
        const pin = request.user?.clientPin;
        if (pin) {
          try {
            await ssotFetch('/auth/invalidateSession', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ userType: 'clients', pin })
            });
          } catch (invalidateError) {
            console.error('Session invalidation failed:', invalidateError.message);
          }
        }

        reply.clearCookie('qolaeClientToken', {
            path: '/',
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: process.env.COOKIE_DOMAIN || '.qolae.com'
        });

        const loginUrl = process.env.LOGIN_URL || '/clientsLogin';
        return reply.redirect(loginUrl + '?message=You have been logged out successfully.');
    });

    // ==============================================
    // LOCATION BLOCK 11: HTMX - VIEW SIGNED CONSENT MODAL
    // Returns modal partial for HTMX to swap in
    // ==============================================
    fastify.get('/consent/viewModal', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { clientPin } = request.user;
        fastify.log.info({ event: 'htmxModalRequest', clientPin });

        return reply.view('partials/viewSignedConsentModal.ejs', {
            clientPin: clientPin
        });
    });

    // ==============================================
    // LOCATION BLOCK 12: HTMX - CLOSE MODAL
    // Returns empty string to clear modal container
    // ==============================================
    fastify.get('/consent/closeModal', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        fastify.log.info({ event: 'htmxModalClose' });
        reply.type('text/html');
        return reply.send('');
    });

    fastify.log.info({ event: 'clientWorkflowRoutesRegistered' });
}

// Export previewCache for access from cd_server.js dashboard route
export { previewCache };
