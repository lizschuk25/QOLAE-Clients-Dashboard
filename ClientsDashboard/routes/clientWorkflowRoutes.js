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
const API_URL = process.env.API_URL || 'https://api.qolae.com';

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
export default async function clientWorkflowRoutes(fastify, options) {

    // ==============================================
    // LOCATION BLOCK 1: CLIENTS DASHBOARD - MAIN VIEW
    // Calls SSOT API for data
    // ==============================================
    fastify.get('/clientsDashboard', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { pin, name, email } = request.user;

        try {
            // Call SSOT API for dashboard data
            const apiResponse = await fetch(API_URL + '/api/clients/dashboardData', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
            });

            const apiData = await apiResponse.json();

            if (!apiData.success) {
                console.error('[ClientWorkflow] API error:', apiData.error);
                return reply.code(apiResponse.status).send({
                    success: false,
                    error: apiData.error || 'Failed to load dashboard'
                });
            }

            const client = apiData.client;
            const notifications = apiData.notifications || [];
            const unreadCount = apiData.unreadCount || 0;

            // Calculate workflow progress
            const workflowSteps = [
                {
                    label: 'Initial Contact',
                    status: 'completed',
                    statusLabel: 'Completed'
                },
                {
                    label: 'Consent Form',
                    status: client.consentSigned ? 'completed' : 'active',
                    statusLabel: client.consentSigned ? 'Completed' : 'Action Required'
                },
                {
                    label: 'INA Appointment',
                    status: client.inaAppointmentScheduled ? 'completed' : (client.consentSigned ? 'active' : 'pending'),
                    statusLabel: client.inaAppointmentScheduled ? 'Scheduled' : (client.consentSigned ? 'Ready to Schedule' : 'Pending Consent')
                },
                {
                    label: 'Documents Library',
                    status: client.documentsLibraryEnabled ? 'active' : 'pending',
                    statusLabel: client.documentsLibraryEnabled ? 'Now Available' : 'Requires Consent'
                },
                {
                    label: 'Final Report',
                    status: client.finalReportAvailable ? 'completed' : 'pending',
                    statusLabel: client.finalReportAvailable ? 'Available' : 'Pending Assessment'
                }
            ];

            // Calculate progress percentage
            const completedSteps = workflowSteps.filter(s => s.status === 'completed').length;
            const progressPercentage = Math.round((completedSteps / workflowSteps.length) * 100);

            // Card states for EJS
            const cards = {
                consentForm: {
                    signed: client.consentSigned,
                    signedAt: client.consentSignedAt,
                    status: client.consentSigned ? 'completed' : 'active',
                    statusLabel: client.consentSigned ? 'Completed' : 'Action Required'
                },
                inaAppointment: {
                    scheduled: client.inaAppointmentScheduled,
                    appointmentDate: client.inaAppointmentDate,
                    canSchedule: client.consentSigned,
                    status: client.inaAppointmentScheduled ? 'completed' : (client.consentSigned ? 'active' : 'pending'),
                    statusLabel: client.inaAppointmentScheduled ? 'Scheduled' : (client.consentSigned ? 'Ready to Schedule' : 'Pending Consent')
                },
                documentsLibrary: {
                    enabled: client.documentsLibraryEnabled,
                    status: client.documentsLibraryEnabled ? 'active' : 'pending',
                    statusLabel: client.documentsLibraryEnabled ? 'Now Available' : 'Requires Consent'
                },
                finalReport: {
                    available: client.finalReportAvailable,
                    reportDate: client.finalReportDate,
                    status: client.finalReportAvailable ? 'completed' : 'pending',
                    statusLabel: client.finalReportAvailable ? 'Available' : 'Pending Assessment'
                }
            };

            // Session data
            const session = {
                lastLogin: client.lastLogin ? new Date(client.lastLogin).toLocaleString('en-GB') : 'First login',
                isFirstLogin: !client.lastLogin
            };

            // CSRF token for forms
            const csrfToken = fastify.jwt.sign({ csrf: true, pin });

            return reply.view('clientsDashboard.ejs', {
                client: {
                    id: client.clientPin,
                    name: client.clientName,
                    firstName: client.clientName ? client.clientName.split(' ')[0] : 'Client',
                    email: client.clientEmail
                },
                workflow: {
                    steps: workflowSteps,
                    currentStepLabel: client.workflowStatus || 'In Progress'
                },
                progressPercentage,
                cards,
                notifications: {
                    items: notifications.map(n => ({
                        id: n.id,
                        title: n.title,
                        message: n.message,
                        type: n.type,
                        read: n.read,
                        timeAgo: getTimeAgo(n.createdAt)
                    })),
                    unreadCount
                },
                session,
                csrfToken
            });

        } catch (error) {
            console.error('[ClientWorkflow] Error loading dashboard:', error.message);
            return reply.code(500).send({
                success: false,
                error: 'Failed to load dashboard'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 2: SIGN CONSENT FORM (DIGITAL SIGNATURE)
    // Calls SSOT API for consent signing
    // ==============================================
    fastify.post('/api/consent/sign', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { pin, name } = request.user;

        try {
            // Get signature from multipart form
            const data = await request.file();

            if (!data) {
                return reply.code(400).send({
                    success: false,
                    error: 'Signature file is required'
                });
            }

            const signatureBuffer = await data.toBuffer();
            const signatureBase64 = signatureBuffer.toString('base64');

            // Call SSOT API
            const apiResponse = await fetch(API_URL + '/api/clients/consent/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    pin,
                    clientName: name,
                    signatureData: signatureBase64,
                    ipAddress: request.ip
                })
            });

            const apiData = await apiResponse.json();

            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            console.error('[ClientWorkflow] Error signing consent:', error.message);
            return reply.code(500).send({
                success: false,
                error: 'Failed to sign consent form'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 3: GET NOTIFICATIONS
    // Calls SSOT API
    // ==============================================
    fastify.get('/api/notifications', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            const apiResponse = await fetch(API_URL + '/api/clients/notifications', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
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
            console.error('[ClientWorkflow] Error fetching notifications:', error.message);
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
        const { pin } = request.user;

        try {
            const apiResponse = await fetch(API_URL + '/api/clients/notifications/read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin, notificationId: id })
            });

            const apiData = await apiResponse.json();
            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            console.error('[ClientWorkflow] Error marking notification as read:', error.message);
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
        const { pin } = request.user;

        try {
            const apiResponse = await fetch(API_URL + '/api/clients/notifications/count', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
            });

            const apiData = await apiResponse.json();
            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            console.error('[ClientWorkflow] Error fetching notification count:', error.message);
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch notification count'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 6: DOWNLOAD CONSENT FORM
    // ==============================================
    fastify.get('/consent/download', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            // TODO: Fetch consent form PDF from storage/blockchain
            return reply.send({
                success: false,
                error: 'Consent form download not implemented yet'
            });

        } catch (error) {
            console.error('[ClientWorkflow] Error downloading consent:', error.message);
            return reply.code(500).send({
                success: false,
                error: 'Failed to download consent form'
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
        const { pin } = request.user;

        try {
            // Check if Documents Library access is enabled via API
            const apiResponse = await fetch(API_URL + '/api/clients/documentsLibrary/access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
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
            console.error('[ClientWorkflow] Error fetching documents:', error.message);
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
        const { pin } = request.user;

        try {
            // Check if report is available via API
            const apiResponse = await fetch(API_URL + '/api/clients/report/access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
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
            console.error('[ClientWorkflow] Error fetching report:', error.message);
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
        const { pin } = request.user;

        try {
            const apiResponse = await fetch(API_URL + '/api/clients/profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin })
            });

            const apiData = await apiResponse.json();
            return reply.code(apiResponse.status).send(apiData);

        } catch (error) {
            console.error('[ClientWorkflow] Error fetching client profile:', error.message);
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

    console.log('[ClientWorkflow] Routes registered (SSOT compliant)');
}
