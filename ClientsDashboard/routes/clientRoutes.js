// ==============================================
// CLIENTS DASHBOARD - CLIENT ROUTES
// ==============================================
// Purpose: Dashboard, consent signing, documents, appointments, reports
// Author: Liz
// Date: 26th December 2025
// Database: qolae_lawyers (consentForms table)
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// ==============================================
import pg from 'pg';

const { Pool } = pg;

// ==============================================
// LOCATION BLOCK B: DATABASE CONNECTION
// ==============================================
const lawyersDb = new Pool({
    connectionString: process.env.LAWYERS_DATABASE_URL
});

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
        const loginUrl = process.env.LOGIN_URL || '/clients-login';
        return reply.redirect(`${loginUrl}?error=Session expired. Please login again.`);
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
            redirectTo: '/clients-login'
        });
    }
}

// ==============================================
// LOCATION BLOCK D: ROUTES EXPORT
// ==============================================
export default async function clientRoutes(fastify, options) {

    // ==============================================
    // LOCATION BLOCK 1: CLIENTS DASHBOARD - MAIN VIEW
    // ==============================================
    fastify.get('/clients-dashboard', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { pin, name, email } = request.user;

        try {
            // Get client data from consentForms
            const clientResult = await lawyersDb.query(
                `SELECT "clientPin", "clientName", "clientEmail", "clientPhone",
                        "consentSigned", "consentSignedAt",
                        "inaAppointmentScheduled", "inaAppointmentDate",
                        "documentAccessEnabled", "finalReportAvailable", "finalReportDate",
                        "workflowStatus", "createdAt", "lastLogin"
                 FROM "consentForms"
                 WHERE "clientPin" = $1`,
                [pin]
            );

            if (clientResult.rows.length === 0) {
                return reply.code(404).send({ success: false, error: 'Client not found' });
            }

            const client = clientResult.rows[0];

            // Get notifications (last 10)
            const notificationsResult = await lawyersDb.query(
                `SELECT id, title, message, type, read, "createdAt"
                 FROM "clientNotifications"
                 WHERE "clientPin" = $1
                 ORDER BY "createdAt" DESC
                 LIMIT 10`,
                [pin]
            );

            const notifications = notificationsResult.rows;
            const unreadCount = notifications.filter(n => !n.read).length;

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
                    label: 'Document Access',
                    status: client.documentAccessEnabled ? 'active' : 'pending',
                    statusLabel: client.documentAccessEnabled ? 'Now Available' : 'Requires Consent'
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
                documentAccess: {
                    enabled: client.documentAccessEnabled,
                    status: client.documentAccessEnabled ? 'active' : 'pending',
                    statusLabel: client.documentAccessEnabled ? 'Now Available' : 'Requires Consent'
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

            return reply.view('clients-dashboard.ejs', {
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
            fastify.log.error('Error loading clients dashboard:', error);
            return reply.code(500).send({ success: false, error: 'Failed to load dashboard' });
        }
    });

    // ==============================================
    // LOCATION BLOCK 2: SIGN CONSENT FORM (DIGITAL SIGNATURE)
    // ==============================================
    fastify.post('/api/consent/sign', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { pin } = request.user;

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

            // Save signature and update client
            await lawyersDb.query(
                `UPDATE "consentForms"
                 SET "consentSigned" = TRUE,
                     "consentSignedAt" = NOW(),
                     "consentSignatureData" = $1,
                     "documentAccessEnabled" = TRUE,
                     "workflowStatus" = 'consentCompleted'
                 WHERE "clientPin" = $2`,
                [signatureBuffer, pin]
            );

            // Log activity
            await lawyersDb.query(
                `INSERT INTO "clientActivityLog" ("clientPin", "activityType", "activityDescription", "ipAddress", "createdAt")
                 VALUES ($1, $2, $3, $4, NOW())`,
                [pin, 'consentSigned', 'Client signed consent form digitally', request.ip]
            );

            // Add notification
            await lawyersDb.query(
                `INSERT INTO "clientNotifications" ("clientPin", "title", "message", "type", "createdAt")
                 VALUES ($1, $2, $3, $4, NOW())`,
                [pin, 'Consent Form Signed', 'Your consent form has been signed successfully. You can now schedule your INA appointment and access documents.', 'success']
            );

            // TODO: Trigger blockchain hash generation for consent form
            // TODO: Send notification to Case Manager via WebSocket

            return reply.send({
                success: true,
                message: 'Consent form signed successfully'
            });

        } catch (error) {
            fastify.log.error('Error signing consent:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to sign consent form'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 3: GET NOTIFICATIONS
    // ==============================================
    fastify.get('/api/notifications', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            const result = await lawyersDb.query(
                `SELECT id, title, message, type, read, "createdAt"
                 FROM "clientNotifications"
                 WHERE "clientPin" = $1
                 ORDER BY "createdAt" DESC
                 LIMIT 20`,
                [pin]
            );

            const unreadCount = result.rows.filter(n => !n.read).length;

            return reply.send({
                success: true,
                notifications: result.rows.map(n => ({
                    ...n,
                    timeAgo: getTimeAgo(n.createdAt)
                })),
                unreadCount
            });

        } catch (error) {
            fastify.log.error('Error fetching notifications:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch notifications'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 4: MARK NOTIFICATION AS READ
    // ==============================================
    fastify.post('/api/notifications/:id/read', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { id } = request.params;
        const { pin } = request.user;

        try {
            await lawyersDb.query(
                `UPDATE "clientNotifications"
                 SET read = TRUE, "readAt" = NOW()
                 WHERE id = $1 AND "clientPin" = $2`,
                [id, pin]
            );

            return reply.send({ success: true });

        } catch (error) {
            fastify.log.error('Error marking notification as read:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to mark notification as read'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 5: GET UNREAD NOTIFICATION COUNT
    // ==============================================
    fastify.get('/api/notifications/count', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            const result = await lawyersDb.query(
                `SELECT COUNT(*) as count
                 FROM "clientNotifications"
                 WHERE "clientPin" = $1 AND read = FALSE`,
                [pin]
            );

            return reply.send({
                success: true,
                unreadCount: parseInt(result.rows[0].count)
            });

        } catch (error) {
            fastify.log.error('Error fetching notification count:', error);
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
            // For now, return placeholder
            return reply.send({
                success: false,
                error: 'Consent form download not implemented yet'
            });

        } catch (error) {
            fastify.log.error('Error downloading consent:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to download consent form'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 7: VIEW DOCUMENTS
    // ==============================================
    fastify.get('/documents', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            // Check if document access is enabled
            const clientResult = await lawyersDb.query(
                `SELECT "documentAccessEnabled" FROM "consentForms" WHERE "clientPin" = $1`,
                [pin]
            );

            if (!clientResult.rows[0]?.documentAccessEnabled) {
                return reply.code(403).send({
                    success: false,
                    error: 'Document access requires signed consent form'
                });
            }

            // TODO: Fetch documents from secure storage
            return reply.send({
                success: false,
                error: 'Document library not implemented yet'
            });

        } catch (error) {
            fastify.log.error('Error fetching documents:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch documents'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 8: VIEW FINAL REPORT
    // ==============================================
    fastify.get('/report/view', {
        preHandler: authenticateClient
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            // Check if report is available
            const clientResult = await lawyersDb.query(
                `SELECT "finalReportAvailable" FROM "consentForms" WHERE "clientPin" = $1`,
                [pin]
            );

            if (!clientResult.rows[0]?.finalReportAvailable) {
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
            fastify.log.error('Error fetching report:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch report'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 9: CLIENT PROFILE / BOOTSTRAP DATA
    // ==============================================
    fastify.get('/api/client/profile', {
        preHandler: authenticateClientAPI
    }, async (request, reply) => {
        const { pin } = request.user;

        try {
            const result = await lawyersDb.query(
                `SELECT "clientPin", "clientName", "clientEmail", "clientPhone",
                        "consentSigned", "consentSignedAt",
                        "inaAppointmentScheduled", "inaAppointmentDate",
                        "documentAccessEnabled", "finalReportAvailable",
                        "workflowStatus", "createdAt"
                 FROM "consentForms"
                 WHERE "clientPin" = $1`,
                [pin]
            );

            if (result.rows.length === 0) {
                return reply.code(404).send({
                    success: false,
                    error: 'Client not found'
                });
            }

            return reply.send({
                success: true,
                client: result.rows[0]
            });

        } catch (error) {
            fastify.log.error('Error fetching client profile:', error);
            return reply.code(500).send({
                success: false,
                error: 'Failed to fetch client profile'
            });
        }
    });

    // ==============================================
    // LOCATION BLOCK 10: LOGOUT (CLEARS COOKIE & REDIRECTS)
    // ==============================================
    fastify.get('/logout', async (request, reply) => {
        reply.clearCookie('qolaeClientToken', {
            path: '/',
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: process.env.COOKIE_DOMAIN || '.qolae.com'
        });

        const loginUrl = process.env.LOGIN_URL || '/clients-login';
        return reply.redirect(`${loginUrl}?message=You have been logged out successfully.`);
    });
}

// ==============================================
// LOCATION BLOCK 11: HELPER FUNCTIONS
// ==============================================
function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);

    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)} days ago`;

    return new Date(date).toLocaleDateString('en-GB');
}