import 'dotenv/config';
// ==============================================
// QOLAE CLIENTS DASHBOARD SERVER
// ==============================================
// Purpose: Secure workspace for clients - consent, documents, reports
// Author: Liz
// Date: 27th December 2025
// Port: 3010
// PM2 Process: qolae-clients
// Architecture: SSOT - Calls api.qolae.com for data
// Database: qolae_clients (via API-Dashboard SSOT)
// ==============================================

// ==============================================
// LOCATION BLOCK A: IMPORTS & CONFIGURATION
// ==============================================
import Fastify from 'fastify';
import path from 'path';
import { fileURLToPath } from 'url';
import fastifyStatic from '@fastify/static';
import fastifyView from '@fastify/view';
import ejs from 'ejs';
import fastifyFormbody from '@fastify/formbody';
import fastifyCors from '@fastify/cors';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import fastifyMultipart from '@fastify/multipart';
import ssotFetch from './utils/ssotFetch.js';
import sessionMiddleware from './middleware/sessionMiddleware.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==============================================
// LOCATION BLOCK B: FASTIFY SERVER INITIALIZATION
// ==============================================
const server = Fastify({
    logger: {
        level: 'info',
        transport: {
            target: 'pino-pretty',
            options: {
                translateTime: 'HH:MM:ss Z',
                ignore: 'pid,hostname',
            },
        },
    },
});

// ==============================================
// LOCATION BLOCK C: MIDDLEWARE REGISTRATION
// ==============================================

// 1. CORS Configuration
await server.register(fastifyCors, {
    origin: process.env.CORS_ORIGIN || 'https://clients.qolae.com',
    credentials: true,
});

// 2. Cookie Support (MUST be before JWT to parse cookies first)
await server.register(fastifyCookie);

// 3. JWT Authentication (must match LoginPortal secret)
await server.register(fastifyJwt, {
    secret: process.env.CLIENTS_LOGIN_JWT_SECRET,
    sign: { algorithm: 'HS256' },
    verify: { algorithms: ['HS256'] },
    cookie: {
        cookieName: 'qolaeClientToken',
        signed: false,
    },
});

// 4. Form Body Parser
await server.register(fastifyFormbody);

// 5. Multipart (for signature uploads)
await server.register(fastifyMultipart, {
    limits: {
        fileSize: 500 * 1024 * 1024, // 500MB max
    },
});

// 6. Static Files
await server.register(fastifyStatic, {
    root: path.join(__dirname, 'public'),
    prefix: '/public/',
});

// 7. View Engine (EJS)
await server.register(fastifyView, {
    engine: {
        ejs: ejs,
    },
    root: path.join(__dirname, 'views'),
    options: {
        filename: path.join(__dirname, 'views'),
    },
});

// SSOT-compliant session validation (replaces inline jwtVerify preHandler + authenticateClient decorator)
server.addHook('preHandler', sessionMiddleware);

// ==============================================
// LOCATION BLOCK D: CONSTANTS & CONFIGURATION
// ==============================================
// SSOT_BASE_URL now centralised in utils/ssotFetch.js

// ==============================================
// LOCATION BLOCK F: BOOTSTRAP HELPER FUNCTION
// ==============================================
/**
 * Builds client bootstrap data from SSOT API
 * @param {string} clientPin - Client PIN identifier
 * @returns {Promise<Object|null>} Bootstrap data or null if error
 */
async function buildClientBootstrapData(clientPin) {
    try {
        server.log.info({ event: 'buildingBootstrap', clientPin });

        // Get stored JWT token from SSOT
        const tokenResponse = await ssotFetch(`/auth/clients/getStoredToken?clientPin=${clientPin}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!tokenResponse.ok) {
            server.log.warn({ event: 'noValidJwt', clientPin });
            return null;
        }

        const tokenData = await tokenResponse.json();
        const { accessToken } = tokenData;

        // Call SSOT bootstrap endpoint with stored JWT token
        const bootstrapResponse = await ssotFetch(`/clients/workspace/bootstrap`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (bootstrapResponse.ok) {
            const bootstrapData = await bootstrapResponse.json();
            server.log.info({ event: 'bootstrapSuccess', clientPin });
            return bootstrapData;
        } else {
            server.log.error({ event: 'bootstrapFailed', status: bootstrapResponse.status });
            return null;
        }

    } catch (error) {
        server.log.error({ event: 'bootstrapError', clientPin, error: error.message });
        return null;
    }
}

// ==============================================
// LOCATION BLOCK G: MAIN DASHBOARD ROUTE
// ==============================================
/**
 * Main Clients Dashboard Route
 * Uses SSOT Bootstrap as SINGLE SOURCE OF TRUTH
 * No duplicate database queries - all data comes from SSOT
 */
server.get('/clientsDashboard', async (req, reply) => {
    reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    reply.header('Pragma', 'no-cache');
    reply.header('Expires', '0');

    const { clientPin, showPreview, redoSignature, showModal } = req.query;

    if (!clientPin) {
        return reply.code(400).send({ error: 'Client PIN required' });
    }

    // Check for preview data in cache (server-side preview flow)
    let previewData = null;
    let redoSignatureData = null;

    // Import previewCache dynamically since it's registered after this route
    const { previewCache } = await import('./routes/clientWorkflowRoutes.js');

    if (showPreview === 'true') {
        if (previewCache.has(clientPin)) {
            previewData = previewCache.get(clientPin);
            server.log.info({ event: 'previewMode', clientPin });
        }
    }

    // Check for redo signature flow - preserve consent checkboxes
    if (redoSignature === 'true') {
        if (previewCache.has(clientPin)) {
            redoSignatureData = previewCache.get(clientPin);
            server.log.info({ event: 'redoSignatureMode', clientPin });
        }
    }

    try {
        server.log.info({ event: 'dashboardRoute', clientPin });

        // SINGLE SOURCE OF TRUTH - SSOT Bootstrap only
        const bootstrapData = await buildClientBootstrapData(clientPin);

        if (!bootstrapData || !bootstrapData.valid) {
            server.log.error({ event: 'invalidBootstrap', clientPin });
            return reply.code(401).send({ error: 'Invalid session - please login again' });
        }

        server.log.info({ event: 'dashboardLoading', clientName: bootstrapData.user.clientName, clientPin });

        // ==========================================
        // SERVER-SIDE DATA TRANSFORMATION
        // Transform bootstrap data into template-ready structures
        // ==========================================

        // 1. CLIENT object (template expects firstName, name)
        const clientNameParts = (bootstrapData.user.clientName || 'Client User').split(' ');
        const client = {
            clientPin: bootstrapData.user.clientPin,
            firstName: clientNameParts[0],
            name: bootstrapData.user.clientName,
            clientName: bootstrapData.user.clientName,
            clientEmail: bootstrapData.user.clientEmail,
            assignedLawyerPin: bootstrapData.user.assignedLawyerPin
        };

        // 2. SESSION object
        const session = {
            lastLogin: bootstrapData.user.lastLogin || 'Never',
            isFirstLogin: bootstrapData.user.lastLogin === 'First login'
        };

        // 3. WORKFLOW steps (SERVER builds array based on progress)
        // Steps match the 4 workflow cards: Consent Form, INA Appointment, Documents Library, Final Report
        const workflow = {
            steps: [
                {
                    label: 'Consent Form',
                    status: bootstrapData.progress.consentSigned ? 'completed' : 'active',
                    statusLabel: bootstrapData.progress.consentSigned ? 'Completed' : 'In Progress'
                },
                {
                    label: 'INA Appointment',
                    status: bootstrapData.progress.consentSigned ? 'active' : 'pending',
                    statusLabel: bootstrapData.progress.consentSigned ? 'Ready' : 'Pending'
                },
                {
                    label: 'Documents Library',
                    status: bootstrapData.features.viewDocuments ? 'active' : 'pending',
                    statusLabel: bootstrapData.features.viewDocuments ? 'Available' : 'Locked'
                },
                {
                    label: 'Final Report',
                    status: 'pending',
                    statusLabel: 'Pending'
                }
            ]
        };

        // 4. CARDS (SERVER determines enabled/disabled states)
        const cards = {
            consentForm: {
                signed: bootstrapData.progress.consentSigned || false,
                status: bootstrapData.progress.consentSigned ? 'completed' : 'active',
                statusLabel: bootstrapData.progress.consentSigned ? 'Signed' : 'Action Required'
            },
            inaAppointment: {
                scheduled: false, // TODO: Add appointment tracking
                canSchedule: bootstrapData.progress.consentSigned || false,
                status: bootstrapData.progress.consentSigned ? 'active' : 'pending',
                statusLabel: bootstrapData.progress.consentSigned ? 'Ready to Schedule' : 'Awaiting Consent'
            },
            documentsLibrary: {
                enabled: bootstrapData.features.viewDocuments || false,
                status: bootstrapData.features.viewDocuments ? 'active' : 'pending',
                statusLabel: bootstrapData.features.viewDocuments ? 'Available' : 'Locked'
            },
            finalReport: {
                available: false, // TODO: Add report tracking
                status: 'pending',
                statusLabel: 'Pending Assessment'
            }
        };

        // 5. PROGRESS PERCENTAGE (SERVER calculates)
        let completedSteps = 0;
        const totalSteps = workflow.steps.length;
        workflow.steps.forEach(step => {
            if (step.status === 'completed') completedSteps++;
        });
        const progressPercentage = Math.round((completedSteps / totalSteps) * 100);

        // 6. CSRF TOKEN (SERVER generates)
        const csrfToken = server.jwt.sign({
            csrf: true,
            clientPin: clientPin,
            timestamp: new Date().toISOString()
        });

        // 7. NOTIFICATIONS (from SSOT bootstrap)
        const notifications = bootstrapData.notifications || {
            unreadCount: 0,
            items: []
        };

        // ==========================================
        // RENDER TEMPLATE WITH SERVER-COMPUTED DATA
        // ==========================================
        return reply.view('clientsDashboard.ejs', {
            title: 'QOLAE Clients Dashboard',
            client,
            session,
            workflow,
            cards,
            progressPercentage,
            csrfToken,
            notifications,
            progress: bootstrapData.progress,
            features: bootstrapData.features,
            caseInfo: bootstrapData.caseInfo,
            bootstrapData: JSON.stringify(bootstrapData),
            // Preview mode data (server-side)
            showPreview: previewData !== null,
            previewPdfBase64: previewData?.pdfBase64 || null,
            // Redo signature mode (preserve checkboxes, auto-open modal)
            redoSignature: redoSignatureData !== null,
            cachedConsentData: redoSignatureData?.consentData || null,
            // Server-side modal control (replaces JavaScript open/close)
            showModal: showModal || null,
            degradedMode: req.degradedMode || false
        });

    } catch (error) {
        server.log.error({ event: 'dashboardLoadError', error: error.message });
        return reply.code(500).send({ error: 'Failed to load dashboard' });
    }
});

// ==============================================
// LOCATION BLOCK H: ROUTES REGISTRATION
// ==============================================

// Client Workflow Routes (SSOT compliant - calls API for data)
const clientWorkflowModule = await import('./routes/clientWorkflowRoutes.js');
await server.register(clientWorkflowModule.default);

// Access preview cache for server-side preview flow
const { previewCache } = clientWorkflowModule;

// ==============================================
// LOCATION BLOCK I: ROOT ROUTE
// ==============================================
server.get('/', async (request, reply) => {
    // Check if authenticated
    try {
        await request.jwtVerify();
        return reply.redirect('/clientsDashboard');
    } catch (error) {
        // Not authenticated, redirect to LoginPortal
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(loginUrl);
    }
});

// ==============================================
// LOCATION BLOCK I2: INA APPOINTMENTS PAGE
// ==============================================
/**
 * GET /inaAppointments
 * Server-side INA appointment scheduling page
 * All state managed via query parameters (no client-side JS state)
 */
server.get('/inaAppointments', async (req, reply) => {
    try {
        await req.jwtVerify();
        const { clientPin, clientName } = req.user;

        // Query params for server-side state (month as YYYY-MM format)
        const { month, selectedSlotId } = req.query;

        server.log.info({ event: 'inaAppointmentsAccess', clientPin });

        // Use buildClientBootstrapData helper (handles JWT token retrieval from SSOT)
        const bootstrapData = await buildClientBootstrapData(clientPin);
        if (!bootstrapData) {
            throw new Error('Failed to fetch client data from SSOT');
        }

        // Build client object for template
        const fullName = bootstrapData.client?.fullName || clientName || 'Client';
        const client = {
            clientPin: clientPin,
            fullName: fullName,
            initials: fullName.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2),
            referenceNumber: clientPin,
            address: bootstrapData.client?.address || bootstrapData.consent?.clientAddress || null
        };

        // Case manager info (from SSOT or defaults)
        const caseManager = {
            name: bootstrapData.caseManager?.name || 'Liz'
        };

        // Check if appointment already confirmed
        const existingAppointment = bootstrapData.appointments?.ina || null;
        const appointmentStatus = existingAppointment?.confirmed ? 'confirmed' : 'selecting';

        // Calendar generation (server-side) - YYYY-MM format
        const currentDate = new Date();
        const defaultMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;
        const targetMonthStr = month || defaultMonth;
        const [targetYear, targetMonth] = targetMonthStr.split('-').map(Number);

        // Calculate prev/next as YYYY-MM strings
        const prevDate = new Date(targetYear, targetMonth - 2, 1);
        const nextDate = new Date(targetYear, targetMonth, 1);
        const prevMonth = `${prevDate.getFullYear()}-${String(prevDate.getMonth() + 1).padStart(2, '0')}`;
        const nextMonth = `${nextDate.getFullYear()}-${String(nextDate.getMonth() + 1).padStart(2, '0')}`;

        const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                           'July', 'August', 'September', 'October', 'November', 'December'];

        // Build calendar days array (targetMonth is 1-indexed from YYYY-MM)
        const jsMonth = targetMonth - 1; // Convert to JS 0-indexed
        const firstDay = new Date(targetYear, jsMonth, 1);
        const lastDay = new Date(targetYear, jsMonth + 1, 0);
        const startPadding = (firstDay.getDay() + 6) % 7; // Monday = 0

        const calendarDays = [];

        // Previous month padding
        const prevMonthLastDay = new Date(targetYear, jsMonth, 0).getDate();
        for (let i = startPadding - 1; i >= 0; i--) {
            calendarDays.push({
                dayNumber: prevMonthLastDay - i,
                isOtherMonth: true,
                isToday: false,
                slots: []
            });
        }

        // Current month days with available slots
        const availableSlots = bootstrapData.availableSlots || [];
        for (let day = 1; day <= lastDay.getDate(); day++) {
            const dateStr = `${targetYear}-${String(targetMonth).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
            const daySlots = availableSlots.filter(s => s.date === dateStr);
            const isToday = (day === currentDate.getDate() && jsMonth === currentDate.getMonth() && targetYear === currentDate.getFullYear());

            calendarDays.push({
                dayNumber: day,
                isOtherMonth: false,
                isToday: isToday,
                slots: daySlots.map(s => ({
                    slotId: s.slotId,
                    time: s.time
                }))
            });
        }

        // Next month padding to complete grid
        const remainingCells = 42 - calendarDays.length;
        for (let i = 1; i <= remainingCells; i++) {
            calendarDays.push({
                dayNumber: i,
                isOtherMonth: true,
                isToday: false,
                slots: []
            });
        }

        // Selected slot data (if any)
        let selectedSlotData = null;
        if (selectedSlotId) {
            const slot = availableSlots.find(s => s.slotId === selectedSlotId);
            if (slot) {
                selectedSlotData = {
                    displayDate: slot.displayDate || slot.date,
                    time: slot.time
                };
            }
        }

        // Confirmed appointment data
        const appointment = existingAppointment ? {
            displayDate: existingAppointment.displayDate,
            displayTime: existingAppointment.displayTime,
            location: existingAppointment.location
        } : null;

        // Generate CSRF token using JWT (same pattern as /clientsDashboard)
        const csrfToken = server.jwt.sign({
            csrf: true,
            clientPin: clientPin,
            timestamp: new Date().toISOString()
        });

        return reply.view('inaAppointments', {
            client: client,
            caseManager: caseManager,
            csrfToken: csrfToken,
            appointmentStatus: appointmentStatus,
            calendarDays: calendarDays,
            calendarMonth: monthNames[jsMonth],
            calendarYear: targetYear,
            currentMonth: targetMonthStr,
            prevMonth: prevMonth,
            nextMonth: nextMonth,
            selectedSlotId: selectedSlotId || null,
            selectedSlotData: selectedSlotData,
            appointment: appointment
        });

    } catch (error) {
        server.log.error({ event: 'inaAppointmentsError', error: error.message });
        return reply.redirect('/clientsDashboard?error=Session expired');
    }
});

// ==============================================
// LOCATION BLOCK I2.1: INA APPOINTMENT CONFIRMATION
// ==============================================
/**
 * POST /inaAppointments/confirm
 * Server-side appointment confirmation
 * Submits to SSOT API then redirects back to confirmed state
 */
server.post('/inaAppointments/confirm', async (req, reply) => {
    try {
        await req.jwtVerify();
        const { clientPin, slotId } = req.body;

        server.log.info({ event: 'appointmentConfirmation', clientPin });

        // Submit confirmation to SSOT
        const response = await ssotFetch(`/clients/workspace/appointments/confirm`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientPin: clientPin,
                slotId: slotId,
                appointmentType: 'ina'
            })
        });

        if (!response.ok) {
            server.log.error({ event: 'appointmentConfirmationFailed' });
            return reply.redirect('/inaAppointments?error=Confirmation failed');
        }

        server.log.info({ event: 'appointmentConfirmed', clientPin });

        // Redirect back to show confirmed state
        return reply.redirect('/inaAppointments');

    } catch (error) {
        server.log.error({ event: 'appointmentConfirmationError', error: error.message });
        return reply.redirect('/clientsDashboard?error=Session expired');
    }
});

// ==============================================
// LOCATION BLOCK I3: DOCUMENTS LIBRARY PAGE
// ==============================================
server.get('/documentsLibrary', async (req, reply) => {
    try {
        await req.jwtVerify();
        const { clientPin, clientName } = req.user;

        server.log.info({ event: 'documentsLibraryAccess', clientPin });

        // Use buildClientBootstrapData helper (handles JWT token retrieval from SSOT)
        const bootstrapData = await buildClientBootstrapData(clientPin);

        if (!bootstrapData) {
            server.log.error({ event: 'documentsLibraryBootstrapFailed' });
            return reply.redirect('/clientsDashboard?error=Failed to load documents');
        }

        const client = bootstrapData.client || { clientName, clientPin };
        const consentSigned = bootstrapData.progress?.consentSigned || false;

        // Generate CSRF token using JWT (same pattern as /clientsDashboard)
        const csrfToken = server.jwt.sign({
            csrf: true,
            clientPin: clientPin,
            timestamp: new Date().toISOString()
        });

        // Render documents library page
        return reply.view('documentsLibrary', {
            client: client,
            csrfToken: csrfToken,
            consentSigned: consentSigned,
            documentsLibraryFiles: bootstrapData.documents || [],
            documentsLibraryFileCount: bootstrapData.documents?.length || 0,
            pendingUploadRequests: bootstrapData.pendingUploadRequests || []
        });

    } catch (error) {
        server.log.error({ event: 'documentsLibraryError', error: error.message });
        return reply.redirect('/clientsDashboard?error=Session expired');
    }
});

// ==============================================
// LOCATION BLOCK I4: FINAL REPORT PAGE
// ==============================================
/**
 * GET /finalReport
 * Server-side final INA report viewing page
 * Report rendered as PNG images (no browser PDF viewer)
 */
server.get('/finalReport', async (req, reply) => {
    try {
        await req.jwtVerify();
        const { clientPin, clientName } = req.user;

        server.log.info({ event: 'finalReportAccess', clientPin });

        // Use buildClientBootstrapData helper (handles JWT token retrieval from SSOT)
        const bootstrapData = await buildClientBootstrapData(clientPin);

        if (!bootstrapData) {
            throw new Error('Failed to fetch client data from SSOT');
        }

        // Build client object for template
        const fullName = bootstrapData.client?.fullName || clientName || 'Client';
        const client = {
            clientPin: clientPin,
            fullName: fullName,
            initials: fullName.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2),
            referenceNumber: clientPin
        };

        // Check if report is available
        const reportData = bootstrapData.finalReport || null;
        const reportAvailable = reportData?.available || false;

        // Report metadata (when available)
        const report = reportAvailable ? {
            completedDate: reportData.completedDate || 'N/A'
        } : null;

        // Report pages as base64 PNG images (when available)
        const reportPages = reportAvailable ? (reportData.pages || []) : [];

        return reply.view('finalReport', {
            client: client,
            reportAvailable: reportAvailable,
            report: report,
            reportPages: reportPages
        });

    } catch (error) {
        server.log.error({ event: 'finalReportError', error: error.message });
        return reply.redirect('/clientsDashboard?error=Session expired');
    }
});

// ==============================================
// LOCATION BLOCK J: HEALTH CHECK
// ==============================================
server.get('/health', async (request, reply) => {
    return {
        status: 'healthy',
        service: 'qolae-clients-dashboard',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'production',
        architecture: 'SSOT via API-Dashboard',
        database: 'qolae_clients (via api.qolae.com)',
    };
});

// ==============================================
// LOCATION BLOCK J2: LOGOUT ROUTE
// ==============================================
/**
 * POST /clientsAuth/logout
 * Server-side logout - clears JWT cookie and redirects to login
 */
server.post('/clientsAuth/logout', async (request, reply) => {
    try {
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
            domain: '.qolae.com'
        });

        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(loginUrl);

    } catch (error) {
        console.error('Logout error:', error.message);
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(loginUrl);
    }
});

// ==============================================
// LOCATION BLOCK K: ERROR HANDLING
// ==============================================
server.setErrorHandler((error, request, reply) => {
    server.log.error(error);

    // Check if it's an auth error
    if (error.statusCode === 401) {
        const loginUrl = process.env.LOGIN_URL || 'https://clients.qolae.com/clientsLogin';
        return reply.redirect(`${loginUrl}?error=Please login to continue.`);
    }

    reply.status(error.statusCode || 500).send({
        success: false,
        error: error.message || 'Internal Server Error',
        timestamp: new Date().toISOString(),
    });
});

// ==============================================
// LOCATION BLOCK L: SERVER START
// ==============================================
const start = async () => {
    try {
        const port = process.env.CLIENTS_DASHBOARD_PORT || 3010;
        const host = process.env.HOST || '0.0.0.0';

        await server.listen({ port, host });

        server.log.info(`ClientsDashboard running at http://${host}:${port}`);

    } catch (err) {
        server.log.error(err);
        process.exit(1);
    }
};

// Start the server
start();

export default server;