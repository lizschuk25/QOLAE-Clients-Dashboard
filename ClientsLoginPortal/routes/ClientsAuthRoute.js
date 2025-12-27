// ==============================================
// CLIENTS LOGIN PORTAL - AUTHENTICATION ROUTES
// ==============================================
// Purpose: 2FA authentication for clients (PIN + Email verification)
// Author: Liz
// Date: 27th December 2025
// Architecture: SSOT - Calls api.qolae.com for DB operations
// BLOCKCHAIN COMPLIANT: Server-side form POST, no client-side fetch()
// ==============================================

// ==============================================
// LOCATION BLOCK A: CONFIGURATION
// ==============================================
const API_URL = process.env.API_URL || 'https://api.qolae.com';

// ==============================================
// LOCATION BLOCK B: ROUTES EXPORT
// ==============================================
export default async function clientsAuthRoute(fastify, options) {

    // ==============================================
    // LOCATION BLOCK 0: BACKWARDS COMPATIBILITY REDIRECT
    // ==============================================
    fastify.get('/login', async (request, reply) => {
        const pin = request.query.pin || '';
        return reply.redirect('/clients-login?pin=' + encodeURIComponent(pin));
    });

    // ==============================================
    // LOCATION BLOCK 1: LOGIN PAGE (STEP 1 - PIN & EMAIL)
    // ==============================================
    fastify.get('/clients-login', async (request, reply) => {
        // Check if already authenticated
        try {
            await request.jwtVerify();
            // Already logged in, redirect to dashboard
            return reply.redirect(process.env.DASHBOARD_URL || 'https://clients.qolae.com/clients-dashboard');
        } catch (err) {
            // Not logged in, show login page
        }

        return reply.view('clients-login.ejs', {
            pin: request.query.pin || '',
            error: request.query.error || null,
            message: request.query.message || null
        });
    });

    // ==============================================
    // LOCATION BLOCK 2: SERVER-SIDE LOGIN (FORM POST)
    // BLOCKCHAIN COMPLIANT: No fetch(), server-side redirect
    // SSOT COMPLIANT: Calls API for DB operations
    // ==============================================
    fastify.post('/clients-auth/login', async (request, reply) => {
        const { pin, email } = request.body;
        const clientIP = request.ip;

        // Validate input
        if (!pin || !email) {
            return reply.redirect('/clients-login?pin=' + encodeURIComponent(pin || '') + '&error=' + encodeURIComponent('Client PIN and email are required'));
        }

        try {
            // Call SSOT API for login
            const apiResponse = await fetch(API_URL + '/api/clientPortal/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin, email, ipAddress: clientIP })
            });

            const apiData = await apiResponse.json();

            if (!apiData.success) {
                return reply.redirect('/clients-login?pin=' + encodeURIComponent(pin) + '&error=' + encodeURIComponent(apiData.error || 'Login failed'));
            }

            // Send verification code via email service
            try {
                const emailResponse = await fetch(API_URL + '/api/email/send-client-verification', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: email,
                        code: apiData.verificationCode,
                        clientName: apiData.clientName
                    })
                });

                const emailResult = await emailResponse.json();

                if (!emailResult.success) {
                    console.error('[ClientsAuth] Failed to send verification email:', emailResult.error);
                    return reply.redirect('/clients-login?pin=' + encodeURIComponent(pin) + '&error=' + encodeURIComponent('Failed to send verification email. Please try again.'));
                }

            } catch (emailError) {
                console.error('[ClientsAuth] Email service error:', emailError.message);
                return reply.redirect('/clients-login?pin=' + encodeURIComponent(pin) + '&error=' + encodeURIComponent('Email service unavailable. Please try again later.'));
            }

            // SERVER-SIDE REDIRECT to 2FA page
            const clientFirstName = apiData.clientName.split(' ')[0];
            return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin) + '&email=' + encodeURIComponent(email) + '&name=' + encodeURIComponent(clientFirstName) + '&codeSent=true');

        } catch (error) {
            console.error('[ClientsAuth] Error in login:', error.message);
            return reply.redirect('/clients-login?pin=' + encodeURIComponent(pin || '') + '&error=' + encodeURIComponent('An error occurred. Please try again.'));
        }
    });

    // ==============================================
    // LOCATION BLOCK 3: 2FA PAGE (STEP 2 - VERIFICATION CODE)
    // ==============================================
    fastify.get('/clients-2fa', async (request, reply) => {
        const { pin, email, name, codeSent, error } = request.query;

        if (!pin || !email) {
            return reply.redirect('/clients-login?error=Please start from the login page');
        }

        return reply.view('clients-2fa.ejs', {
            pin: pin,
            email: email,
            clientName: name || 'Client',
            codeSent: codeSent === 'true',
            error: error || null
        });
    });

    // ==============================================
    // LOCATION BLOCK 4: SERVER-SIDE VERIFY CODE (FORM POST)
    // BLOCKCHAIN COMPLIANT: No fetch(), server-side redirect
    // SSOT COMPLIANT: Calls API for DB operations
    // ==============================================
    fastify.post('/clients-auth/verify-code', async (request, reply) => {
        const { pin, email, verificationCode } = request.body;
        const clientIP = request.ip;

        // Validate input
        if (!pin || !email || !verificationCode) {
            return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin || '') + '&email=' + encodeURIComponent(email || '') + '&error=' + encodeURIComponent('Verification code is required'));
        }

        try {
            // Call SSOT API for verification
            const apiResponse = await fetch(API_URL + '/api/clientPortal/verifyCode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin, email, verificationCode, ipAddress: clientIP })
            });

            const apiData = await apiResponse.json();

            if (!apiData.success) {
                // Get client name for redirect
                const clientFirstName = apiData.client?.name?.split(' ')[0] || 'Client';
                return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin) + '&email=' + encodeURIComponent(email) + '&name=' + encodeURIComponent(clientFirstName) + '&error=' + encodeURIComponent(apiData.error || 'Verification failed'));
            }

            // Generate JWT token
            const token = fastify.jwt.sign({
                pin: apiData.client.pin,
                name: apiData.client.name,
                email: apiData.client.email,
                role: 'client'
            });

            // Set secure cookie
            reply.setCookie('qolaeClientToken', token, {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 5 * 60 * 60, // 5 hours
                domain: process.env.COOKIE_DOMAIN || '.qolae.com'
            });

            // SERVER-SIDE REDIRECT to dashboard
            const dashboardUrl = process.env.DASHBOARD_URL || 'https://clients.qolae.com/clients-dashboard';
            return reply.redirect(dashboardUrl);

        } catch (error) {
            console.error('[ClientsAuth] Error verifying code:', error.message);
            return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin || '') + '&email=' + encodeURIComponent(email || '') + '&error=' + encodeURIComponent('An error occurred. Please try again.'));
        }
    });

    // ==============================================
    // LOCATION BLOCK 5: SERVER-SIDE RESEND CODE (FORM POST)
    // BLOCKCHAIN COMPLIANT: No fetch(), server-side redirect
    // SSOT COMPLIANT: Calls API for DB operations
    // ==============================================
    fastify.post('/clients-auth/resend-code', async (request, reply) => {
        const { pin, email } = request.body;
        const clientIP = request.ip;

        if (!pin || !email) {
            return reply.redirect('/clients-login?error=Session expired. Please start again.');
        }

        try {
            // Call SSOT API for resend
            const apiResponse = await fetch(API_URL + '/api/clientPortal/resendCode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pin, email, ipAddress: clientIP })
            });

            const apiData = await apiResponse.json();

            if (!apiData.success) {
                return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin) + '&email=' + encodeURIComponent(email) + '&error=' + encodeURIComponent(apiData.error || 'Failed to resend code'));
            }

            // Send verification code via email service
            try {
                const emailResponse = await fetch(API_URL + '/api/email/send-client-verification', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: email,
                        code: apiData.verificationCode,
                        clientName: apiData.clientName
                    })
                });

                const emailResult = await emailResponse.json();

                if (!emailResult.success) {
                    const clientFirstName = apiData.clientName.split(' ')[0];
                    return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin) + '&email=' + encodeURIComponent(email) + '&name=' + encodeURIComponent(clientFirstName) + '&error=' + encodeURIComponent('Failed to send new code. Please try again.'));
                }

            } catch (emailError) {
                console.error('[ClientsAuth] Email service error:', emailError.message);
                const clientFirstName = apiData.clientName.split(' ')[0];
                return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin) + '&email=' + encodeURIComponent(email) + '&name=' + encodeURIComponent(clientFirstName) + '&error=' + encodeURIComponent('Email service unavailable.'));
            }

            // SERVER-SIDE REDIRECT back to 2FA with success message
            const clientFirstName = apiData.clientName.split(' ')[0];
            return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin) + '&email=' + encodeURIComponent(email) + '&name=' + encodeURIComponent(clientFirstName) + '&codeSent=true');

        } catch (error) {
            console.error('[ClientsAuth] Error resending code:', error.message);
            return reply.redirect('/clients-2fa?pin=' + encodeURIComponent(pin || '') + '&email=' + encodeURIComponent(email || '') + '&error=' + encodeURIComponent('An error occurred. Please try again.'));
        }
    });

    // ==============================================
    // LOCATION BLOCK 6: LOGOUT (GET - Link based)
    // BLOCKCHAIN COMPLIANT: Server-side redirect
    // SSOT COMPLIANT: Calls API for audit logging
    // ==============================================
    fastify.get('/clients-auth/logout', async (request, reply) => {
        const clientIP = request.ip;

        try {
            // Try to get user info for logging
            let pin = 'unknown';
            try {
                await request.jwtVerify();
                pin = request.user.pin;
            } catch (e) {
                // Not authenticated, still clear cookie
            }

            // Log logout via API
            if (pin !== 'unknown') {
                try {
                    await fetch(API_URL + '/api/clientPortal/logout', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pin, ipAddress: clientIP })
                    });
                } catch (logError) {
                    console.error('[ClientsAuth] Error logging logout:', logError.message);
                }
            }

            // Clear cookie
            reply.clearCookie('qolaeClientToken', {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                domain: process.env.COOKIE_DOMAIN || '.qolae.com'
            });

            return reply.redirect('/clients-login?message=You have been logged out successfully.');

        } catch (error) {
            console.error('[ClientsAuth] Error logging out:', error.message);
            return reply.redirect('/clients-login');
        }
    });

    // Note: Health check route is defined in Clients_server.js to avoid duplication

    console.log('[ClientsAuth] Routes registered (SSOT compliant)');
}
