const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const {
    hasDatabaseConnection,
    initializeDatabase,
    createUser,
    findUserByUsername,
    findUserByEmail,
    deleteExpiredResetTokens,
    replaceResetToken,
    findResetToken,
    clearUserResetTokens,
    updateUserPassword,
} = require('./db');

const app = express();
const publicDir = path.join(__dirname, 'public');

app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.static(publicDir));

const PORT = Number(process.env.PORT || 3000);
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
let transporterPromise;

function normalizeEmail(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hasMailConfig() {
    return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function getBaseUrl(req) {
    if (process.env.APP_BASE_URL) {
        return process.env.APP_BASE_URL.replace(/\/$/, '');
    }

    const forwardedProto = req.get('x-forwarded-proto');
    const forwardedHost = req.get('x-forwarded-host');
    const protocol = forwardedProto || req.protocol;
    const host = forwardedHost || req.get('host');

    return `${protocol}://${host}`;
}

function getTransporter() {
    if (!hasMailConfig()) {
        return null;
    }

    if (!transporterPromise) {
        transporterPromise = Promise.resolve(
            nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: Number(process.env.SMTP_PORT || 587),
                secure: String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS,
                },
            })
        );
    }

    return transporterPromise;
}

async function sendResetEmail({ to, username, resetLink }) {
    const transporter = getTransporter();

    if (!transporter) {
        throw new Error('SMTP is not configured on the server');
    }

    const resolvedTransporter = await transporter;
    const from = process.env.SMTP_FROM || process.env.SMTP_USER;

    await resolvedTransporter.sendMail({
        from,
        to,
        subject: 'Password reset request',
        text: `Hello ${username},\n\nWe received a password reset request for your account. Use this link within 15 minutes:\n${resetLink}\n\nIf you did not request this, you can ignore this email.`,
        html: `
            <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6;">
                <h2>Password reset request</h2>
                <p>Hello ${username},</p>
                <p>We received a password reset request for your account.</p>
                <p>
                    <a href="${resetLink}" style="display: inline-block; padding: 12px 18px; background: #0ea5e9; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold;">Reset password</a>
                </p>
                <p>Or open this link within 15 minutes:</p>
                <p>${resetLink}</p>
                <p>If you did not request this, you can ignore this email.</p>
            </div>
        `,
    });
}

function buildResetRecord(user, baseUrl) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + RESET_TOKEN_TTL_MS;

    return {
        token,
        expiresAt,
        resetLink: `${baseUrl}/reset-password.html?token=${token}&username=${encodeURIComponent(user.username)}`,
    };
}

function sendPage(res, fileName) {
    res.sendFile(path.join(publicDir, fileName));
}

async function requireDatabase(req, res, next) {
    if (!hasDatabaseConnection()) {
        return res.status(503).json({
            error: 'Database is not configured. Add DATABASE_URL or POSTGRES_URL in Vercel before using signup, login, or password reset.',
        });
    }

    try {
        await initializeDatabase();
        next();
    } catch (error) {
        console.error('Database initialization error:', error);
        res.status(500).json({ error: 'Could not connect to the database. Check your Postgres environment variables.' });
    }
}

app.get('/', (req, res) => {
    sendPage(res, 'index.html');
});

app.get('/login-page.html', (req, res) => {
    sendPage(res, 'login-page.html');
});

app.get('/forgot-password.html', (req, res) => {
    sendPage(res, 'forgot-password.html');
});

app.get('/reset-password.html', (req, res) => {
    sendPage(res, 'reset-password.html');
});

app.get('/health', async (req, res) => {
    if (!hasDatabaseConnection()) {
        return res.status(200).json({ status: 'ok', database: 'missing' });
    }

    try {
        await initializeDatabase();
        res.status(200).json({ status: 'ok', database: 'connected' });
    } catch (error) {
        console.error('Health check database error:', error);
        res.status(500).json({ status: 'error', database: 'failed' });
    }
});

app.post('/signup', requireDatabase, async (req, res) => {
    const username = req.body.username?.trim();
    const password = req.body.password;
    const email = normalizeEmail(req.body.email);

    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Enter a valid email address for recovery' });
    }

    try {
        const existingUser = await findUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        const existingEmail = await findUserByEmail(email);
        if (existingEmail) {
            return res.status(409).json({ error: 'Email address is already in use' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await createUser({ username, email, passwordHash });

        res.status(201).json({
            message: 'User created successfully!',
            userId: user.id,
            email: user.email,
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Server error during signup' });
    }
});

app.post('/login', requireDatabase, async (req, res) => {
    const username = req.body.username?.trim();
    const password = req.body.password;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const user = await findUserByUsername(username);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        res.status(200).json({
            message: 'Login successful!',
            userId: user.id,
            username: user.username,
            email: normalizeEmail(user.email),
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/password-reset/request', requireDatabase, async (req, res) => {
    const username = req.body.username?.trim();
    const email = normalizeEmail(req.body.email);

    if (!hasMailConfig()) {
        return res.status(503).json({ error: 'Password reset email is not configured on the server yet. Add SMTP credentials first.' });
    }

    if (!username || !email) {
        return res.status(400).json({ error: 'Username and recovery email are required' });
    }

    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Enter the same valid recovery email used at signup' });
    }

    try {
        await deleteExpiredResetTokens();
        const user = await findUserByUsername(username);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const storedEmail = normalizeEmail(user.email);
        if (storedEmail !== email) {
            return res.status(400).json({ error: 'The recovery email does not match this username' });
        }

        const resetRecord = buildResetRecord(user, getBaseUrl(req));
        await replaceResetToken({
            token: resetRecord.token,
            userId: user.id,
            expiresAt: resetRecord.expiresAt,
        });

        await sendResetEmail({
            to: storedEmail,
            username: user.username,
            resetLink: resetRecord.resetLink,
        });

        res.status(200).json({
            message: `A reset link was sent to ${storedEmail}. It expires in 15 minutes.`,
            delivery: 'email',
        });
    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({ error: 'Could not send the reset email. Check your SMTP or database configuration.' });
    }
});

app.post('/password-reset/confirm', requireDatabase, async (req, res) => {
    const username = req.body.username?.trim();
    const token = req.body.token?.trim();
    const newPassword = req.body.newPassword;

    if (!username || !token || !newPassword) {
        return res.status(400).json({ error: 'Username, token, and new password are required' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }

    try {
        await deleteExpiredResetTokens();
        const resetRecord = await findResetToken(token);

        if (!resetRecord || new Date(resetRecord.expires_at).getTime() <= Date.now()) {
            return res.status(400).json({ error: 'This reset link is invalid or has expired' });
        }

        const user = await findUserByUsername(username);
        if (!user || Number(user.id) !== Number(resetRecord.user_id)) {
            return res.status(404).json({ error: 'User not found for this reset request' });
        }

        const passwordHash = await bcrypt.hash(newPassword, 10);
        await updateUserPassword(user.id, passwordHash);
        await clearUserResetTokens(user.id);

        res.status(200).json({ message: 'Password reset successful. You can now log in with your new password.' });
    } catch (error) {
        console.error('Password reset confirm error:', error);
        res.status(500).json({ error: 'Server error during password reset confirmation' });
    }
});

module.exports = app;

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
        console.log('Auth data now uses Postgres via DATABASE_URL or POSTGRES_URL.');
    });
}