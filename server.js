const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const publicDir = path.join(__dirname, 'public');

app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.static(publicDir));

const PORT = Number(process.env.PORT || 3000);
const DB_FILE = path.join(__dirname, 'users.json');
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;
const resetTokens = new Map();
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

function pruneResetTokens() {
    const now = Date.now();

    for (const [token, data] of resetTokens.entries()) {
        if (data.expiresAt <= now) {
            resetTokens.delete(token);
        }
    }
}

function clearUserResetTokens(userId) {
    for (const [token, data] of resetTokens.entries()) {
        if (data.userId === userId) {
            resetTokens.delete(token);
        }
    }
}

function createResetRecord(user, baseUrl) {
    clearUserResetTokens(user.id);
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + RESET_TOKEN_TTL_MS;

    resetTokens.set(token, {
        token,
        userId: user.id,
        username: user.username,
        expiresAt,
    });

    return {
        token,
        expiresAt,
        resetLink: `${baseUrl}/reset-password.html?token=${token}&username=${encodeURIComponent(user.username)}`,
    };
}

async function readDatabase() {
    try {
        const data = await fs.readFile(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        if (err.code === 'ENOENT') {
            return [];
        }

        throw err;
    }
}

async function writeDatabase(data) {
    await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2));
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

function sendPage(res, fileName) {
    res.sendFile(path.join(publicDir, fileName));
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

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

app.post('/signup', async (req, res) => {
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
        const users = await readDatabase();

        if (users.find((u) => u.username === username)) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        if (users.find((u) => normalizeEmail(u.email) === email)) {
            return res.status(409).json({ error: 'Email address is already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Date.now(),
            username,
            email,
            password: hashedPassword,
        };

        users.push(newUser);
        await writeDatabase(users);

        res.status(201).json({
            message: 'User created successfully!',
            userId: newUser.id,
            email: newUser.email,
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({
            error: 'Server error during signup. If you deploy to Vercel, replace users.json with a real database because file writes are not persistent there.',
        });
    }
});

app.post('/login', async (req, res) => {
    const username = req.body.username?.trim();
    const password = req.body.password;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const users = await readDatabase();
        const user = users.find((u) => u.username === username);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const match = await bcrypt.compare(password, user.password);

        if (match) {
            res.status(200).json({
                message: 'Login successful!',
                userId: user.id,
                username: user.username,
                email: normalizeEmail(user.email) || null,
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/password-reset/request', async (req, res) => {
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
        pruneResetTokens();
        const users = await readDatabase();
        const user = users.find((u) => u.username === username);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const storedEmail = normalizeEmail(user.email);

        if (!storedEmail) {
            return res.status(400).json({ error: 'This account does not have a recovery email yet' });
        }

        if (storedEmail !== email) {
            return res.status(400).json({ error: 'The recovery email does not match this username' });
        }

        const resetRecord = createResetRecord(user, getBaseUrl(req));
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
        res.status(500).json({ error: 'Could not send the reset email. Check your SMTP configuration.' });
    }
});

app.post('/password-reset/confirm', async (req, res) => {
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
        pruneResetTokens();
        const resetRecord = resetTokens.get(token);

        if (!resetRecord || resetRecord.username !== username || resetRecord.expiresAt <= Date.now()) {
            return res.status(400).json({ error: 'This reset link is invalid or has expired' });
        }

        const users = await readDatabase();
        const userIndex = users.findIndex((u) => u.id === resetRecord.userId && u.username === username);

        if (userIndex === -1) {
            resetTokens.delete(token);
            return res.status(404).json({ error: 'User not found for this reset request' });
        }

        users[userIndex].password = await bcrypt.hash(newPassword, 10);
        await writeDatabase(users);
        clearUserResetTokens(resetRecord.userId);

        res.status(200).json({ message: 'Password reset successful. You can now log in with your new password.' });
    } catch (error) {
        console.error('Password reset confirm error:', error);
        res.status(500).json({
            error: 'Server error during password reset confirmation. On Vercel, password changes will not persist with users.json; use a real database.',
        });
    }
});

module.exports = app;

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
        console.log('Player data is stored in users.json for local development.');
        console.log('For Vercel deployment, use a real database because users.json is not persistent there.');
    });
}