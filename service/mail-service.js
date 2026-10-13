const nodemailer = require('nodemailer');
const config = require('../config');

class MailService {
    async sendActivationMail(to, link) {
        if (!process.env.SMTP_HOST || !process.env.SMTP_FROM) throw new Error('SMTP is not configured');
        const secure = process.env.SMTP_SECURE === 'true';
        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT || (secure ? 465 : 587)),
            secure,
            requireTLS: config.production && !secure,
            connectionTimeout: 5000,
            socketTimeout: 10000,
            disableFileAccess: true,
            disableUrlAccess: true,
            ...(process.env.SMTP_USER ? {
                auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
            } : {}),
        });
        await transporter.sendMail({
            from: process.env.SMTP_FROM, to,
            subject: 'Confirm your email',
            text: 'Confirm your email within 24 hours: ' + link,
        });
    }
}

module.exports = new MailService();
