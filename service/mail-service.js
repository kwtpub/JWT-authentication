const nodemailer = require('nodemailer');


class MailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST, 
            port: process.env.SMTP_PORT,
            secure: false,
            connectionTimeout: 5000, // 5 секунд
            socketTimeout: 10000, // 10 секунд
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASSWORD
            }
        })
    }
    async sendActivationMail(to, link) {
        console.log(to, link);
}
}

module.exports = new MailService(); 