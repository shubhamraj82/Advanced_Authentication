import nodemailer from "nodemailer"

const transporter = nodemailer.createTransport({
    host: "gmail",
    port: 587,
    auth : {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
    }
});

// Verify transporter configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP Configuration Error:', error.message);
    } else {
        console.log('SMTP Server is ready to send emails');
    }
});

export default transporter;