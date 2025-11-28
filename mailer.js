const nodemailer = require("nodemailer");
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config(); 

// Create the Nodemailer Transporter
// It uses your EMAIL_USER and EMAIL_PASS from the .env file
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Function to send a standardized email
const sendEmail = async (to, subject, htmlContent) => {
    try {
        const info = await transporter.sendMail({
            from: `"Your App Name" <${process.env.EMAIL_USER}>`,
            to: to,
            subject: subject,
            html: htmlContent,
        });
        console.log("Message sent: %s", info.messageId);
        return true; // Return success
    } catch (error) {
        console.error("Error sending email:", error);
        return false; // Return failure
    }
};

module.exports = sendEmail;