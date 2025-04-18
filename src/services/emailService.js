import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

export const sendEmail = async (to, subject, text) => {
  try {
    await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, text });
    console.log(`✅ Email sent to ${to}`);
  } catch (error) {
    console.error(`❌ Email sending failed: ${error.message}`);
    throw new Error("Failed to send email");
  }
};

