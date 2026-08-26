'use strict';
/**
 * Email Service — sends member invitation emails.
 * Uses nodemailer. Falls back to console logging if not configured (development).
 */

const nodemailer = require('nodemailer');
const config = require('../config/config');

let transporter = null;

function getTransporter() {
  if (!transporter) {
    if (!config.email.host || !config.email.user) {
      // Development fallback — log to console
      transporter = nodemailer.createTransport({ jsonTransport: true });
    } else {
      transporter = nodemailer.createTransport({
        host: config.email.host,
        port: config.email.port,
        secure: config.email.port === 465,
        auth: {
          user: config.email.user,
          pass: config.email.password,
        },
      });
    }
  }
  return transporter;
}

/**
 * Send a member invitation email.
 * @param {object} params
 * @param {string} params.to       - recipient email
 * @param {string} params.name     - recipient name
 * @param {string} params.token    - invitation token
 * @param {string} params.invitedBy - name of admin who sent the invite
 */
async function sendInvitationEmail({ to, name, token, invitedBy }) {
  const inviteUrl = `${config.app.url}/register.html?token=${token}`;

  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: 'Inter', Arial, sans-serif; background: #0a0f1e; color: #e2e8f0; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; background: #0d1528; border: 1px solid #1e3a5f; border-radius: 12px; overflow: hidden; }
    .header { background: linear-gradient(135deg, #0a1628 0%, #0d2137 100%); padding: 40px; text-align: center; border-bottom: 1px solid #1e3a5f; }
    .logo { font-size: 24px; font-weight: 700; color: #00d4ff; letter-spacing: 2px; }
    .badge { display: inline-block; background: rgba(0,212,255,0.1); color: #00d4ff; border: 1px solid rgba(0,212,255,0.3); border-radius: 20px; padding: 4px 12px; font-size: 12px; margin-top: 8px; }
    .body { padding: 40px; }
    h2 { color: #ffffff; font-size: 22px; margin: 0 0 16px; }
    p { color: #94a3b8; line-height: 1.6; margin: 0 0 16px; }
    .highlight { color: #00d4ff; font-weight: 600; }
    .btn { display: inline-block; background: linear-gradient(135deg, #00d4ff, #0066cc); color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 16px; margin: 24px 0; }
    .security-note { background: rgba(0,212,255,0.05); border: 1px solid rgba(0,212,255,0.15); border-radius: 8px; padding: 16px; margin-top: 24px; }
    .footer { padding: 24px 40px; border-top: 1px solid #1e3a5f; text-align: center; color: #475569; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">🔐 SECURE CLOUD</div>
      <div class="badge">SECURE FILE SHARING</div>
    </div>
    <div class="body">
      <h2>You're Invited, ${name}!</h2>
      <p>
        <span class="highlight">${invitedBy}</span> has invited you to join the
        <strong>Secure Cloud File Sharing System</strong> — a hybrid cryptography-powered
        platform for secure file exchange.
      </p>
      <p>Click the button below to create your account. This invitation is valid for <strong>48 hours</strong>.</p>
      <div style="text-align:center;">
        <a href="${inviteUrl}" class="btn">Accept Invitation & Create Account</a>
      </div>
      <div class="security-note">
        <p style="margin:0; font-size:13px;">
          🔒 <strong>Security Note:</strong> This link is unique to you. Do not share it.
          We will never ask for your password via email.
          If you did not expect this invitation, you can safely ignore this email.
        </p>
      </div>
    </div>
    <div class="footer">
      Secure Cloud File Sharing System &bull; Cryptography &amp; Network Security
    </div>
  </div>
</body>
</html>`;

  const mailOptions = {
    from: config.email.from,
    to,
    subject: `You've been invited to Secure Cloud — ${invitedBy}`,
    html,
    text: `You've been invited to Secure Cloud by ${invitedBy}.\n\nCreate your account: ${inviteUrl}\n\nThis link expires in 48 hours.`,
  };

  const info = await getTransporter().sendMail(mailOptions);

  if (!config.email.host || !config.email.user) {
    // Development: log the invite URL
    console.log(`[EMAIL DEV] Invitation to ${to}: ${inviteUrl}`);
    console.log('[EMAIL DEV] Full message:', JSON.parse(info.message));
  }
  return info;
}

module.exports = { sendInvitationEmail };
