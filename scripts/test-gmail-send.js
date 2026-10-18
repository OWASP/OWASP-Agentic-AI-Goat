/**
 * Test script to send one email via Gmail SMTP (Email Agent workshop).
 * Run from project root: node scripts/test-gmail-send.js [recipient@sharklasers.com]
 *
 * Requires .env with GMAIL_USER and GMAIL_APP_PASSWORD set.
 * 
 * Setup:
 * 1. Enable 2FA on your Gmail account
 * 2. Generate App Password at https://myaccount.google.com/apppasswords
 * 3. Set GMAIL_USER and GMAIL_APP_PASSWORD in .env
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const gmailService = require('../server/services/gmailEmailAgentService');

const TEST_RECIPIENT = process.argv[2] || 'w84g2q+p0qtrk59dh0@sharklasers.com';
const TEST_SUBJECT = 'Test from Email Agent Workshop';
const TEST_BODY = `This is a test email sent via Gmail SMTP.

If you received this, the Email Agent workshop is properly configured.

Sent at: ${new Date().toISOString()}`;

async function main() {
  console.log('Gmail SMTP send test');
  console.log('====================');
  console.log('Recipient:', TEST_RECIPIENT);
  console.log('GMAIL_USER:', process.env.GMAIL_USER || '(not set)');
  console.log('GMAIL_APP_PASSWORD:', process.env.GMAIL_APP_PASSWORD ? '****' + process.env.GMAIL_APP_PASSWORD.slice(-4) : '(not set)');
  console.log('');

  const ok = await gmailService.initialize();
  if (!ok) {
    console.error('Gmail SMTP service failed to initialize:');
    console.error('  Error:', gmailService.initError);
    console.error('');
    console.error('Troubleshooting:');
    console.error('  1. Ensure GMAIL_USER is set to your Gmail address');
    console.error('  2. Ensure GMAIL_APP_PASSWORD is a 16-character App Password');
    console.error('  3. App Passwords require 2FA enabled on your Google account');
    console.error('  4. Generate at: https://myaccount.google.com/apppasswords');
    process.exit(1);
  }
  console.log('Gmail SMTP service initialized successfully.\n');

  try {
    const result = await gmailService.sendEmail(TEST_RECIPIENT, TEST_SUBJECT, TEST_BODY, 'test-script');
    console.log('Email sent successfully!');
    console.log('  Message ID:', result.messageId);
    console.log('  Sent from:', result.sentFrom);
    console.log('  Sent to:', result.sentTo);
    console.log('  Subject:', result.subject);
    process.exit(0);
  } catch (err) {
    console.error('Send failed:');
    console.error('  Error:', err.message);
    if (err.code) {
      console.error('  Code:', err.code);
    }
    if (err.statusCode) {
      console.error('  Status:', err.statusCode);
    }
    process.exit(1);
  }
}

main();
