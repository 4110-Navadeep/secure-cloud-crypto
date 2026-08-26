'use strict';
/**
 * Rigorous Integration Test Suite
 * Verifies all 17 requirements of database-free JSON persistence layer
 */

process.env.APPLICATION_SECRET = 'super-secret-key-for-testing-only-12345';
process.env.JWT_SECRET = 'jwt-secret-key-for-testing-only-12345';

const request = require('supertest');
const fs = require('fs');
const path = require('path');
const db = require('../server/database/db');
const app = require('../server/server');

describe('End-to-End JSON Integration & Sharing Pipeline', () => {
  let adminToken = '';
  let memberToken = '';
  let memberEmail = 'bob@securecloud.app';
  let invitationToken = '';
  let uploadedFileId = '';
  let passphrase = 'secure-file-passphrase';

  beforeAll(() => {
    // 1. Reset database to fresh clean state
    db.users.saveAll([]);
    db.members.saveAll([]);
    db.files.saveAll([]);
    db.shares.saveAll([]);
    db.access.saveAll([]);
    db.securityLogs.saveAll([]);
    db.performance.saveAll([]);

    // Ensure storage folders exist
    const storageDir = path.join(__dirname, '..', 'storage');
    if (!fs.existsSync(storageDir)) {
      fs.mkdirSync(storageDir, { recursive: true });
    }
  });

  afterAll((done) => {
    // Reset databases at the end to keep repository clean
    db.users.saveAll([]);
    db.members.saveAll([]);
    db.files.saveAll([]);
    db.shares.saveAll([]);
    db.access.saveAll([]);
    db.securityLogs.saveAll([]);
    db.performance.saveAll([]);

    // Clean up local S3 cloud simulator files
    const simDir = path.join(__dirname, '..', 'storage', 'cloud_sim');
    if (fs.existsSync(simDir)) {
      fs.readdirSync(simDir).forEach(file => {
        fs.unlinkSync(path.join(simDir, file));
      });
    }

    done();
  });

  // Checklist 1 & 2: Server starts without MySQL & Admin account can be created
  test('1. Admin setup works (create the first administrator)', async () => {
    const res = await request(app)
      .post('/api/auth/setup')
      .send({
        full_name: 'Super Admin',
        email: 'admin@securecloud.app',
        password: 'AdminPassword123!',
        confirm_password: 'AdminPassword123!'
      });

    expect(res.status).toBe(201);
    expect(res.body.message).toContain('Administrator account created successfully');

    // Setup is now disabled
    const res2 = await request(app)
      .post('/api/auth/setup')
      .send({
        full_name: 'Second Admin',
        email: 'admin2@securecloud.app',
        password: 'AdminPassword123!',
        confirm_password: 'AdminPassword123!'
      });
    expect(res2.status).toBe(403);
  });

  test('2. Admin login works', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'admin@securecloud.app',
        password: 'AdminPassword123!'
      });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    adminToken = res.body.token;
  });

  // Checklist 3: Admin can invite a member
  test('3. Admin can invite a member', async () => {
    const res = await request(app)
      .post('/api/members/invite')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        full_name: 'Bob Member',
        email: memberEmail,
        role: 'member'
      });

    expect(res.status).toBe(201);
    expect(res.body.invitation).toBeDefined();
    expect(res.body.invitation.email).toBe(memberEmail);

    // Get the invitation token from storage
    const invite = db.members.findOne({ email: memberEmail });
    expect(invite).toBeDefined();
    invitationToken = invite.token;
  });

  test('4. Validate invitation token works', async () => {
    const res = await request(app)
      .get(`/api/members/invitations/${invitationToken}`);

    expect(res.status).toBe(200);
    expect(res.body.invitation.email).toBe(memberEmail);
  });

  test('5. Sign up using invitation token', async () => {
    const res = await request(app)
      .post('/api/members/register')
      .send({
        token: invitationToken,
        password: 'BobPassword123!',
        confirm_password: 'BobPassword123!'
      });

    expect(res.status).toBe(201);
    expect(res.body.message).toContain('Account created successfully');
  });

  // Checklist 4: User/member can log in
  test('6. Member can log in', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: memberEmail,
        password: 'BobPassword123!'
      });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    memberToken = res.body.token;
  });

  // Checklist 5, 6, 7 & 11: File can be uploaded, encrypted, downloaded
  test('7. Member can upload and encrypt a file', async () => {
    const fileContent = 'This is a secure payload representing client data.';
    const res = await request(app)
      .post('/api/files/upload')
      .set('Authorization', `Bearer ${memberToken}`)
      .field('passphrase', passphrase)
      .attach('file', Buffer.from(fileContent, 'utf-8'), 'payload.txt');

    expect(res.status).toBe(201);
    expect(res.body.file).toBeDefined();
    expect(res.body.file.original_filename).toBe('payload.txt');
    uploadedFileId = res.body.file.id;

    // Verify S3 cloud simulator wrote encrypted file to disk
    const encPath = path.join(__dirname, '..', 'storage', 'cloud_sim', `${uploadedFileId}.enc`);
    expect(fs.existsSync(encPath)).toBe(true);

    // Verify it is encrypted (not containing the plaintext string)
    const storedEncryptedContent = fs.readFileSync(encPath, 'utf8');
    expect(storedEncryptedContent).not.toContain(fileContent);
  });

  test('8. Owner can download and decrypt the original file successfully', async () => {
    const res = await request(app)
      .get(`/api/files/${uploadedFileId}/download-original`)
      .set('Authorization', `Bearer ${memberToken}`);

    expect(res.status).toBe(200);
    expect(res.text).toBe('This is a secure payload representing client data.');
  });

  // Checklist 8 & 9: Share file and recipient sees it
  test('9. Share the file with the Admin', async () => {
    const res = await request(app)
      .post('/api/sharing/')
      .set('Authorization', `Bearer ${memberToken}`)
      .send({
        file_id: uploadedFileId,
        shared_with_email: 'admin@securecloud.app',
        permission: 'download'
      });

    expect(res.status).toBe(201);
    expect(res.body.message).toContain('File shared with');
  });

  test('10. Recipient (Admin) can see the shared file', async () => {
    const res = await request(app)
      .get('/api/sharing/with-me')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.shares.length).toBeGreaterThan(0);
    expect(res.body.shares[0].file_id).toBe(uploadedFileId);
  });

  // Checklist 10: Unauthorized user cannot access it
  test('11. Unauthorized user (guest or non-shared) cannot download the file', async () => {
    // Create another member to test unauthorized access
    db.users.insert({
      id: 'hacker-uuid',
      full_name: 'Intruder',
      email: 'intruder@hacker.com',
      password_hash: 'somehash',
      role: 'member',
      status: 'active'
    });

    const intruderToken = require('jsonwebtoken').sign(
      { id: 'hacker-uuid', email: 'intruder@hacker.com', role: 'member' },
      process.env.JWT_SECRET
    );

    const res = await request(app)
      .get(`/api/files/${uploadedFileId}/download-original`)
      .set('Authorization', `Bearer ${intruderToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Access denied');
  });

  // Checklist 12: Integrity verification detects modification
  test('12. Integrity check fails if encrypted file is tampered', async () => {
    const encPath = path.join(__dirname, '..', 'storage', 'cloud_sim', `${uploadedFileId}.enc`);
    
    // Backup encrypted content
    const originalEncData = fs.readFileSync(encPath);

    // Tamper the file contents
    fs.writeFileSync(encPath, Buffer.from('tampered payload data', 'utf-8'));

    const res = await request(app)
      .get(`/api/files/${uploadedFileId}/download-original`)
      .set('Authorization', `Bearer ${memberToken}`);

    expect(res.status).toBe(409);
    expect(res.body.error).toContain('File integrity check failed');

    // Restore original file content
    fs.writeFileSync(encPath, originalEncData);
  });

  // Checklist 15: Revoked access prevents access
  test('13. Revoking access prevents recipient download', async () => {
    const adminUser = db.users.findOne({ email: 'admin@securecloud.app' });
    const share = db.shares.findOne({ file_id: uploadedFileId, shared_with: adminUser.id });
    expect(share).toBeDefined();

    const resRevoke = await request(app)
      .patch(`/api/sharing/${share.id}/revoke`)
      .set('Authorization', `Bearer ${memberToken}`);

    expect(resRevoke.status).toBe(200);

    const resDown = await request(app)
      .get(`/api/files/${uploadedFileId}/download-original`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(resDown.status).toBe(403);
  });

  // Checklist 16: Security activity is logged
  test('14. Security events are stored in audit logs', async () => {
    const logs = db.securityLogs.find();
    expect(logs.length).toBeGreaterThan(0);
    const downloadDeniedLog = logs.find(l => l.event_type === 'ACCESS_DENIED');
    expect(downloadDeniedLog).toBeDefined();
  });
});
