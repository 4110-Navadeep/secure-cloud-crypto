'use strict';
/**
 * Amazon S3 Storage Service with Local File Fallback
 * Handles upload, download, and deletion of encrypted objects.
 * Only encrypted .enc files are stored — never plaintext.
 */

const fs = require('fs');
const path = require('path');
const config = require('../config/config');

const LOCAL_STORAGE_DIR = path.join(__dirname, '..', '..', 'storage', 'cloud_sim');

// Ensure local fallback directory exists
function initLocalDir() {
  if (!fs.existsSync(LOCAL_STORAGE_DIR)) {
    fs.mkdirSync(LOCAL_STORAGE_DIR, { recursive: true });
  }
}

// Check if we should fall back to local disk storage
const isS3Configured = !!(config.s3.accessKeyId && config.s3.bucket);

let s3Client = null;

function getS3Client() {
  if (!isS3Configured) return null;
  if (!s3Client) {
    const { S3Client } = require('@aws-sdk/client-s3');
    s3Client = new S3Client({
      region: config.s3.region,
      credentials: {
        accessKeyId: config.s3.accessKeyId,
        secretAccessKey: config.s3.secretAccessKey,
      },
    });
  }
  return s3Client;
}

/**
 * Upload an encrypted buffer.
 * @param {string} objectKey  - storage object key (e.g. 'secure-files/uuid.enc')
 * @param {Buffer} encryptedBuffer
 * @param {string} contentType - should be 'application/octet-stream'
 * @returns {Promise<{ key: string, size: number }>}
 */
async function uploadEncryptedFile(objectKey, encryptedBuffer, contentType = 'application/octet-stream') {
  if (!isS3Configured) {
    initLocalDir();
    const filePath = path.join(LOCAL_STORAGE_DIR, path.basename(objectKey));
    fs.writeFileSync(filePath, encryptedBuffer);
    return { key: objectKey, size: encryptedBuffer.length };
  }

  const { PutObjectCommand } = require('@aws-sdk/client-s3');
  const client = getS3Client();
  const command = new PutObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
    Body: encryptedBuffer,
    ContentType: contentType,
    ServerSideEncryption: 'AES256',
    Metadata: {
      'x-content-type': 'encrypted',
    },
  });
  await client.send(command);
  return { key: objectKey, size: encryptedBuffer.length };
}

/**
 * Download an encrypted object into a Buffer.
 * @param {string} objectKey
 * @returns {Promise<Buffer>}
 */
async function downloadEncryptedFile(objectKey) {
  if (!isS3Configured) {
    const filePath = path.join(LOCAL_STORAGE_DIR, path.basename(objectKey));
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found in local storage fallback: ${filePath}`);
    }
    return fs.readFileSync(filePath);
  }

  const { GetObjectCommand } = require('@aws-sdk/client-s3');
  const client = getS3Client();
  const command = new GetObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
  });
  const response = await client.send(command);

  return new Promise((resolve, reject) => {
    const chunks = [];
    response.Body.on('data', chunk => chunks.push(chunk));
    response.Body.on('end', () => resolve(Buffer.concat(chunks)));
    response.Body.on('error', reject);
  });
}

/**
 * Delete an object.
 * @param {string} objectKey
 */
async function deleteEncryptedFile(objectKey) {
  if (!isS3Configured) {
    const filePath = path.join(LOCAL_STORAGE_DIR, path.basename(objectKey));
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    return;
  }

  const { DeleteObjectCommand } = require('@aws-sdk/client-s3');
  const client = getS3Client();
  const command = new DeleteObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
  });
  await client.send(command);
}

/**
 * Check if an object exists.
 * @param {string} objectKey
 * @returns {Promise<boolean>}
 */
async function objectExists(objectKey) {
  if (!isS3Configured) {
    const filePath = path.join(LOCAL_STORAGE_DIR, path.basename(objectKey));
    return fs.existsSync(filePath);
  }

  try {
    const { HeadObjectCommand } = require('@aws-sdk/client-s3');
    const client = getS3Client();
    await client.send(new HeadObjectCommand({ Bucket: config.s3.bucket, Key: objectKey }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a presigned URL or mock local download URL.
 * @param {string} objectKey
 * @param {number} expiresInSeconds
 * @returns {Promise<string>}
 */
async function getPresignedDownloadUrl(objectKey, expiresInSeconds = 300) {
  if (!isS3Configured) {
    // Return a local URL path
    return `/api/files/download-fallback/${path.basename(objectKey)}`;
  }

  const { GetObjectCommand } = require('@aws-sdk/client-s3');
  const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
  const client = getS3Client();
  const command = new GetObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
  });
  return getSignedUrl(client, command, { expiresIn: expiresInSeconds });
}

module.exports = {
  uploadEncryptedFile,
  downloadEncryptedFile,
  deleteEncryptedFile,
  objectExists,
  getPresignedDownloadUrl,
};
