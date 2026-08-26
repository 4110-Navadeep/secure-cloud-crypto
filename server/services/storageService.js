'use strict';
/**
 * Amazon S3 Storage Service
 * Handles upload, download, and deletion of encrypted objects.
 * Only encrypted .enc files are stored in S3 — never plaintext.
 */

const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const config = require('../config/config');

let s3Client = null;

function getS3Client() {
  if (!s3Client) {
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
 * Upload an encrypted buffer to S3.
 * @param {string} objectKey  - S3 object key (e.g. 'secure-files/uuid.enc')
 * @param {Buffer} encryptedBuffer
 * @param {string} contentType - should be 'application/octet-stream'
 * @returns {Promise<{ key: string, size: number }>}
 */
async function uploadEncryptedFile(objectKey, encryptedBuffer, contentType = 'application/octet-stream') {
  const client = getS3Client();
  const command = new PutObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
    Body: encryptedBuffer,
    ContentType: contentType,
    ServerSideEncryption: 'AES256', // additional S3-side encryption
    Metadata: {
      'x-content-type': 'encrypted',
    },
  });
  await client.send(command);
  return { key: objectKey, size: encryptedBuffer.length };
}

/**
 * Download an encrypted object from S3 into a Buffer.
 * @param {string} objectKey
 * @returns {Promise<Buffer>}
 */
async function downloadEncryptedFile(objectKey) {
  const client = getS3Client();
  const command = new GetObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
  });
  const response = await client.send(command);

  // Stream to Buffer
  return new Promise((resolve, reject) => {
    const chunks = [];
    response.Body.on('data', chunk => chunks.push(chunk));
    response.Body.on('end', () => resolve(Buffer.concat(chunks)));
    response.Body.on('error', reject);
  });
}

/**
 * Delete an object from S3.
 * @param {string} objectKey
 */
async function deleteEncryptedFile(objectKey) {
  const client = getS3Client();
  const command = new DeleteObjectCommand({
    Bucket: config.s3.bucket,
    Key: objectKey,
  });
  await client.send(command);
}

/**
 * Check if an object exists in S3.
 * @param {string} objectKey
 * @returns {Promise<boolean>}
 */
async function objectExists(objectKey) {
  try {
    const client = getS3Client();
    await client.send(new HeadObjectCommand({ Bucket: config.s3.bucket, Key: objectKey }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a presigned URL for secure temporary access (e.g. for streaming preview).
 * @param {string} objectKey
 * @param {number} expiresInSeconds
 * @returns {Promise<string>}
 */
async function getPresignedDownloadUrl(objectKey, expiresInSeconds = 300) {
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
