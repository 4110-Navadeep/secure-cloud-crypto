'use strict';
require('dotenv').config();

module.exports = {
  db: {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : undefined,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    charset: 'utf8mb4',
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: '24h',
  },
  app: {
    secret: process.env.APPLICATION_SECRET,
    port: parseInt(process.env.PORT) || 5000,
    url: process.env.APP_URL || 'http://localhost:5000',
    nodeEnv: process.env.NODE_ENV || 'development',
  },
  s3: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'us-east-1',
    bucket: process.env.AWS_S3_BUCKET,
  },
  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT) || 587,
    user: process.env.EMAIL_USER,
    password: process.env.EMAIL_PASSWORD,
    from: process.env.EMAIL_FROM || 'Secure Cloud <noreply@securecloud.app>',
  },
  upload: {
    maxFileSizeMB: 100,
    allowedMimeTypes: [
      'application/pdf',
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'text/plain',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/zip',
      'video/mp4',
      'audio/mpeg',
    ],
  },
};
