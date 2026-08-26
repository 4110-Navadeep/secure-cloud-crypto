'use strict';
const mysql = require('mysql2/promise');

// ---------------------------------------------------------------------------
// Port separation guard
// ---------------------------------------------------------------------------
// DB_PORT is for MySQL only. process.env.PORT is for Express only.
// These must NEVER be mixed. The pool is created once and reused.
// ---------------------------------------------------------------------------

let pool = null;

function getPool() {
  if (!pool) {
    const dbHost = process.env.DB_HOST;
    const dbPort = Number(process.env.DB_PORT || 3306);
    const dbUser = process.env.DB_USER;
    const dbPassword = process.env.DB_PASSWORD;
    const dbName = process.env.DB_NAME;

    // Hard-fail if DB_HOST is missing — never fall back to localhost
    if (!dbHost) {
      console.error('[DATABASE] Missing required environment variable: DB_HOST');
      process.exit(1);
    }
    if (!dbUser) {
      console.error('[DATABASE] Missing required environment variable: DB_USER');
      process.exit(1);
    }
    if (!dbPassword) {
      console.error('[DATABASE] Missing required environment variable: DB_PASSWORD');
      process.exit(1);
    }
    if (!dbName) {
      console.error('[DATABASE] Missing required environment variable: DB_NAME');
      process.exit(1);
    }
    if (isNaN(dbPort) || dbPort < 1 || dbPort > 65535) {
      console.error(`[DATABASE] Invalid DB_PORT "${process.env.DB_PORT}". Expected a numeric MySQL port such as 3306.`);
      process.exit(1);
    }

    pool = mysql.createPool({
      host: dbHost,
      port: dbPort,
      user: dbUser,
      password: dbPassword,
      database: dbName,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      charset: 'utf8mb4',
    });
  }
  return pool;
}

async function query(sql, params) {
  const conn = getPool();
  const [rows] = await conn.execute(sql, params);
  return rows;
}

async function queryOne(sql, params) {
  const rows = await query(sql, params);
  return rows[0] || null;
}

async function testConnection() {
  const conn = await getPool().getConnection();
  conn.release();
  return true;
}

module.exports = { getPool, query, queryOne, testConnection };
