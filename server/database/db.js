'use strict';
const mysql = require('mysql2/promise');
const config = require('../config/config');

let pool = null;

function getPool() {
  if (!pool) {
    pool = mysql.createPool(config.db);
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
