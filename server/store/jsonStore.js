'use strict';
/**
 * JSON Flat-File Store
 * Thread-safe synchronous read/write for small JSON arrays.
 * Used as lightweight persistence (no database).
 */

const fs = require('fs');
const path = require('path');

const STORAGE_DIR = path.join(__dirname, '..', '..', 'storage');

function filePath(name) {
  return path.join(STORAGE_DIR, `${name}.json`);
}

function readAll(name) {
  try {
    const raw = fs.readFileSync(filePath(name), 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAll(name, data) {
  if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });
  fs.writeFileSync(filePath(name), JSON.stringify(data, null, 2), 'utf8');
}

function findById(name, id) {
  return readAll(name).find(item => item.id === id) || null;
}

function findOne(name, predicate) {
  return readAll(name).find(predicate) || null;
}

function findMany(name, predicate) {
  return readAll(name).filter(predicate);
}

function insert(name, record) {
  const all = readAll(name);
  all.push(record);
  writeAll(name, all);
  return record;
}

function updateById(name, id, updates) {
  const all = readAll(name);
  const idx = all.findIndex(item => item.id === id);
  if (idx === -1) return null;
  all[idx] = { ...all[idx], ...updates };
  writeAll(name, all);
  return all[idx];
}

function removeById(name, id) {
  const all = readAll(name).filter(item => item.id !== id);
  writeAll(name, all);
}

module.exports = { readAll, writeAll, findById, findOne, findMany, insert, updateById, removeById };
