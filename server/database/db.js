'use strict';
const fs = require('fs');
const path = require('path');

const STORAGE_DIR = path.join(__dirname, '..', '..', 'storage');

// Helper to ensure storage directory and files exist
function initStorage() {
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }

  const defaultFiles = {
    'users.json': '[]',
    'members.json': '[]', // maps to invitations table
    'files.json': '[]',
    'shares.json': '[]', // maps to file_shares table
    'access.json': '[]', // maps to file_keys table
    'security_logs.json': '[]', // maps to audit_logs table
    'performance_metrics.json': '[]',
  };

  for (const [filename, defaultContent] of Object.entries(defaultFiles)) {
    const filePath = path.join(STORAGE_DIR, filename);
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, defaultContent, 'utf8');
    }
  }
}

// Initialize storage immediately
initStorage();

// Read JSON file helper
function readStore(filename) {
  const filePath = path.join(STORAGE_DIR, filename);
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(`[DB] Error reading ${filename}:`, err);
    return [];
  }
}

// Write JSON file helper
function writeStore(filename, data) {
  const filePath = path.join(STORAGE_DIR, filename);
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`[DB] Error writing ${filename}:`, err);
  }
}

// Generic Store class for simple query builder
class Store {
  constructor(filename) {
    this.filename = filename;
  }

  getAll() {
    return readStore(this.filename);
  }

  saveAll(data) {
    writeStore(this.filename, data);
  }

  find(predicate) {
    const list = this.getAll();
    if (typeof predicate === 'function') {
      return list.filter(predicate);
    }
    if (typeof predicate === 'object') {
      return list.filter(item => {
        return Object.entries(predicate).every(([key, value]) => item[key] === value);
      });
    }
    return list;
  }

  findOne(predicate) {
    const list = this.getAll();
    if (typeof predicate === 'function') {
      return list.find(predicate) || null;
    }
    if (typeof predicate === 'object') {
      return list.find(item => {
        return Object.entries(predicate).every(([key, value]) => item[key] === value);
      }) || null;
    }
    return list[0] || null;
  }

  insert(item) {
    const list = this.getAll();
    const newItem = {
      ...item,
      created_at: item.created_at || new Date().toISOString(),
      updated_at: item.updated_at || new Date().toISOString(),
    };
    list.push(newItem);
    this.saveAll(list);
    return newItem;
  }

  update(predicate, updates) {
    const list = this.getAll();
    let updatedCount = 0;
    const isFn = typeof predicate === 'function';

    const newList = list.map(item => {
      const match = isFn ? predicate(item) : Object.entries(predicate).every(([key, value]) => item[key] === value);
      if (match) {
        updatedCount++;
        return {
          ...item,
          ...updates,
          updated_at: new Date().toISOString(),
        };
      }
      return item;
    });

    if (updatedCount > 0) {
      this.saveAll(newList);
    }
    return updatedCount;
  }

  delete(predicate) {
    const list = this.getAll();
    const isFn = typeof predicate === 'function';
    const originalLen = list.length;

    const newList = list.filter(item => {
      const match = isFn ? predicate(item) : Object.entries(predicate).every(([key, value]) => item[key] === value);
      return !match;
    });

    if (newList.length !== originalLen) {
      this.saveAll(newList);
    }
    return originalLen - newList.length;
  }
}

const usersStore = new Store('users.json');
const membersStore = new Store('members.json');
const filesStore = new Store('files.json');
const sharesStore = new Store('shares.json');
const accessStore = new Store('access.json');
const securityLogsStore = new Store('security_logs.json');
const performanceStore = new Store('performance_metrics.json');

// Fake test connection helper for compatibility
async function testConnection() {
  return true;
}

module.exports = {
  users: usersStore,
  members: membersStore,
  files: filesStore,
  shares: sharesStore,
  access: accessStore,
  securityLogs: securityLogsStore,
  performance: performanceStore,
  testConnection,
};
