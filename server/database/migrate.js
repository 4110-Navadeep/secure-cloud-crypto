'use strict';

// No-op for file-based JSON DB migration
async function runMigrations() {
  console.log('[DATABASE] File-based JSON database initialized successfully.');
  return true;
}

module.exports = { runMigrations };
