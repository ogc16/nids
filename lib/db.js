const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const config = require('./config');
const { AppError } = require('./errors');

const dbPath = path.join(config.dataDir, 'nids.db');

let db;

function getDb() {
  if (!db) {
    db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    migrateJsonData();
  }
  return db;
}

function getTableNames() {
  const rows = getDb().prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
  return rows.map(r => r.name);
}

function initTable(name) {
  const tableName = name.replace(/-/g, '_');
  getDb().exec(`CREATE TABLE IF NOT EXISTS "${tableName}" (id INTEGER PRIMARY KEY, data TEXT)`);
  return tableName;
}

function readTable(name) {
  const tableName = initTable(name);
  try {
    const rows = getDb().prepare(`SELECT id, data FROM "${tableName}" ORDER BY id`).all();
    return rows.map(r => {
      const obj = JSON.parse(r.data);
      obj.id = r.id;
      return obj;
    });
  } catch (err) {
    console.error(`[DB] readTable error for ${name}:`, err.message);
    throw new AppError(500, `Database read error for ${name}`);
  }
}

function writeTable(name, data) {
  const tableName = initTable(name);
  try {
    const del = getDb().prepare(`DELETE FROM "${tableName}"`);
    const ins = getDb().prepare(`INSERT INTO "${tableName}" (id, data) VALUES (@id, @data)`);
    const tx = getDb().transaction((items) => {
      del.run();
      for (const item of items) {
        const { id, ...rest } = item;
        ins.run({ id: id ?? 0, data: JSON.stringify(rest) });
      }
    });
    tx(data);
  } catch (err) {
    console.error(`[DB] writeTable error for ${name}:`, err.message);
    throw new AppError(500, `Database write error for ${name}`);
  }
}

function nextId(data) {
  return data.reduce((max, d) => Math.max(max, d.id || 0), 0) + 1;
}

function readTablePaginated(name, query) {
  let data = readTable(name);
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(config.maxPageSize, Math.max(1, parseInt(query.limit) || config.defaultPageSize));
  const total = data.length;

  if (query.search && query.searchField) {
    const terms = query.search.toLowerCase();
    data = data.filter(d => String(d[query.searchField] || '').toLowerCase().includes(terms));
  }

  const totalFiltered = data.length;
  const offset = (page - 1) * limit;
  const items = data.slice(offset, offset + limit);

  return { items, pagination: { page, limit, total, totalFiltered, totalPages: Math.ceil(totalFiltered / limit) } };
}

function readTableSafe(name) {
  try {
    return readTable(name);
  } catch {
    return [];
  }
}

function queryTable(name, whereClause, params) {
  const tableName = initTable(name);
  try {
    const sql = `SELECT id, data FROM "${tableName}" WHERE ${whereClause} ORDER BY id`;
    const rows = getDb().prepare(sql).all(...(params || []));
    return rows.map(r => {
      const obj = JSON.parse(r.data);
      obj.id = r.id;
      return obj;
    });
  } catch (err) {
    console.error(`[DB] queryTable error for ${name}:`, err.message);
    throw new AppError(500, `Database query error for ${name}`);
  }
}

function deleteTable(name, id) {
  const tableName = initTable(name);
  try {
    const result = getDb().prepare(`DELETE FROM "${tableName}" WHERE id = ?`).run(id);
    return result.changes > 0;
  } catch (err) {
    console.error(`[DB] deleteTable error for ${name}:`, err.message);
    throw new AppError(500, `Database delete error for ${name}`);
  }
}

function getStats() {
  const d = getDb();
  const tableCount = getTableNames().length;

  let recordCount = 0;
  const tables = getTableNames();
  for (const t of tables) {
    const row = d.prepare(`SELECT COUNT(*) as cnt FROM "${t}"`).get();
    recordCount += row.cnt;
  }

  let dbSize = 0;
  try {
    const stats = fs.statSync(dbPath);
    dbSize = stats.size;
  } catch {}

  const lastVacuum = (() => {
    try {
      const row = d.prepare("SELECT strftime('%s', MAX(mtime)) as mtime FROM (SELECT mtime FROM dbstat WHERE pageno > 1)").get();
      return row && row.mtime ? new Date(row.mtime * 1000).toISOString() : null;
    } catch {
      return null;
    }
  })();

  return { tableCount, recordCount, dbSize, lastVacuum };
}

function vacuum() {
  try {
    getDb().exec('VACUUM');
  } catch (err) {
    console.error(`[DB] vacuum error:`, err.message);
    throw new AppError(500, 'Database vacuum failed');
  }
}

function migrateJsonData() {
  const tables = [
    'incidents', 'detection-rules', 'threat-intel', 'engineering-tasks',
    'network-assets', 'qa-tests', 'network-traffic', 'playbooks',
    'security-policies', 'security-standards', 'users', 'asset-logs',
    'pcap-captures', 'automations-log'
  ];

  for (const name of tables) {
    const file = path.join(config.dataDir, `${name}.json`);
    if (!fs.existsSync(file)) continue;

    const tableName = initTable(name);
    const count = getDb().prepare(`SELECT COUNT(*) as cnt FROM "${tableName}"`).get().cnt;
    if (count > 0) continue;

    try {
      const raw = fs.readFileSync(file, 'utf8');
      const data = JSON.parse(raw);
      if (!Array.isArray(data) || data.length === 0) continue;

      const ins = getDb().prepare(`INSERT INTO "${tableName}" (id, data) VALUES (@id, @data)`);
      const tx = getDb().transaction((items) => {
        for (const item of items) {
          const { id, ...rest } = item;
          ins.run({ id: id ?? 0, data: JSON.stringify(rest) });
        }
      });
      tx(data);
      console.log(`[DB] Migrated ${data.length} records from ${name}.json`);
    } catch (err) {
      console.error(`[DB] Migration error for ${name}.json:`, err.message);
    }
  }
}

module.exports = {
  getDb,
  getTableNames,
  readTable,
  writeTable,
  nextId,
  readTablePaginated,
  readTableSafe,
  queryTable,
  deleteTable,
  getStats,
  vacuum
};
