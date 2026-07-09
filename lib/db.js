const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
const tables = {};

function ensureTable(name) {
  if (!tables[name]) {
    const filePath = path.join(DATA_DIR, `${name}.json`);
    try {
      tables[name] = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch {
      tables[name] = [];
    }
  }
  return tables[name];
}

function readTable(name) {
  return ensureTable(name);
}

function writeTable(name, data) {
  tables[name] = data;
  const filePath = path.join(DATA_DIR, `${name}.json`);
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch {}
}

function readTablePaginated(table, query) {
  const data = readTable(table);
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 25));
  const offset = (page - 1) * limit;
  return {
    items: data.slice(offset, offset + limit),
    pagination: { page, limit, total: data.length, totalFiltered: data.length, totalPages: Math.ceil(data.length / limit) },
  };
}

function nextId(data) {
  if (!data || data.length === 0) return 1;
  return Math.max(...data.map((d) => (typeof d === 'object' && d !== null ? d.id || 0 : 0))) + 1;
}

function getStats() {
  return {
    tables: Object.keys(tables).length,
    records: Object.values(tables).reduce((sum, t) => sum + t.length, 0),
    uptime: process.uptime(),
  };
}

module.exports = { readTable, writeTable, readTablePaginated, nextId, getStats, DATA_DIR };
