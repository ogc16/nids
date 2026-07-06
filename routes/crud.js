const express = require('express');
const router = express.Router();
const { authenticate, authorize, optionalAuth } = require('../lib/auth');
const { audit } = require('../lib/audit');
const config = require('../lib/config');
const db = require('../lib/db');

const WRITABLE_TABLES = ['incidents', 'detection-rules', 'threat-intel', 'engineering-tasks', 'network-assets', 'qa-tests', 'playbooks', 'security-policies', 'security-standards'];
const READONLY_TABLES = ['network-traffic'];
const ALL_TABLES = [...WRITABLE_TABLES, ...READONLY_TABLES];

function readTable(name) { return db.readTable(name); }
function writeTable(name, data) { return db.writeTable(name, data); }

ALL_TABLES.forEach(table => {
  const route = `/${table}`;

  if (table !== 'network-traffic') {
    router.get(route, optionalAuth, (req, res) => {
      const result = db.readTablePaginated(table, req.query);
      res.json(result);
    });
  }

  router.get(`${route}/export`, authenticate, (req, res) => {
    const data = readTable(table);
    if (data.length === 0) return res.status(404).json({ error: 'No data to export' });
    const headers = Object.keys(data[0]);
    const csv = [headers.join(','), ...data.map(row => headers.map(h => {
      const val = row[h];
      if (val === null || val === undefined) return '';
      let str = String(val);
      if (['=', '+', '-', '@', '\t'].includes(str[0])) str = "'" + str;
      return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str.replace(/"/g, '""')}"` : str;
    }).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${table}-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csv);
  });

  router.get(`${route}/:id`, optionalAuth, (req, res) => {
    const data = readTable(table);
    const item = data.find(d => d.id === parseInt(req.params.id));
    if (!item) return res.status(404).json({ error: 'Not found' });
    res.json(item);
  });

  if (table !== 'network-traffic') {
    router.post(route, authenticate, authorize('admin', 'analyst'), (req, res, next) => {
      try {
        const data = readTable(table);
        const nextIdVal = db.nextId(data);
        const item = { id: nextIdVal, ...req.body };
        data.push(item);
        writeTable(table, data);
        audit('create', req, { table, id: item.id });
        res.status(201).json(item);
      } catch (err) { next(err); }
    });
  }

  if (table !== 'network-traffic') {
    router.put(`${route}/:id`, authenticate, authorize('admin', 'analyst'), (req, res, next) => {
      try {
        const data = readTable(table);
        const idx = data.findIndex(d => d.id === parseInt(req.params.id));
        if (idx === -1) return res.status(404).json({ error: 'Not found' });
        data[idx] = { ...data[idx], ...req.body, id: data[idx].id };
        writeTable(table, data);
        audit('update', req, { table, id: data[idx].id, changes: Object.keys(req.body) });
        res.json(data[idx]);
      } catch (err) { next(err); }
    });
  }

  if (table !== 'network-traffic') {
    router.delete(`${route}/:id`, authenticate, authorize('admin'), (req, res, next) => {
      try {
        const data = readTable(table);
        const idx = data.findIndex(d => d.id === parseInt(req.params.id));
        if (idx === -1) return res.status(404).json({ error: 'Not found' });
        data.splice(idx, 1);
        writeTable(table, data);
        audit('delete', req, { table, id: parseInt(req.params.id) });
        res.status(204).send();
      } catch (err) { next(err); }
    });
  }
});

module.exports = { router, WRITABLE_TABLES, ALL_TABLES };
