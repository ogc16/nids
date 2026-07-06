const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { authenticate, authorize } = require('../lib/auth');
const { audit } = require('../lib/audit');
const pcap = require('../lib/pcap');

const upload = multer({
  dest: pcap.PCAP_DIR,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.pcap', '.pcapng', '.cap'].includes(ext)) return cb(null, true);
    cb(new Error('Only .pcap, .pcapng, .cap files allowed'));
  }
});

router.post('/pcap/upload', authenticate, authorize('admin', 'analyst'), upload.single('pcap'), (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No PCAP file uploaded' });
    const result = { id: Date.now(), filename: req.file.originalname, size: req.file.size, path: req.file.path, uploadedAt: new Date().toISOString() };
    audit('pcap_uploaded', req, { filename: req.file.originalname, size: req.file.size });
    res.json(result);
  } catch (err) { next(err); }
});

router.post('/pcap/analyze', authenticate, authorize('admin', 'analyst'), (req, res, next) => {
  try {
    const { captureSize = 100 } = req.body || {};
    const result = pcap.analyze(captureSize);
    audit('pcap_analysis', req, { packets: result.length });
    res.json({ packets: result, total: result.length, source: 'simulated' });
  } catch (err) { next(err); }
});

router.post('/pcap/inject', authenticate, authorize('admin'), (req, res, next) => {
  try {
    const { packet, count = 1 } = req.body || {};
    if (!packet) return res.status(400).json({ error: 'PCAP data is required' });
    if (typeof packet === 'string') {
      const data = JSON.parse(packet);
      const results = [];
      for (let i = 0; i < count; i++) results.push({ ...data, id: Date.now() + i, injectedAt: new Date().toISOString() });
      res.json({ status: 'success', count: count, packets: results });
    } else {
      const results = [];
      for (let i = 0; i < count; i++) results.push({ ...packet, id: Date.now() + i, injectedAt: new Date().toISOString() });
      res.json({ status: 'success', count: count, packets: results });
    }
  } catch (err) { next(err); }
});

router.get('/pcap/list', authenticate, (req, res) => {
  try {
    const files = fs.readdirSync(pcap.PCAP_DIR).filter(f => f.endsWith('.pcap')).map(f => {
      const stats = fs.statSync(path.join(pcap.PCAP_DIR, f));
      return { name: f, size: stats.size, modified: stats.mtime.toISOString() };
    });
    res.json(files);
  } catch (err) { next(err); }
});

router.get('/pcap/download/:filename', authenticate, (req, res) => {
  try {
    const filepath = path.join(pcap.PCAP_DIR, req.params.filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });
    res.download(filepath);
  } catch (err) { next(err); }
});

router.delete('/pcap/delete/:filename', authenticate, authorize('admin'), (req, res) => {
  try {
    const filepath = path.join(pcap.PCAP_DIR, req.params.filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });
    fs.unlinkSync(filepath);
    audit('pcap_deleted', req, { filename: req.params.filename });
    res.status(204).send();
  } catch (err) { next(err); }
});

module.exports = router;
