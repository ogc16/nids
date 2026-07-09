function audit(action, req, data) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  console.log(`[Audit] ${action} - ${ip}${data ? ' ' + JSON.stringify(data) : ''}`);
}

module.exports = { audit };
