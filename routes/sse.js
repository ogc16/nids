const { authenticate } = require('../lib/auth');

let sseClients = [];

function addClient(res, user) {
  const id = Date.now();
  sseClients.push({ id, res, user });
  res.on('close', () => { sseClients = sseClients.filter(c => c.id !== id); });
  return id;
}

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(c => { try { c.res.write(msg); } catch {} });
}

function setup(app) {
  app.get('/api/events', authenticate, (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write('data: {"type":"connected"}\n\n');
    addClient(res, req.user);
  });
}

module.exports = { setup, broadcast, sseClients };
