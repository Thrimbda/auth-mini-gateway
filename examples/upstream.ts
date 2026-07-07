import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';

let hits = 0;

const server = createServer((req, res) => {
  if (req.url === '/hits') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ hits }));
    return;
  }

  if (req.url === '/reset') {
    hits = 0;
    res.writeHead(204).end();
    return;
  }

  hits += 1;
  res.writeHead(200, {
    'content-type': 'text/plain; charset=utf-8',
    'x-upstream-hits': String(hits),
  });
  res.end(`upstream ok ${hits}\n`);
});

const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (socket) => {
  hits += 1;
  socket.on('message', (message) => {
    socket.send(`echo:${message.toString()}`);
  });
  socket.send('connected');
});

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

const port = Number.parseInt(process.env.PORT ?? '4000', 10);
const host = process.env.HOST ?? '127.0.0.1';
server.listen(port, host, () => {
  console.log(`poc upstream listening on ${host}:${port}`);
});
