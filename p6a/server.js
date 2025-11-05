// server.js
const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const publicKeys = {};       // userId -> base64 public key
const clients = new Map();   // userId -> ws connection

// Register public key
app.post('/register', (req, res) => {
  const { userId, publicKey } = req.body;
  console.log('[HTTP] /register', userId);
  if (!userId || !publicKey) return res.status(400).json({ error: 'userId and publicKey required' });
  publicKeys[userId] = publicKey;
  res.json({ ok: true });
});

// Get public key for a user
app.get('/pubkey/:userId', (req, res) => {
  const userId = req.params.userId;
  console.log('[HTTP] GET /pubkey/', userId);
  const key = publicKeys[userId];
  if (!key) return res.status(404).json({ error: 'not found' });
  res.json({ userId, publicKey: key });
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  console.log('[WS] connection established');

  ws.on('message', (msg) => {
    console.log('[WS] raw:', msg.toString().slice(0,150));
    try {
      const data = JSON.parse(msg.toString());
      if (data.type === 'identify') {
        ws.userId = data.userId;
        clients.set(data.userId, ws);
        console.log('[WS] identified', data.userId);
        ws.send(JSON.stringify({ type: 'identify-ack', userId: data.userId }));
        return;
      }
      if (data.type === 'message') {
        console.log('[WS] message from', data.from, 'to', data.to);
        const targetWs = clients.get(data.to);
        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
          targetWs.send(JSON.stringify({
            type: 'message',
            from: data.from,
            nonce: data.nonce,
            ciphertext: data.ciphertext,
            senderPubKey: data.senderPubKey
          }));
          ws.send(JSON.stringify({ type: 'sent', ok: true }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'recipient offline' }));
        }
      }
    } catch (e) {
      console.error('[WS] parse error', e);
      ws.send(JSON.stringify({ type: 'error', message: 'invalid payload' }));
    }
  });

  ws.on('close', () => {
    if (ws.userId) {
      console.log('[WS] closed for', ws.userId);
      clients.delete(ws.userId);
    }
  });
});

const PORT = 3000;
server.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
