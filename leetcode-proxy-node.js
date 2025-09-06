const express = require('express');
const fetch = (...args) => import('node-fetch').then(mod => mod.default(...args));
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

// --- Security Middleware ---
app.use(helmet());
app.use(cors({
  origin: [/^http:\/\/localhost(:\d+)?$/],
  methods: ['GET', 'POST'],
  credentials: false
}));
app.use(express.json({ limit: '10kb' })); // Limit payload size

// --- Rate Limiting and Abuse Protection ---
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.'
});
app.use(globalLimiter);

const speedLimiter = slowDown({
  windowMs: 60 * 1000, // 1 minute
  delayAfter: 10, // allow 10 requests/minute at full speed
  delayMs: 500 // add 0.5s delay per request above 10
});
app.use(speedLimiter);

// --- IP Blacklist (in-memory, for demo) ---
const blockedIPs = new Set();
app.use((req, res, next) => {
  const ip = req.ip;
  if (blockedIPs.has(ip)) {
    return res.status(403).send('Forbidden');
  }
  next();
});

// --- User-Agent and Payload Checks ---
app.use((req, res, next) => {
  const ua = req.get('user-agent') || '';
  if (/curl|python|wget|bot|scrapy|spider|scan|nmap/i.test(ua)) {
    return res.status(403).send('Automated clients are not allowed.');
  }
  if (req.method === 'POST' && req.originalUrl === '/leetcode-proxy') {
    if (!req.body || typeof req.body !== 'object' || !req.body.body || !req.body.headers) {
      return res.status(400).send('Malformed request.');
    }
    // Basic abuse detection: block repeated identical payloads from same IP
    const ip = req.ip;
    const hash = crypto.createHash('sha256').update(JSON.stringify(req.body.body)).digest('hex');
    req._payloadHash = hash;
    req._payloadIP = ip;
    if (!global.lastPayloads) global.lastPayloads = {};
    if (!global.lastPayloads[ip]) global.lastPayloads[ip] = [];
    global.lastPayloads[ip].push({ hash, time: Date.now() });
    // If >5 identical payloads in 1 min, block IP
    global.lastPayloads[ip] = global.lastPayloads[ip].filter(e => Date.now() - e.time < 60000);
    const same = global.lastPayloads[ip].filter(e => e.hash === hash);
    if (same.length > 5) {
      blockedIPs.add(ip);
      return res.status(429).send('Too many repeated requests. IP blocked.');
    }
  }
  next();
});

// --- Serve static files (web app) at root ---
app.use('/', express.static(path.join(__dirname)));

// --- Proxy endpoint ---
app.post('/leetcode-proxy', async (req, res) => {
  try {
    const { body, headers: customHeaders } = req.body;
    // Only allow certain headers to be proxied
    const allowedHeaders = [
      'accept', 'accept-language', 'content-type', 'x-csrftoken', 'user-agent', 'referer', 'origin', 'cookie'
    ];
    const filteredHeaders = {};
    for (const k in customHeaders) {
      if (allowedHeaders.includes(k.toLowerCase())) {
        filteredHeaders[k] = customHeaders[k];
      }
    }
    const response = await fetch('https://leetcode.com/graphql/', {
      method: 'POST',
      headers: filteredHeaders,
      body: JSON.stringify(body),
    });
    const data = await response.text();
    res.status(response.status).send(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Error handler ---
app.use((err, req, res, next) => {
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`LeetCode proxy server running on port ${PORT}`);
  console.log(`Serving static files at http://localhost:${PORT}/`);
});
