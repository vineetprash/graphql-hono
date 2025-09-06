import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { secureHeaders } from 'hono/secure-headers'

// In-memory rate limiting for demo (reset on deploy)
const rateMap = new Map()
const RATE_LIMIT = 30
const WINDOW = 60 * 1000 // 1 minute
const CLEANUP_WINDOW = 5 * 60 * 1000 // 5 minutes

const app = new Hono()

// Security headers
app.use('*', secureHeaders())

// CORS for localhost and production
app.use('*', cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'https://*.workers.dev'],
  allowMethods: ['GET', 'POST'],
}))

// Rate limiting middleware with cleanup
app.use('*', async (c, next) => {
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown'
  const now = Date.now()
  let entry = rateMap.get(ip)
  if (!entry || now - entry.start > WINDOW) {
    entry = { count: 1, start: now }
  } else {
    entry.count++
  }
  rateMap.set(ip, entry)
  // Cleanup: remove old entries
  for (const [k, v] of rateMap.entries()) {
    if (now - v.start > CLEANUP_WINDOW) {
      rateMap.delete(k)
    }
  }
  if (entry.count > RATE_LIMIT) {
    return c.text('Too many requests, please try again later.', 429)
  }
  await next()
})

// User-Agent and payload checks
app.use('/leetcode-proxy', async (c, next) => {
  const ua = c.req.header('user-agent') || ''
  if (/curl|python|wget|bot|scrapy|spider|scan|nmap/i.test(ua)) {
    return c.text('Automated clients are not allowed.', 403)
  }
  if (c.req.method === 'POST') {
    // Validate content-type
    const contentType = c.req.header('content-type') || ''
    if (!contentType.includes('application/json')) {
      return c.text('Content-Type must be application/json', 415)
    }
    
    let reqBody
    try {
      reqBody = await c.req.json()
    } catch {
      return c.text('Malformed JSON', 400)
    }
    
    // Validate payload structure
    if (!reqBody || typeof reqBody !== 'object' || !reqBody.body || !reqBody.headers) {
      return c.text('Malformed request.', 400)
    }
    
    // Check for allowed fields only
    const allowedFields = ['body', 'headers']
    for (const key of Object.keys(reqBody)) {
      if (!allowedFields.includes(key)) {
        return c.text('Unexpected field in payload', 400)
      }
    }
    
    // Store parsed body for reuse
    c.set('parsedBody', reqBody)
  }
  await next()
})

// Root endpoint - simple response
app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>LeetCode Proxy API</title>
    </head>
    <body>
      <h1>LeetCode Proxy API</h1>
      <p>POST to /leetcode-proxy to use the GraphQL proxy</p>
    </body>
    </html>
  `)
})

// Read BASE_URL from environment (Cloudflare Workers: env.BASE_URL, Node: process.env.BASE_URL)
const getBaseUrl = (env) => {
  if (typeof process !== 'undefined' && process.env && process.env.BASE_URL) {
    return process.env.BASE_URL
  }
  if (env && env.BASE_URL) {
    return env.BASE_URL
  }
  return 'https://leetcode.com/graphql/'
}

app.post('/leetcode-proxy', async (c) => {
  try {
    // Use stored parsed body or parse JSON
    const { body, headers: customHeaders } = c.get('parsedBody') || await c.req.json()
    const allowedHeaders = [
      'accept', 'accept-language', 'content-type', 'x-csrftoken', 'user-agent', 'referer', 'origin', 'cookie'
    ]
    const filteredHeaders = {}
    for (const k in customHeaders) {
      if (allowedHeaders.includes(k.toLowerCase())) {
        filteredHeaders[k] = customHeaders[k]
      }
    }
    const baseUrl = getBaseUrl(c.env)
    const resp = await fetch(baseUrl, {
      method: 'POST',
      headers: filteredHeaders,
      body: JSON.stringify(body),
    })
    const text = await resp.text()
    return c.newResponse(text, resp.status, { 'content-type': resp.headers.get('content-type') })
  } catch (err) {
    return c.json({ error: err.message }, 500)
  }
})

export default app
