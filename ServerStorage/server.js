const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const APP_URL = process.env.APP_URL || `http://${HOST}:${PORT}`;
const COOKIE_SECURE = APP_URL.startsWith("https://");
const DATA_DIR = path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");
const SCRIPTS_DIR = path.join(DATA_DIR, "scripts");
const CONFIG_PATH = path.join(DATA_DIR, "config.json");
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const MAX_BODY_BYTES = 1024 * 1024 * 2;

bootstrap();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, APP_URL);
    const method = req.method || "GET";

    if (method === "GET" && serveStatic(url.pathname, res)) {
      return;
    }

    if (method === "GET" && url.pathname === "/") {
      return sendHtml(res, renderShell());
    }

    if (method === "GET" && url.pathname === "/health") {
      return sendJson(res, 200, { ok: true });
    }

    if (method === "GET" && url.pathname.startsWith("/raw/")) {
      return handleRawRequest(res, url);
    }

    if (url.pathname === "/api/setup" && method === "GET") {
      return sendJson(res, 200, { needsSetup: !getConfig().passwordHash });
    }

    if (url.pathname === "/api/setup" && method === "POST") {
      const body = await readRequestJson(req);
      return handleSetup(res, body);
    }

    if (url.pathname === "/api/login" && method === "POST") {
      const body = await readRequestJson(req);
      return handleLogin(res, body);
    }

    if (url.pathname === "/api/logout" && method === "POST") {
      return handleLogout(res);
    }

    if (url.pathname === "/api/session" && method === "GET") {
      return handleSession(req, res);
    }

    if (url.pathname === "/api/scripts" && method === "GET") {
      return withAuth(req, () => sendJson(res, 200, buildDashboardPayload()));
    }

    if (url.pathname === "/api/scripts" && method === "POST") {
      return withAuth(req, async (session) => {
        const body = await readRequestJson(req);
        verifyCsrf(req, session);
        const script = createScript(body);
        return sendJson(res, 201, { script, message: "Script saved." });
      });
    }

    if (url.pathname.match(/^\/api\/scripts\/[^/]+$/) && method === "PUT") {
      return withAuth(req, async (session) => {
        const body = await readRequestJson(req);
        verifyCsrf(req, session);
        const id = url.pathname.split("/").pop();
        const script = updateScript(id, body);
        return sendJson(res, 200, { script, message: "Script updated." });
      });
    }

    if (url.pathname.match(/^\/api\/scripts\/[^/]+$/) && method === "DELETE") {
      return withAuth(req, (session) => {
        verifyCsrf(req, session);
        const id = url.pathname.split("/").pop();
        deleteScript(id);
        return sendJson(res, 200, { ok: true });
      });
    }

    if (url.pathname.match(/^\/api\/scripts\/[^/]+\/rotate-token$/) && method === "POST") {
      return withAuth(req, (session) => {
        verifyCsrf(req, session);
        const id = url.pathname.split("/")[3];
        const script = rotateScriptToken(id);
        return sendJson(res, 200, { script, message: "Access token rotated." });
      });
    }

    sendJson(res, 404, { error: "Not found." });
  } catch (error) {
    const status = error.statusCode || 500;
    sendJson(res, status, { error: error.message || "Unexpected error." });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`ServerStorage running at ${APP_URL}`);
});

function bootstrap() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  fs.mkdirSync(SCRIPTS_DIR, { recursive: true });
  if (!fs.existsSync(CONFIG_PATH)) {
    writeJson(CONFIG_PATH, {
      passwordHash: "",
      passwordSalt: "",
      sessionSecret: randomToken(32),
      createdAt: new Date().toISOString()
    });
  }
}

function renderShell() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ServerStorage</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/style.css" />
  </head>
  <body>
    <div id="app"></div>
    <script src="/app.js" defer></script>
  </body>
</html>`;
}

function serveStatic(pathname, res) {
  const fileMap = {
    "/style.css": path.join(PUBLIC_DIR, "style.css"),
    "/app.js": path.join(PUBLIC_DIR, "app.js")
  };
  const target = fileMap[pathname];
  if (!target || !fs.existsSync(target)) {
    return false;
  }
  const type = path.extname(target) === ".css" ? "text/css; charset=utf-8" : "application/javascript; charset=utf-8";
  writeHead(res, 200, type);
  res.end(fs.readFileSync(target));
  return true;
}

function handleSetup(res, body) {
  const config = getConfig();
  if (config.passwordHash) {
    throw httpError(409, "Setup is already complete.");
  }
  const password = String(body.password || "");
  if (password.length < 12) {
    throw httpError(400, "Use a password with at least 12 characters.");
  }
  const salt = randomToken(16);
  config.passwordSalt = salt;
  config.passwordHash = hashPassword(password, salt);
  writeJson(CONFIG_PATH, config);
  sendJson(res, 201, { ok: true });
}

function handleLogin(res, body) {
  const config = getConfig();
  if (!config.passwordHash) {
    throw httpError(400, "Complete setup first.");
  }
  const password = String(body.password || "");
  const hashed = hashPassword(password, config.passwordSalt);
  const expected = Buffer.from(config.passwordHash, "hex");
  const actual = Buffer.from(hashed, "hex");
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw httpError(401, "Invalid password.");
  }
  const session = issueSession(config.sessionSecret);
  setCookie(res, "session", session.token, {
    httpOnly: true,
    sameSite: "Strict",
    secure: COOKIE_SECURE,
    path: "/",
    maxAge: SESSION_TTL_MS / 1000
  });
  setCookie(res, "csrf", session.csrf, {
    httpOnly: false,
    sameSite: "Strict",
    secure: COOKIE_SECURE,
    path: "/",
    maxAge: SESSION_TTL_MS / 1000
  });
  sendJson(res, 200, { ok: true });
}

function handleLogout(res) {
  expireCookie(res, "session");
  expireCookie(res, "csrf");
  sendJson(res, 200, { ok: true });
}

function handleSession(req, res) {
  const session = parseSession(req);
  if (!session) {
    return sendJson(res, 200, { authenticated: false });
  }
  sendJson(res, 200, {
    authenticated: true,
    csrfToken: session.csrf,
    appUrl: APP_URL
  });
}

function handleRawRequest(res, url) {
  const id = url.pathname.split("/").pop();
  const token = String(url.searchParams.get("token") || "");
  const script = getScript(id);
  if (!script) {
    throw httpError(404, "Script not found.");
  }
  if (!script.enabled) {
    recordExecution(id, false);
    throw httpError(403, "Script is disabled.");
  }
  if (!token || token !== script.accessToken) {
    recordExecution(id, false);
    throw httpError(401, "Invalid access token.");
  }
  recordExecution(id, true);
  writeHead(res, 200, "text/plain; charset=utf-8", {
    "Content-Disposition": `inline; filename="${safeFileName(script.slug)}.lua"`,
    "Cache-Control": "no-store"
  });
  res.end(script.code);
}

function withAuth(req, callback) {
  const session = parseSession(req);
  if (!session) {
    throw httpError(401, "Sign in required.");
  }
  return callback(session);
}

function parseSession(req) {
  const config = getConfig();
  const cookies = parseCookies(req.headers.cookie || "");
  const token = cookies.session;
  if (!token || !config.sessionSecret) {
    return null;
  }
  try {
    const decoded = Buffer.from(token, "base64url").toString("utf8");
    const [payloadJson, signature] = decoded.split(".");
    const expected = sign(payloadJson, config.sessionSecret);
    if (!signature || signature !== expected) {
      return null;
    }
    const payload = JSON.parse(payloadJson);
    if (Date.now() > payload.expiresAt) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function verifyCsrf(req, session) {
  const header = req.headers["x-csrf-token"];
  if (!header || header !== session.csrf) {
    throw httpError(403, "Invalid CSRF token.");
  }
}

function issueSession(secret) {
  const payload = {
    issuedAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    csrf: randomToken(24)
  };
  const payloadJson = JSON.stringify(payload);
  const signature = sign(payloadJson, secret);
  return {
    csrf: payload.csrf,
    token: Buffer.from(`${payloadJson}.${signature}`).toString("base64url")
  };
}

function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function buildDashboardPayload() {
  const scripts = listScripts().sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
  const totals = scripts.reduce(
    (acc, script) => {
      acc.totalScripts += 1;
      acc.enabled += script.enabled ? 1 : 0;
      acc.executions += Number(script.executions || 0);
      acc.success += Number(script.successCount || 0);
      acc.failed += Number(script.failureCount || 0);
      return acc;
    },
    { totalScripts: 0, enabled: 0, executions: 0, success: 0, failed: 0 }
  );

  return {
    appUrl: APP_URL,
    stats: {
      totalScripts: totals.totalScripts,
      enabled: totals.enabled,
      executions: totals.executions,
      successRate: totals.executions ? Math.round((totals.success / totals.executions) * 100) : 0,
      failed: totals.failed
    },
    scripts: scripts.map((script) => ({
      ...script,
      rawUrl: `${APP_URL}/raw/${script.id}?token=${script.accessToken}`
    }))
  };
}

function createScript(body) {
  const now = new Date().toISOString();
  const name = String(body.name || "").trim();
  const code = normalizeCode(body.code);
  if (!name) {
    throw httpError(400, "Script name is required.");
  }
  if (!code) {
    throw httpError(400, "Script code is required.");
  }

  const script = {
    id: crypto.randomUUID(),
    name,
    slug: makeSlug(name),
    description: String(body.description || "").trim(),
    code,
    enabled: body.enabled !== false,
    accessToken: randomToken(24),
    createdAt: now,
    updatedAt: now,
    executions: 0,
    successCount: 0,
    failureCount: 0
  };
  writeJson(path.join(SCRIPTS_DIR, `${script.id}.json`), script);
  return script;
}

function updateScript(id, body) {
  const script = getScript(id);
  if (!script) {
    throw httpError(404, "Script not found.");
  }
  const nextName = String(body.name || script.name).trim();
  const nextCode = normalizeCode(body.code ?? script.code);
  if (!nextName) {
    throw httpError(400, "Script name is required.");
  }
  if (!nextCode) {
    throw httpError(400, "Script code is required.");
  }

  script.name = nextName;
  script.slug = makeSlug(nextName);
  script.description = String(body.description ?? script.description).trim();
  script.code = nextCode;
  script.enabled = Boolean(body.enabled);
  script.updatedAt = new Date().toISOString();
  writeJson(path.join(SCRIPTS_DIR, `${script.id}.json`), script);
  return script;
}

function deleteScript(id) {
  const target = path.join(SCRIPTS_DIR, `${id}.json`);
  if (!fs.existsSync(target)) {
    throw httpError(404, "Script not found.");
  }
  fs.unlinkSync(target);
}

function rotateScriptToken(id) {
  const script = getScript(id);
  if (!script) {
    throw httpError(404, "Script not found.");
  }
  script.accessToken = randomToken(24);
  script.updatedAt = new Date().toISOString();
  writeJson(path.join(SCRIPTS_DIR, `${script.id}.json`), script);
  return script;
}

function recordExecution(id, success) {
  const script = getScript(id);
  if (!script) {
    return;
  }
  script.executions += 1;
  if (success) {
    script.successCount += 1;
  } else {
    script.failureCount += 1;
  }
  script.updatedAt = new Date().toISOString();
  writeJson(path.join(SCRIPTS_DIR, `${script.id}.json`), script);
}

function listScripts() {
  return fs
    .readdirSync(SCRIPTS_DIR)
    .filter((file) => file.endsWith(".json"))
    .map((file) => readJson(path.join(SCRIPTS_DIR, file)))
    .filter(Boolean);
}

function getScript(id) {
  const target = path.join(SCRIPTS_DIR, `${id}.json`);
  if (!fs.existsSync(target)) {
    return null;
  }
  return readJson(target);
}

function getConfig() {
  return readJson(CONFIG_PATH);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), "utf8");
}

function normalizeCode(value) {
  return String(value || "").replace(/\r\n/g, "\n").trim();
}

function makeSlug(value) {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "script";
}

function safeFileName(value) {
  return value.replace(/[^a-z0-9-_]/gi, "_");
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function randomToken(bytes) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function parseCookies(header) {
  return header
    .split(";")
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .reduce((acc, cookie) => {
      const eq = cookie.indexOf("=");
      if (eq === -1) {
        return acc;
      }
      const key = cookie.slice(0, eq);
      const value = cookie.slice(eq + 1);
      acc[key] = decodeURIComponent(value);
      return acc;
    }, {});
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push("Secure");
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
  const existing = res.getHeader("Set-Cookie");
  const next = Array.isArray(existing) ? existing.concat(parts.join("; ")) : [parts.join("; ")];
  res.setHeader("Set-Cookie", next);
}

function expireCookie(res, name) {
  setCookie(res, name, "", { path: "/", maxAge: 0, sameSite: "Strict", secure: COOKIE_SECURE });
}

function readRequestJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let body = "";
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(httpError(413, "Request body too large."));
        req.destroy();
        return;
      }
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(httpError(400, "Invalid JSON body."));
      }
    });
    req.on("error", reject);
  });
}

function writeHead(res, statusCode, contentType, extraHeaders = {}) {
  const baseHeaders = {
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  };
  res.writeHead(statusCode, { ...baseHeaders, ...extraHeaders });
}

function sendJson(res, statusCode, value) {
  writeHead(res, statusCode, "application/json; charset=utf-8", { "Cache-Control": "no-store" });
  res.end(JSON.stringify(value));
}

function sendHtml(res, html) {
  writeHead(res, 200, "text/html; charset=utf-8", { "Cache-Control": "no-store" });
  res.end(html);
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}
