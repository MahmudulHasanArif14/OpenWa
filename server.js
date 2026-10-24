"use strict";

const http = require("node:http");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 10000);
const OPENWA_PORT = 8081;
const OPENWA_HOST = "127.0.0.1";
const MAX_BODY_BYTES = 16 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 30;

const proxyToken = process.env.PROXY_TOKEN;
const waApiKey = process.env.WA_API_KEY;

function validSecret(value) {
  return typeof value === "string" && /^[\x21-\x7e]{32,256}$/.test(value);
}

if (!validSecret(proxyToken) || !validSecret(waApiKey)) {
  throw new Error("PROXY_TOKEN and WA_API_KEY must be separate strong secrets");
}

if (proxyToken === waApiKey) {
  throw new Error("Proxy and OpenWA credentials must differ");
}

function safeEqual(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// One global limit: suitable for a single-purpose test service.
// For production, use a distributed limiter and a trusted client-IP source.
let windowStarted = Date.now();
let requestCount = 0;

function rateLimited() {
  const now = Date.now();

  if (now - windowStarted >= WINDOW_MS) {
    windowStarted = now;
    requestCount = 0;
  }

  requestCount++;
  return requestCount > MAX_REQUESTS_PER_WINDOW;
}

let openwa;
let shuttingDown = false;
let openwaExited = false;
let openwaStarted = false;

const server = http.createServer((req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");

  // Only this synthetic endpoint is public.
  // It does not query OpenWA or reveal session state.
  if (req.method === "GET" && req.url === "/_render-health") {
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
    });
    return res.end("ok");
  }

  // No WebSockets, QR pages, dashboard, health or docs.
  if (
    req.headers.upgrade ||
    req.method !== "POST" ||
    req.url !== "/api/sendText"
  ) {
    res.writeHead(404, {
      "Content-Type": "application/json",
    });
    return res.end('{"error":"Not found"}');
  }

  const auth = req.headers.authorization || "";
  const supplied = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!safeEqual(supplied, proxyToken)) {
    res.writeHead(401, {
      "Content-Type": "application/json",
      "WWW-Authenticate": "Bearer",
    });
    return res.end('{"error":"Unauthorized"}');
  }

  if (rateLimited()) {
    res.writeHead(429, {
      "Content-Type": "application/json",
      "Retry-After": "60",
    });
    return res.end('{"error":"Rate limit exceeded"}');
  }

  const contentType = (req.headers["content-type"] || "")
    .split(";")[0]
    .trim()
    .toLowerCase();

  if (contentType !== "application/json") {
    res.writeHead(415, {
      "Content-Type": "application/json",
    });
    return res.end('{"error":"JSON required"}');
  }

  const declaredLength = req.headers["content-length"];

  if (
    declaredLength !== undefined &&
    (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_BODY_BYTES)
  ) {
    res.writeHead(413, {
      "Content-Type": "application/json",
    });
    return res.end('{"error":"Request too large"}');
  }

  let bodyBytes = 0;
  let completed = false;

  const upstream = http.request({
    hostname: OPENWA_HOST,
    port: OPENWA_PORT,
    path: "/api/sendText",
    method: "POST",
    timeout: REQUEST_TIMEOUT_MS,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": waApiKey,
    },
  });

  const finishError = (status, message) => {
    if (completed) return;
    completed = true;
    upstream.destroy();

    if (!res.headersSent) {
      res.writeHead(status, {
        "Content-Type": "application/json",
      });
      res.end(JSON.stringify({ error: message }));
    } else {
      res.destroy();
    }
  };

  req.on("data", (chunk) => {
    bodyBytes += chunk.length;

    if (bodyBytes > MAX_BODY_BYTES) {
      finishError(413, "Request too large");
      req.destroy();
      return;
    }

    if (!completed) upstream.write(chunk);
  });

  req.on("end", () => {
    if (!completed) upstream.end();
  });

  req.on("aborted", () => {
    finishError(400, "Request aborted");
  });

  upstream.on("response", (upstreamRes) => {
    // Limit response data too; never relay arbitrary headers.
    let responseBytes = 0;
    const chunks = [];

    upstreamRes.on("data", (chunk) => {
      responseBytes += chunk.length;

      if (responseBytes > MAX_BODY_BYTES) {
        finishError(502, "Upstream response too large");
        upstreamRes.destroy();
        return;
      }

      chunks.push(chunk);
    });

    upstreamRes.on("end", () => {
      if (completed) return;
      completed = true;

      const status = upstreamRes.statusCode || 502;
      const body = Buffer.concat(chunks);

      res.writeHead(status, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      res.end(body);
    });
  });

  upstream.on("timeout", () => {
    finishError(504, "Upstream timeout");
  });

  upstream.on("error", () => {
    finishError(502, "OpenWA unavailable");
  });

  res.on("close", () => {
    if (!res.writableEnded) upstream.destroy();
  });
});

server.headersTimeout = 10_000;
server.requestTimeout = REQUEST_TIMEOUT_MS;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 100;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log("Shutting down:", signal);

  server.close(() => {
    if (openwa && !openwa.killed) {
      openwa.kill("SIGTERM");
    }
  });

  if (openwa && !openwa.killed) openwa.kill("SIGTERM");

  const forceExit = setTimeout(() => {
    if (openwa && !openwa.killed) openwa.kill("SIGKILL");
    process.exit(1);
  }, 10_000);

  forceExit.unref();
}

server.listen(PORT, "0.0.0.0", () => {
  console.log("Protected proxy listening on port", PORT);

  openwa = spawn(
    "npx",
    [
      "--yes",
      "@open-wa/wa-automate@5.1.0",
      "--session-id",
      "render-test",
      "--host",
      OPENWA_HOST,
      "--port",
      String(OPENWA_PORT),
      "--api-key",
      waApiKey,
    ],
    {
      env: {
        ...process.env,
        WA_API_KEY: waApiKey,
        WA_HOST: OPENWA_HOST,
        WA_PORT: String(OPENWA_PORT),
        WA_SESSION_ID: "render-test",
        WA_USER_DATA_DIR: "/tmp/openwa-session",
      },
      stdio: ["ignore", "inherit", "inherit"],
    },
  );

  openwaStarted = true;

  openwa.on("error", (err) => {
    // Do not log environment variables or credentials.
    console.error("OpenWA process failed to start:", err.message);
    openwaExited = true;
    server.close();
  });

  openwa.on("exit", (code) => {
    openwaExited = true;
    console.error("OpenWA exited with code", code);
    if (!shuttingDown) server.close();
  });
});

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
