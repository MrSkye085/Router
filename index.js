const express = require("express");
const path = require("node:path");
const crypto = require("node:crypto");
const { createClient } = require("@tursodatabase/serverless/compat");
require("dotenv").config();

const app = express();
const { PORT } = process.env;

// ---------- DATABASE SETUP (TURSO COMPAT LAYER) ----------
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ---------- HELPERS ----------
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
}

// ---------- SCHEMA INITIALIZATION ----------
async function initDatabase() {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.execute(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);

    await db.execute(`
      CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT,
        ip TEXT,
        mac TEXT,
        connected INTEGER DEFAULT 1,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.execute(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
    `);

    console.log("✅ Database schema ready");
  } catch (err) {
    console.error("❌ Schema init error:", err);
  }
}

// ---------- SEED DATA ----------
async function createDefaultUser() {
  try {
    const existing = await db.execute({
      sql: "SELECT id FROM users WHERE username = ?",
      args: ["admin"],
    });

    if (existing.rows.length === 0) {
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = hashPassword("admin", salt);

      await db.execute({
        sql: "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
        args: ["admin", hash, salt],
      });
      console.log("✅ Default user created: admin / admin");
    }
  } catch (err) {
    console.error("❌ Default user error:", err);
  }
}

async function seedDevices() {
  try {
    const result = await db.execute("SELECT COUNT(*) AS c FROM devices");
    const count = result.rows[0].c;

    if (count === 0) {
      const seeds = [
        ["DESKTOP-01", "192.168.1.101", "AA:BB:CC:11:22:33"],
        ["iPhone-13", "192.168.1.102", "AA:BB:CC:44:55:66"],
        ["Smart-TV", "192.168.1.103", "AA:BB:CC:77:88:99"],
        ["Laptop-HP", "192.168.1.104", "AA:BB:CC:AA:BB:CC"],
      ];

      for (const d of seeds) {
        await db.execute({
          sql: "INSERT INTO devices (hostname, ip, mac) VALUES (?, ?, ?)",
          args: d,
        });
      }
      console.log("✅ Devices seeded");
    }
  } catch (err) {
    console.error("❌ Device seed error:", err);
  }
}

async function seedSettings() {
  try {
    const defaults = {
      ssid: "HomeGateway_2.4G",
      wifi_password: "changeme123",
      channel: "6",
      security_mode: "WPA2-PSK",
      firewall_enabled: "true",
      parental_control: "false",
      firmware_version: "v2.1.4",
      router_name: "Home Gateway",
    };

    for (const [key, value] of Object.entries(defaults)) {
      await db.execute({
        sql: "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        args: [key, value],
      });
    }
    console.log("✅ Settings seeded");
  } catch (err) {
    console.error("❌ Settings seed error:", err);
  }
}

// ---------- ONE-TIME INIT ----------
let initialized = false;
async function ensureInitialized() {
  if (initialized) return;
  await initDatabase();
  await createDefaultUser();
  await seedDevices();
  await seedSettings();
  initialized = true;
}

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Simple cookie parser
app.use((req, _res, next) => {
  req.cookies = {};
  const raw = req.headers.cookie;
  if (raw) {
    raw.split(";").forEach((part) => {
      const [k, ...v] = part.trim().split("=");
      req.cookies[k] = decodeURIComponent(v.join("="));
    });
  }
  next();
});

// Init database on every request (idempotent)
app.use(async (req, _res, next) => {
  await ensureInitialized();
  next();
});

// Auth middleware (redirects to login)
async function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.redirect("/");

  try {
    const result = await db.execute({
      sql: "SELECT * FROM sessions WHERE token = ?",
      args: [token],
    });

    if (result.rows.length === 0) return res.redirect("/");
    req.userId = result.rows[0].user_id;
    next();
  } catch (err) {
    console.error("Auth error:", err);
    res.redirect("/");
  }
}

// Auth middleware (JSON response for API)
async function requireApiAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  try {
    const result = await db.execute({
      sql: "SELECT * FROM sessions WHERE token = ?",
      args: [token],
    });

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    req.userId = result.rows[0].user_id;
    next();
  } catch (err) {
    console.error("API auth error:", err);
    res.status(401).json({ success: false, message: "Unauthorized" });
  }
}

// ---------- PUBLIC ROUTES ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required.",
      });
    }

    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
      args: [username],
    });

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password.",
      });
    }

    const user = result.rows[0];
    const attempt = hashPassword(password, user.salt);

    if (attempt !== user.password_hash) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password.",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    await db.execute({
      sql: "INSERT INTO sessions (token, user_id) VALUES (?, ?)",
      args: [token, user.id],
    });

    res.setHeader(
      "Set-Cookie",
      `session=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`
    );
    res.json({
      success: true,
      message: "Login successful.",
      redirect: "/dashboard",
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/logout", async (req, res) => {
  try {
    const token = req.cookies.session;
    if (token) {
      await db.execute({
        sql: "DELETE FROM sessions WHERE token = ?",
        args: [token],
      });
    }
    res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
    res.json({ success: true, redirect: "/" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

// ---------- PROTECTED PAGES ----------
const pages = ["dashboard", "wifi", "devices", "security", "system"];
pages.forEach((p) => {
  app.get(`/${p}`, requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "public", `${p}.html`));
  });
});

// ---------- PROTECTED API ----------
app.get("/api/settings", requireApiAuth, async (req, res) => {
  try {
    const result = await db.execute("SELECT key, value FROM settings");
    const settings = Object.fromEntries(
      result.rows.map((r) => [r.key, r.value])
    );
    res.json({ success: true, settings });
  } catch (err) {
    console.error("Get settings error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/api/settings", requireApiAuth, async (req, res) => {
  try {
    const updates = req.body;

    for (const [key, value] of Object.entries(updates)) {
      await db.execute({
        sql: `INSERT INTO settings (key, value) VALUES (?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        args: [key, String(value)],
      });
    }

    res.json({ success: true, message: "Settings saved." });
  } catch (err) {
    console.error("Save settings error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.get("/api/devices", requireApiAuth, async (req, res) => {
  try {
    const result = await db.execute("SELECT * FROM devices ORDER BY id");
    res.json({ success: true, devices: result.rows });
  } catch (err) {
    console.error("Get devices error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/api/devices/:id/block", requireApiAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.execute({
      sql: "SELECT * FROM devices WHERE id = ?",
      args: [id],
    });

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Device not found" });
    }

    const dev = result.rows[0];
    const newState = dev.connected ? 0 : 1;

    await db.execute({
      sql: "UPDATE devices SET connected = ? WHERE id = ?",
      args: [newState, id],
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Block device error:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/api/reboot", requireApiAuth, async (req, res) => {
  res.json({ success: true, message: "Router rebooting… (simulated)" });
});

// ---------- 404 ----------
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found." });
});

// ---------- SERVER ----------
if (process.env.NODE_ENV !== "production" || !process.env.VERCEL) {
  const listenPort = PORT || 5000;
  app.listen(listenPort, () => {
    console.log(`🚀 Router admin at http://localhost:${listenPort}`);
  });
}

// Export for Vercel serverless
module.exports = app;