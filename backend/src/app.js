const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const { pool } = require("./config/db");

const app = express();
app.set("trust proxy", 1);

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is not set");
}

/* =========================
   PATHS
   ========================= */

const FRONTEND_DIR = path.join(__dirname, "../../frontend");
const PAGES_DIR = path.join(FRONTEND_DIR, "pages");

/* =========================
   STATIC FILES
   ========================= */

app.use(express.static(FRONTEND_DIR));

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

function sendPage(res, file) {
  return res.sendFile(path.join(PAGES_DIR, file));
}

/* =========================
   HELPERS
   ========================= */

function safeNextUrl(raw, fallback = "/profile") {
  const val = String(raw || "").trim();
  if (!val) return fallback;
  if (val.startsWith("/") && !val.startsWith("//")) return val;
  return fallback;
}

function getCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
  };
}

/* =========================
   CHAT SESSION COOKIE
   ========================= */

function ensureChatSession(req, res, next) {
  let sid = req.cookies?.chat_session;

  if (!sid) {
    sid = crypto.randomUUID();
    res.cookie("chat_session", sid, {
      ...getCookieOptions(),
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  }

  req.chatSessionId = sid;
  next();
}

app.use(ensureChatSession);

/* =========================
   AUTH MIDDLEWARE
   ========================= */

function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.access_token;

    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.auth = payload;
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (req.auth.role !== role) {
      return res.status(403).json({ error: "Forbidden" });
    }

    next();
  };
}

function requireAuthPage(req, res, next) {
  try {
    const token = req.cookies?.access_token;

    if (!token) {
      const nextUrl = encodeURIComponent(req.originalUrl || "/");
      return res.redirect(`/auth?next=${nextUrl}`);
    }

    jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch (error) {
    const nextUrl = encodeURIComponent(req.originalUrl || "/");
    return res.redirect(`/auth?next=${nextUrl}`);
  }
}

/* =========================
   PAGE ROUTES
   ========================= */

app.get("/", (req, res) => sendPage(res, "index.html"));
app.get("/about", (req, res) => sendPage(res, "about.html"));
app.get("/works", (req, res) => sendPage(res, "works.html"));
app.get("/contact", (req, res) => sendPage(res, "contact.html"));
app.get("/courses", (req, res) => sendPage(res, "courses.html"));
app.get("/auth", (req, res) => sendPage(res, "auth.html"));

app.get("/get-courses", (req, res) => {
  return res.redirect("/courses");
});

app.get("/courses/beginner", requireAuthPage, (req, res) =>
  sendPage(res, "course-beginner.html")
);

app.get("/courses/pro", requireAuthPage, (req, res) =>
  sendPage(res, "course-pro.html")
);

app.get("/courses/uiux-basic", requireAuthPage, (req, res) =>
  sendPage(res, "course-uiux-basic.html")
);

app.get("/level", requireAuthPage, (req, res) => sendPage(res, "level.html"));
app.get("/profile", requireAuthPage, (req, res) => sendPage(res, "profile.html"));

/* =========================
   API
   ========================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    return res.json({
      status: "ok",
      service: "Mirage_Site backend",
      database: "connected",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      status: "error",
      service: "Mirage_Site backend",
      database: "disconnected",
    });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const userId = req.auth.sub;

    const userRes = await pool.query(
      "SELECT id, email, role, first_name, last_name, created_at FROM users WHERE id = $1",
      [userId]
    );

    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.json({
      user: userRes.rows[0],
      role: req.auth.role,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/chat/history", async (req, res) => {
  try {
    const sessionId = req.chatSessionId;

    const result = await pool.query(
      `SELECT id, sender, message, created_at
       FROM chat_messages
       WHERE session_id = $1
       ORDER BY created_at ASC
       LIMIT 50`,
      [sessionId]
    );

    return res.json({
      session_id: sessionId,
      items: result.rows,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "chat history error" });
  }
});

app.post("/api/chat/send", async (req, res) => {
  try {
    const sessionId = req.chatSessionId;
    const message = String(req.body.message || "").trim();

    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }

    if (message.length > 2000) {
      return res.status(400).json({ error: "message too long" });
    }

    const insertRes = await pool.query(
      `INSERT INTO chat_messages (session_id, sender, message)
       VALUES ($1, 'user', $2)
       RETURNING id, sender, message, created_at`,
      [sessionId, message]
    );

    return res.json({ ok: true, item: insertRes.rows[0] });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "chat send error" });
  }
});

app.get("/api/admin/ping", requireAuth, requireRole("admin"), (req, res) => {
  return res.json({ ok: true, message: "admin access granted" });
});

/* =========================
   AUTH
   ========================= */

app.post("/auth/register", async (req, res) => {
  try {
    const nextUrl = safeNextUrl(req.query.next, "/auth?registered=1");

    const firstName = String(req.body.first_name || "").trim();
    const lastName = String(req.body.last_name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!firstName || !lastName) {
      return res.status(400).send("First name and last name are required.");
    }

    if (!email || !password) {
      return res.status(400).send("Email and password are required.");
    }

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
    if (!emailOk) {
      return res.status(400).send("Please enter a valid email address.");
    }

    const passwordPolicy =
      /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%])[A-Za-z\d!@#$%]{8,}$/;

    if (!passwordPolicy.test(password)) {
      return res.status(400).send(
        "Password must be at least 8 characters long and include one uppercase letter, one number, and one special character (! @ # $ %)."
      );
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).send("User already exists.");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (email, password_hash, first_name, last_name)
       VALUES ($1, $2, $3, $4)`,
      [email, passwordHash, firstName, lastName]
    );

    if (nextUrl.startsWith("/auth?")) {
      return res.redirect(nextUrl);
    }

    return res.redirect("/auth?registered=1");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Server error.");
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const nextUrl = safeNextUrl(req.query.next, "/profile");

    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).send("Email and password are required.");
    }

    const userRes = await pool.query(
      "SELECT id, email, password_hash, role FROM users WHERE email = $1",
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).send("Invalid credentials.");
    }

    const user = userRes.rows[0];
    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      return res.status(401).send("Invalid credentials.");
    }

    const token = jwt.sign(
      {
        sub: String(user.id),
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("access_token", token, {
      ...getCookieOptions(),
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.redirect(nextUrl);
  } catch (error) {
    console.error(error);
    return res.status(500).send("Server error.");
  }
});

app.get("/auth/logout", (req, res) => {
  const nextUrl = safeNextUrl(req.query.next, "/auth?logout=1");

  res.clearCookie("access_token", getCookieOptions());

  return res.redirect(nextUrl);
});

app.post("/api/me/delete", requireAuth, async (req, res) => {
  try {
    const userId = req.auth.sub;
    const password = String(req.body.password || "");

    if (!password) {
      return res.status(400).send("Password is required to delete the account.");
    }

    const userRes = await pool.query(
      "SELECT id, password_hash FROM users WHERE id = $1",
      [userId]
    );

    if (userRes.rows.length === 0) {
      res.clearCookie("access_token", getCookieOptions());
      return res.status(404).send("User not found.");
    }

    const user = userRes.rows[0];
    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      return res.status(401).send("Wrong password.");
    }

    await pool.query("DELETE FROM users WHERE id = $1", [userId]);

    res.clearCookie("access_token", getCookieOptions());

    return res.redirect("/auth?deleted=1");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Server error.");
  }
});

/* =========================
   DEBUG
   ========================= */

app.get("/debug/jwt", (req, res) => {
  return res.json({
    tokenExists: Boolean(req.cookies?.access_token),
    cookieNames: Object.keys(req.cookies || {}),
  });
});

/* =========================
   404
   ========================= */

app.use((req, res) => {
  res.status(404).send("404 Not Found");
});

module.exports = app;