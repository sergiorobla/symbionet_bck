// index.js mejorado con Refresh Tokens, seguridad JWT, rate limiting, helmet y validaciones

import express from "express";
import pg from "pg";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import { Server } from "socket.io";
import { createServer } from "http";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import jwkToPem from "jwk-to-pem";
import {
  jwtAuthMiddleware as authMiddleware,
  checkAdminAuth,
} from "./middlewares/auth.js";

dotenv.config();

const app = express();
const { Pool } = pg;
const httpServer = createServer(app);
const JWT_SECRET = process.env.JWT_SECRET || "mi_clave_secreta_super_segura";

// Seguridad
app.use(helmet());
app.use(cookieParser());

// Rate limiting global
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// CORS seguro
app.use(
  cors({
    origin: ["https://localhost:3000", "https://symbi-brown.vercel.app"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Socket.IO
const io = new Server(httpServer, {
  cors: {
    origin: ["https://localhost:3000", "https://symbi-brown.vercel.app"],
    credentials: true,
  },
});

app.use(express.json());

const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
  ssl: { rejectUnauthorized: false },
});

const connectedUsers = new Map();

// Socket handlers
io.on("connection", (socket) => {
  socket.on("registerUser", (userId) => {
    connectedUsers.set(userId, socket.id);
  });

  socket.on("disconnect", () => {
    for (const [userId, socketId] of connectedUsers.entries()) {
      if (socketId === socket.id) {
        connectedUsers.delete(userId);
        break;
      }
    }
  });
});

// Utils
function normalizeJwk(jwk) {
  const ordered = {};
  Object.keys(jwk)
    .sort()
    .forEach((k) => (ordered[k] = jwk[k]));
  return JSON.stringify(ordered);
}

async function findUserByPublicKey(jwk) {
  const normalized = normalizeJwk(jwk);
  const result = await pool.query("SELECT * FROM users WHERE public_key = $1", [
    normalized,
  ]);
  return result.rows[0];
}

function generate4DigitNumber() {
  return Math.floor(Math.random() * 10000)
    .toString()
    .padStart(4, "0");
}

async function generateUniqueUserNumber() {
  const res = await pool.query(
    "SELECT SUBSTRING(username FROM 6 FOR 4) AS num FROM users WHERE username LIKE 'user-%'"
  );
  const used = new Set(res.rows.map((r) => r.num));
  let tries = 0;
  while (tries < 10000) {
    const candidate = generate4DigitNumber();
    if (!used.has(candidate)) return `user-${candidate}`;
    tries++;
  }
  throw new Error("No hay números disponibles");
}

async function verifySignature(message, signatureBase64, publicKeyJwk) {
  try {
    const publicKeyPem = jwkToPem(publicKeyJwk);
    const verify = crypto.createVerify("SHA256");
    verify.update(message);
    verify.end();
    const signature = Buffer.from(signatureBase64, "base64");
    return verify.verify(publicKeyPem, signature);
  } catch (e) {
    console.error("Error verificando firma:", e);
    return false;
  }
}

function generateAccessToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, process.env.REFRESH_SECRET, { expiresIn: "7d" });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token requerido" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Si la ruta recibe public_key o publicKey en el body, compárala con la del token
    if (req.body?.public_key) {
      const bodyKey = normalizeJwk(req.body.public_key);
      if (bodyKey !== decoded.public_key) {
        return res.status(403).json({
          error: "No autorizado: clave pública no coincide con el token",
        });
      }
    }
    if (req.body?.publicKey) {
      const bodyKey = normalizeJwk(req.body.publicKey);
      if (bodyKey !== decoded.public_key) {
        return res.status(403).json({
          error: "No autorizado: clave pública no coincide con el token",
        });
      }
    }
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// ------------------ RUTAS ------------------
app.get("/", (req, res) => {
  res.send("SymbioNet backend con refresh token funcionando.");
});

app.post(
  "/register",
  [
    body("public_key").notEmpty(),
    body("captchaQuestion").isString(),
    body("captchaAnswer").isNumeric(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    let { username, public_key, captchaQuestion, captchaAnswer } = req.body;

    const match = captchaQuestion.match(/¿Cuánto es (\d+) ([+-]) (\d+)\?/);
    if (!match) {
      return res.status(400).json({ error: "CAPTCHA inválido" });
    }

    const expected =
      match[2] === "+" ? +match[1] + +match[3] : +match[1] - +match[3];
    if (+captchaAnswer !== expected) {
      return res.status(400).json({ error: "Respuesta CAPTCHA incorrecta" });
    }

    try {
      // Validación o generación de username
      if (!username || username.trim() === "") {
        username = await generateUniqueUserNumber();
      } else {
        const exists = await pool.query(
          "SELECT 1 FROM users WHERE username = $1",
          [username]
        );
        if (exists.rowCount > 0) {
          username = await generateUniqueUserNumber();
        }
      }

      const normalizedKey = normalizeJwk(public_key);

      // Guardar en DB
      await pool.query(
        "INSERT INTO users (username, public_key) VALUES ($1, $2)",
        [username, normalizedKey]
      );

      const result = await pool.query(
        "SELECT * FROM users WHERE public_key = $1",
        [normalizedKey]
      );
      const user = result.rows[0];

      // ✅ Generar tokens
      const accessToken = generateAccessToken({
        username: user.username,
        public_key: normalizedKey,
      });
      const refreshToken = generateRefreshToken({
        username: user.username,
        public_key: normalizedKey,
      });

      console.log("✅ Generado accessToken:", accessToken);
      console.log("✅ Generado refreshToken:", refreshToken);

      // ✅ Enviar token + cookie
      res
        .cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          path: "/refresh",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        .json({
          message: "Usuario registrado",
          user,
          accessToken, // <- aquí es donde el frontend lo espera
        });
    } catch (err) {
      console.error("❌ Error en /register:", err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  }
);

app.post("/refresh", (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token)
    return res.status(401).json({ error: "Token de actualización requerido" });

  try {
    const payload = jwt.verify(token, process.env.REFRESH_SECRET);
    // Busca la clave pública del usuario en la base de datos
    pool
      .query("SELECT public_key FROM users WHERE username = $1", [
        payload.username,
      ])
      .then((userRes) => {
        const userPublicKey = userRes.rows[0]?.public_key;
        const newAccessToken = generateAccessToken({
          username: payload.username,
          public_key: userPublicKey,
        });
        res.json({ accessToken: newAccessToken });
      })
      .catch((err) => {
        res.status(500).json({ error: "Error obteniendo clave pública" });
      });
  } catch {
    return res.status(403).json({ error: "Refresh token inválido" });
  }
});

// Publicar post (requiere token y firma válida)
app.post(
  "/post",
  verifyToken,
  [
    body("message").isString().notEmpty(),
    body("signature").isString(),
    body("publicKey").notEmpty(),
  ],
  async (req, res) => {
    const { message, signature, publicKey } = req.body;

    try {
      const valid = await verifySignature(message, signature, publicKey);
      if (!valid) return res.status(401).json({ error: "Firma inválida" });

      const publicKeyString = normalizeJwk(publicKey);
      const result = await pool.query(
        `INSERT INTO posts (content, author_public_key, created_at)
       VALUES ($1, $2, NOW()) RETURNING *`,
        [message, publicKeyString]
      );

      res.json({ post: result.rows[0] });
    } catch (err) {
      console.error("Error en /post:", err);
      res.status(500).json({ error: "Error interno" });
    }
  }
);

// Eliminar post (requiere token)
app.delete("/posts/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { public_key } = req.body;

  if (!public_key)
    return res.status(400).json({ error: "Clave pública requerida" });

  const publicKeyString =
    typeof public_key === "string" ? public_key : normalizeJwk(public_key);
  try {
    const postRes = await pool.query("SELECT * FROM posts WHERE id = $1", [id]);
    if (postRes.rowCount === 0)
      return res.status(404).json({ error: "Post no encontrado" });

    if (postRes.rows[0].author_public_key !== publicKeyString)
      return res.status(403).json({ error: "No autorizado" });

    await pool.query("DELETE FROM posts WHERE id = $1", [id]);
    res.json({ message: "Post eliminado" });
  } catch (err) {
    console.error("Error eliminando post:", err);
    res.status(500).json({ error: "Error eliminando post" });
  }
});

// Obtener datos del perfil del usuario autenticado
app.post("/me", verifyToken, async (req, res) => {
  const { public_key } = req.body;
  if (!public_key)
    return res.status(400).json({ error: "Clave pública requerida" });

  try {
    const publicKeyString = normalizeJwk(public_key);
    const result = await pool.query(
      "SELECT * FROM users WHERE public_key = $1",
      [publicKeyString]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Usuario no encontrado" });

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Error en /me:", err);
    res.status(500).json({ error: "Error al obtener usuario" });
  }
});

// Cambiar nombre de usuario
app.put(
  "/username",
  verifyToken,
  [body("newUsername").isString().notEmpty(), body("public_key").notEmpty()],
  async (req, res) => {
    const { newUsername, public_key } = req.body;

    try {
      const existing = await pool.query(
        "SELECT 1 FROM users WHERE username = $1",
        [newUsername.trim()]
      );
      if (existing.rowCount > 0)
        return res.status(409).json({ error: "El nombre ya está en uso" });

      const publicKeyString = normalizeJwk(public_key);
      const result = await pool.query(
        "UPDATE users SET username = $1 WHERE public_key = $2 RETURNING *",
        [newUsername.trim(), publicKeyString]
      );

      if (result.rowCount === 0)
        return res.status(404).json({ error: "Usuario no encontrado" });

      res.json({ message: "Nombre actualizado", user: result.rows[0] });
    } catch (err) {
      console.error("Error actualizando nombre:", err);
      res.status(500).json({ error: "Error actualizando nombre" });
    }
  }
);

// Obtener todos los usuarios públicos
app.get("/users", verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, username, reputation FROM users"
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /users:", err);
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

// Obtener todos los posts para home
app.get("/postshome", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT posts.*, users.username
      FROM posts
      JOIN users ON posts.author_public_key = users.public_key
      ORDER BY posts.created_at DESC
    `);
    res.json({ posts: result.rows });
  } catch (err) {
    console.error("Error en /postshome:", err);
    res.status(500).json({ error: "Error obteniendo posts" });
  }
});

// Obtener posts de un usuario
app.post(
  "/postsuser",
  verifyToken,
  [body("public_key").notEmpty()],
  async (req, res) => {
    const { public_key } = req.body;
    try {
      const publicKeyString = normalizeJwk(public_key);
      const result = await pool.query(
        "SELECT * FROM posts WHERE author_public_key = $1 ORDER BY created_at DESC",
        [publicKeyString]
      );
      res.json({ posts: result.rows });
    } catch (err) {
      console.error("Error en /postsuser:", err);
      res.status(500).json({ error: "Error al obtener posts" });
    }
  }
);

// Obtener usuario por ID
app.get("/user/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "SELECT id, username, public_key FROM users WHERE id = $1",
      [id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Usuario no encontrado" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error en /user/:id:", err);
    res.status(500).json({ error: "Error al obtener usuario" });
  }
});

// RUTA ADMIN: obtener usuarios y posts
app.get("/admin/data", checkAdminAuth, async (req, res) => {
  try {
    const usersPromise = pool.query(
      "SELECT id, username, reputation FROM users"
    );
    const postsPromise = pool.query(`
      SELECT posts.*, users.username
      FROM posts
      JOIN users ON posts.author_public_key = users.public_key
      ORDER BY posts.created_at DESC
    `);
    const [usersRes, postsRes] = await Promise.all([
      usersPromise,
      postsPromise,
    ]);
    res.json({
      users: usersRes.rows,
      posts: postsRes.rows,
    });
  } catch (err) {
    console.error("Error en /admin/data:", err);
    res.status(500).json({ error: "Error interno" });
  }
});

// RUTA ADMIN: eliminar usuario
app.delete("/admin/users/:id", checkAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Usuario no encontrado" });

    const deletedUser = result.rows[0];

    io.emit("userDeleted", deletedUser.id);
    const socketId = connectedUsers.get(deletedUser.id);
    if (socketId) {
      connectedUsers.delete(deletedUser.id);
      io.sockets.sockets.get(socketId)?.disconnect();
    }

    res.json({ success: true, deletedUser });
  } catch (err) {
    console.error("Error eliminando usuario:", err);
    res.status(500).json({ error: "Error eliminando usuario" });
  }
});

// RUTA ADMIN: eliminar post
app.delete("/admin/posts/:id", checkAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "DELETE FROM posts WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Post no encontrado" });

    res.json({ success: true, deletedPost: result.rows[0] });
  } catch (err) {
    console.error("Error eliminando post:", err);
    res.status(500).json({ error: "Error eliminando post" });
  }
});

// Login usuario
app.post("/login", async (req, res) => {
  try {
    const { public_key } = req.body;
    const user = await findUserByPublicKey(public_key);

    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ user, accessToken });
  } catch (err) {
    console.error("Error en /login:", err);
    res.status(500).json({ error: "Error interno en login" });
  }
});

const PORT = process.env.PORT || 4000;
httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
