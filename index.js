import express from "express";
import pg from "pg";
import cors from "cors";
import dotenv from "dotenv";
import { Server } from "socket.io";
import { createServer } from "http";
import { authMiddleware } from "./middlewares/auth.js";
import jwkToPem from "jwk-to-pem";
import crypto from "crypto";

dotenv.config();

const app = express();
const { Pool } = pg;
const httpServer = createServer(app);

app.use(
  cors({
    origin: [
      "https://localhost:3000", // para desarrollo local
      "https://symbionet-phi.vercel.app",
    ],
    credentials: true,
  })
);

const io = new Server(httpServer, {
  cors: {
    origin: ["https://localhost:3000", "https://symbionet-phi.vercel.app"],
    credentials: true,
  },
});

// Map para guardar userId y socketId
const connectedUsers = new Map();

io.on("connection", (socket) => {
  console.log("Cliente conectado:", socket.id);

  socket.on("registerUser", (userId) => {
    connectedUsers.set(userId, socket.id);
    console.log(`Registrado usuario ${userId} con socket ${socket.id}`);
  });

  socket.on("disconnect", () => {
    console.log("Cliente desconectado:", socket.id);
    for (const [userId, socketId] of connectedUsers.entries()) {
      if (socketId === socket.id) {
        connectedUsers.delete(userId);
        break;
      }
    }
  });
});

const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.use(express.json());

app.get("/", (req, res) => {
  res.send("SymbioNet backend is running");
});

// PARTE DE NORMALIZACIONES EN ENCRIPTACIONES -------------------------------------------------------------------------------------

// Función para garantizar la normalización del JWK
function normalizeJwk(jwk) {
  const ordered = {};
  Object.keys(jwk)
    .sort()
    .forEach((key) => {
      ordered[key] = jwk[key];
    });
  return JSON.stringify(ordered);
}

// PARTE DEL REGISTRO DEL USUARIO -------------------------------------------------------------------------------------------------

// Registrar usuario con clave pública
// Genera los 4 números para el user
function generate4DigitNumber() {
  const num = Math.floor(Math.random() * 10000);
  return num.toString().padStart(4, "0");
}

// Genera un user-XXXX único
async function generateUniqueUserNumber() {
  const usedNumbersRes = await pool.query(
    "SELECT SUBSTRING(username FROM 6 FOR 4) AS num FROM users WHERE username LIKE 'user-%'"
  );

  const usedNumbers = new Set(usedNumbersRes.rows.map((r) => r.num));

  let tries = 0;
  while (tries < 10000) {
    const candidate = generate4DigitNumber();
    if (!usedNumbers.has(candidate)) return `user-${candidate}`;
    tries++;
  }
  throw new Error("No hay números disponibles para user-XXXX");
}

// Registrar usuario con clave pública
app.post("/register", async (req, res) => {
  let { username, public_key, captchaQuestion, captchaAnswer } = req.body;

  // 1. Validación del CAPTCHA
  if (
    typeof captchaQuestion !== "string" ||
    typeof captchaAnswer === "undefined"
  ) {
    return res.status(400).json({ error: "CAPTCHA inválido" });
  }

  // Extrae los números y el operador de la pregunta del tipo "¿Cuánto es X + Y?" o "¿Cuánto es X - Y?"
  const match = captchaQuestion.match(/¿Cuánto es (\d+) ([+-]) (\d+)\?/);
  if (!match) {
    return res.status(400).json({ error: "Formato de pregunta inválido" });
  }
  const num1 = parseInt(match[1], 10);
  const operator = match[2];
  const num2 = parseInt(match[3], 10);

  let expectedAnswer;
  if (operator === "+") expectedAnswer = num1 + num2;
  else expectedAnswer = num1 - num2;

  if (parseInt(captchaAnswer, 10) !== expectedAnswer) {
    return res.status(400).json({ error: "Respuesta incorrecta al CAPTCHA" });
  }

  if (username && typeof username !== "string") {
    return res.status(400).json({ error: "Username inválido" });
  }

  if (username) {
    username = username.trim();
    if (username === "") username = null;
  }

  let finalUsername = username;

  if (!finalUsername) {
    try {
      finalUsername = await generateUniqueUserNumber();
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  } else {
    console.log("Verificando existencia de usuario:", finalUsername);

    const exists = await pool.query("SELECT 1 FROM users WHERE username = $1", [
      finalUsername,
    ]);

    console.log("¿Existe usuario?", exists.rowCount > 0);

    if (exists.rowCount > 0) {
      console.log(
        `El username ${finalUsername} ya existe. Generando uno nuevo...`
      );
      try {
        finalUsername = await generateUniqueUserNumber();
      } catch (e) {
        return res.status(500).json({ error: e.message });
      }
    }
  }

  try {
    // 🔧 Normalizamos la clave pública
    const normalizedPublicKey = normalizeJwk(public_key);

    // Guardamos usando la clave pública normalizada
    await pool.query(
      "INSERT INTO users (username, public_key) VALUES ($1, $2)",
      [finalUsername, normalizedPublicKey]
    );

    // Consultamos usando también la clave pública normalizada
    const result = await pool.query(
      "SELECT * FROM users WHERE public_key = $1",
      [normalizedPublicKey]
    );

    res.json({ message: "Usuario registrado", user: result.rows[0] });
  } catch (err) {
    console.error("Error registrando usuario:", err);
    res.status(500).json({ error: "Error registrando usuario" });
  }
});

// PARTE DE VERIFICACIONES PARA ENDPOINTS O FUNCIONES -----------------------------------------------------------------------------

// Función clave para verificar ECDSA con P-256
async function verifySignature(message, signatureBase64, publicKeyJwk) {
  try {
    const publicKeyPem = jwkToPem(publicKeyJwk);
    const verify = crypto.createVerify("SHA256");
    verify.update(message);
    verify.end();
    const signature = Buffer.from(signatureBase64, "base64");
    const isValid = verify.verify(publicKeyPem, signature);
    console.log("Firma válida:", isValid);
    return isValid;
  } catch (e) {
    console.error("Error verificando firma:", e);
    return false;
  }
}

// Middleware simple de autenticación básica para admin
function checkAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return res.status(401).json({ error: "No autorizado" });
  }

  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii"
  );
  const [username, password] = credentials.split(":");

  if (username === "admin" && password === "admin") {
    next();
  } else {
    return res.status(403).json({ error: "Credenciales inválidas" });
  }
}

// PARTE DE GESTIÓN POR PARTE DEL USUARIO DE SU PERFIL ----------------------------------------------------------------------------

// Opción de que el usuario pueda cambiar su nombre.
app.put("/username", async (req, res) => {
  const body = req.body || {}; // fallback seguro
  const { newUsername, public_key } = body;

  if (!newUsername || !public_key) {
    return res.status(400).json({ error: "Faltan parámetros" });
  }

  const trimmedUsername = newUsername.trim();

  if (trimmedUsername === "") {
    return res
      .status(400)
      .json({ error: "El nuevo nombre no puede estar vacío" });
  }

  try {
    const existing = await pool.query(
      "SELECT 1 FROM users WHERE username = $1",
      [trimmedUsername]
    );
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: "El nombre ya está en uso" });
    }

    const publicKeyString = normalizeJwk(public_key);

    const result = await pool.query(
      "UPDATE users SET username = $1 WHERE public_key = $2 RETURNING *",
      [trimmedUsername, publicKeyString]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ message: "Nombre actualizado", user: result.rows[0] });
  } catch (err) {
    console.error("Error cambiando username:", err);
    res.status(500).json({ error: "Error cambiando el nombre" });
  }
});

// Opción de que el usuario puede publicar un post.
app.post("/post", async (req, res) => {
  const { message, signature, publicKey } = req.body;
  console.log("Recibido en /post:", { message, signature, publicKey });

  if (!message || !signature || !publicKey) {
    return res.status(400).json({ error: "Faltan parámetros" });
  }

  try {
    const valid = await verifySignature(message, signature, publicKey);
    console.log("Firma válida:", valid);
    if (!valid) return res.status(401).json({ error: "Firma inválida" });

    const publicKeyString = normalizeJwk(publicKey);

    const result = await pool.query(
      `INSERT INTO posts (content, author_public_key, created_at)
   VALUES ($1, $2, NOW()) RETURNING *`,
      [message, publicKeyString]
    );

    res.json({ post: result.rows[0] });
  } catch (error) {
    console.error("Error en /post:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Opción de que el usuario pueda eliminar sus posts.
app.delete("/posts/:id", async (req, res) => {
  const postId = req.params.id;
  const { public_key } = req.body;
  if (!public_key) {
    return res.status(400).json({ error: "Clave pública requerida" });
  }

  // Normaliza aquí:
  const publicKeyString =
    typeof public_key === "string" ? public_key : normalizeJwk(public_key);

  try {
    const result = await pool.query("SELECT * FROM posts WHERE id = $1", [
      postId,
    ]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Post no encontrado" });
    }
    const post = result.rows[0];

    // Compara usando la clave normalizada
    if (post.author_public_key !== publicKeyString) {
      return res
        .status(403)
        .json({ error: "No autorizado para borrar este post" });
    }

    // Elimina el post
    const deleteResult = await pool.query(
      "DELETE FROM posts WHERE id = $1 RETURNING *",
      [postId]
    );
    res.json({ message: "Post eliminado", post: deleteResult.rows[0] });
  } catch (err) {
    console.error("Error eliminando post:", err);
    res.status(500).json({ error: "Error eliminando post" });
  }
});

// PARTE DE OBTENCIÓN DE DATOS ----------------------------------------------------------------------------------------------------

// Obtener datos del usuario con clave pública.
app.post("/me", async (req, res) => {
  const { public_key } = req.body;

  if (!public_key) {
    return res.status(400).json({ error: "Clave pública requerida" });
  }

  try {
    const publicKeyString = normalizeJwk(public_key);

    const result = await pool.query(
      "SELECT * FROM users WHERE public_key = $1",
      [publicKeyString]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Error en /me:", err);
    res.status(500).json({ error: "Error al obtener usuario" });
  }
});

// Obtener los usuarios para visualización pública.
app.get("/users", async (req, res) => {
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

// Obtener todos los posts (para Home).
app.get("/postshome", async (req, res) => {
  try {
    const result = await pool.query(`
  SELECT posts.*, users.username
  FROM posts
  JOIN users ON posts.author_public_key = users.public_key
  ORDER BY posts.created_at DESC
`);
    res.json({ posts: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo posts" });
  }
});

// Obtener posts de un usuario (para Profile).
app.post("/postsuser", async (req, res) => {
  console.log("BODY RECIBIDO EN /postsuser:", req.body);
  const { public_key } = req.body;
  if (!public_key)
    return res.status(400).json({ error: "Clave pública requerida" });

  try {
    const publicKeyString = normalizeJwk(public_key);

    const result = await pool.query(
      "SELECT * FROM posts WHERE author_public_key = $1 ORDER BY created_at DESC",
      [publicKeyString]
    );

    res.json({ posts: result.rows });
  } catch (err) {
    console.error("Error en POST /posts:", err);
    res.status(500).json({ error: "Error al obtener posts del usuario" });
  }
});

// Obtener usuarios por id
app.get("/user/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "SELECT id, username, public_key FROM users WHERE id = $1",
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error al obtener usuario:", err);
    res.status(500).json({ error: "Error al obtener usuario" });
  }
});

// PARTE DEL /admin PARA ADMINISTRAR LA PAGINA ------------------------------------------------------------------------------------

// Ruta protegida que devuelve todos los usuarios y posts
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

// Eliminar usuario (admin)
app.delete("/admin/users/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const deletedUser = result.rows[0];

    // Emitimos a TODOS que ese usuario fue eliminado (para que lo manejen en frontend)
    io.emit("userDeleted", deletedUser.id);

    // Si queremos desconectar o limpiar algo del socket, lo hacemos aquí
    const socketId = connectedUsers.get(deletedUser.id);
    if (socketId) {
      connectedUsers.delete(deletedUser.id);
      // Desconecta el socket del usuario eliminado
      io.sockets.sockets.get(socketId)?.disconnect();
    }

    res.json({ success: true, deletedUser });
  } catch (error) {
    console.error("Error eliminando usuario:", error);
    res.status(500).json({ error: "Error eliminando usuario" });
  }
});

// Eliminar posts (admin)
app.delete("/admin/posts/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "DELETE FROM posts WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Post no encontrado" });
    }
    res.json({ success: true, deletedPost: result.rows[0] });
  } catch (error) {
    console.error("Error eliminando post:", error);
    res.status(500).json({ error: "Error eliminando post" });
  }
});

// SALIDA DEL BACK HACIA EL PUERTO ------------------------------------------------------------------------------------------------
const PORT = process.env.PORT || 4000;
httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
