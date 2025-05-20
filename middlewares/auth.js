// auth.js (backend)

import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "mi_clave_secreta_super_segura";

/**
 * Middleware para rutas protegidas con JWT.
 */
export function jwtAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token requerido" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    console.error("JWT inválido:", err.message);
    return res.status(403).json({ error: "Token inválido" });
  }
}

/**
 * Middleware de autenticación básica para admin.
 */
export function checkAdminAuth(req, res, next) {
  const expectedAuth = `Basic ${Buffer.from("admin:adminpass").toString(
    "base64"
  )}`;
  const auth = req.headers.authorization;

  if (auth !== expectedAuth) {
    return res.status(401).json({ error: "No autorizado" });
  }

  next();
}
