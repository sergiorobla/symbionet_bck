export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return res
      .status(401)
      .json({ error: "No autorizado: falta autenticación" });
  }

  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString(
    "ascii"
  );
  const [username, password] = credentials.split(":");

  // Cambia aquí si quieres otro usuario o contraseña
  if (username !== "admin" || password !== "admin") {
    return res.status(403).json({ error: "Credenciales inválidas" });
  }

  next();
}
