const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");
const express = require("express");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

const { cow } = require("../shared/cow");

dotenv.config({ path: path.resolve(process.cwd(), ".env") });

const app = express();
app.use(express.json());

const ROOT = process.cwd();
const readFile = (relPath) => fs.readFileSync(path.resolve(ROOT, relPath));

const {
  BACKEND_A_KEY_PATH,
  BACKEND_A_CERT_PATH,
  CA_CERT_PATH,
  BACKEND_A_HTTPS_PORT = "8443",
  BACKEND_A_HTTP_PORT = "8080",
  JWT_PUBLIC_KEY_PATH,
  JWT_ISSUER,
  JWT_AUDIENCE,
} = process.env;

if (!BACKEND_A_KEY_PATH || !BACKEND_A_CERT_PATH || !CA_CERT_PATH || !JWT_PUBLIC_KEY_PATH) {
  throw new Error("Faltan variables de entorno para Backend A.");
}

function requireJwtRole(requiredRole) {
  const publicKey = fs.readFileSync(path.resolve(ROOT, JWT_PUBLIC_KEY_PATH), "utf8");

  return (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
      return res
        .status(401)
        .type("text/plain")
        .send(cow("JWT FALLO", "Falta el header Authorization: Bearer <token>."));
    }

    try {
      const payload = jwt.verify(token, publicKey, {
        algorithms: ["RS256"],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });

      const roles = Array.isArray(payload.roles) ? payload.roles : [];
      if (!roles.includes(requiredRole)) {
        return res
          .status(403)
          .type("text/plain")
          .send(cow("JWT FALLO", `Rol insuficiente. Se requiere: ${requiredRole}.`));
      }

      req.jwt = payload;
      next();
    } catch (error) {
      return res
        .status(401)
        .type("text/plain")
        .send(cow("JWT INVALIDO", `Token rechazado: ${error.message}`));
    }
  };
}

app.get("/", (req, res) => {
  res.type("text/plain").send(cow("TLS OK", "Autenticacion correcta TLS en Backend A."));
});

app.get("/secure", requireJwtRole("backend-a"), (req, res) => {
  res
    .type("text/plain")
    .send(cow("TLS + JWT OK", `Backend A acepto el JWT. Usuario: ${req.jwt.sub}`));
});

http
  .createServer((req, res) => {
    res.writeHead(301, {
      Location: `https://localhost:${BACKEND_A_HTTPS_PORT}${req.url}`,
    });
    res.end(cow("REDIRECCION", "Este servicio solo usa HTTPS."));
  })
  .listen(Number(BACKEND_A_HTTP_PORT), () => {
    console.log(`Backend A HTTP redirect en http://localhost:${BACKEND_A_HTTP_PORT}`);
  });

const httpsOptions = {
  key: readFile(BACKEND_A_KEY_PATH),
  cert: readFile(BACKEND_A_CERT_PATH),
  ca: readFile(CA_CERT_PATH),
  minVersion: "TLSv1.2",
};

https.createServer(httpsOptions, app).listen(Number(BACKEND_A_HTTPS_PORT), () => {
  console.log(`Backend A HTTPS en https://localhost:${BACKEND_A_HTTPS_PORT}`);
});
