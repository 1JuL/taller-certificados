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
  BACKEND_B_KEY_PATH,
  BACKEND_B_CERT_PATH,
  CA_CERT_PATH,
  BACKEND_B_HTTPS_PORT = "9443",
  BACKEND_B_HTTP_PORT = "9080",
  JWT_PUBLIC_KEY_PATH,
  JWT_ISSUER,
  JWT_AUDIENCE,
} = process.env;

if (!BACKEND_B_KEY_PATH || !BACKEND_B_CERT_PATH || !CA_CERT_PATH || !JWT_PUBLIC_KEY_PATH) {
  throw new Error("Faltan variables de entorno para Backend B.");
}

function requireClientCertificate(req, res, next) {
  if (req.client.authorized) {
    return next();
  }

  const reason = req.client.authorizationError || "El cliente no presento certificado valido";
  return res
    .status(401)
    .type("text/plain")
    .send(cow("mTLS FALLO", `Acceso rechazado. Motivo: ${reason}`));
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

app.get("/", requireClientCertificate, (req, res) => {
  const peer = req.socket.getPeerCertificate?.() || {};
  const cn = peer.subject?.CN || "desconocido";

  res
    .type("text/plain")
    .send(cow("mTLS OK", `Autenticacion correcta mTLS en Backend B. CN cliente: ${cn}`));
});

app.get("/secure", requireClientCertificate, requireJwtRole("backend-b"), (req, res) => {
  const peer = req.socket.getPeerCertificate?.() || {};
  const cn = peer.subject?.CN || "desconocido";

  res
    .type("text/plain")
    .send(
      cow("mTLS + JWT OK", `Backend B acepto certificado cliente (${cn}) y JWT de ${req.jwt.sub}.`),
    );
});

http
  .createServer((req, res) => {
    res.writeHead(301, {
      Location: `https://localhost:${BACKEND_B_HTTPS_PORT}${req.url}`,
    });
    res.end(cow("REDIRECCION", "Backend B solo usa HTTPS/mTLS."));
  })
  .listen(Number(BACKEND_B_HTTP_PORT), () => {
    console.log(`Backend B HTTP redirect en http://localhost:${BACKEND_B_HTTP_PORT}`);
  });

const httpsOptions = {
  key: readFile(BACKEND_B_KEY_PATH),
  cert: readFile(BACKEND_B_CERT_PATH),
  ca: readFile(CA_CERT_PATH),
  requestCert: true,
  rejectUnauthorized: false,
  minVersion: "TLSv1.2",
};

https.createServer(httpsOptions, app).listen(Number(BACKEND_B_HTTPS_PORT), () => {
  console.log(`Backend B mTLS en https://localhost:${BACKEND_B_HTTPS_PORT}`);
});
