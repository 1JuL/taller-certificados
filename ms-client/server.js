const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

const { cow } = require("../shared/cow");

dotenv.config({ path: path.resolve(process.cwd(), ".env") });

const app = express();
app.use(express.json());

const ROOT = process.cwd();
const readFile = (relPath) => fs.readFileSync(path.resolve(ROOT, relPath));
const readText = (relPath) => fs.readFileSync(path.resolve(ROOT, relPath), "utf8");

const {
  CLIENT_PORT = "3000",
  CA_CERT_PATH,
  CLIENT_KEY_PATH,
  CLIENT_CERT_PATH,
  JWT_PRIVATE_KEY_PATH,
  JWT_ISSUER,
  JWT_AUDIENCE,
  JWT_EXPIRES_IN = "15m",
  BACKEND_A_URL = "https://localhost:8443",
  BACKEND_B_URL = "https://localhost:9443",
} = process.env;

if (!CA_CERT_PATH || !CLIENT_KEY_PATH || !CLIENT_CERT_PATH || !JWT_PRIVATE_KEY_PATH) {
  throw new Error("Faltan variables de entorno para MS Cliente.");
}

function issueJwt(role, subject) {
  const privateKey = readText(JWT_PRIVATE_KEY_PATH);

  return jwt.sign(
    {
      sub: subject,
      roles: [role],
    },
    privateKey,
    {
      algorithm: "RS256",
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      expiresIn: JWT_EXPIRES_IN,
      keyid: "jwt-rsa-1",
    },
  );
}

const tlsAgent = new https.Agent({
  ca: readFile(CA_CERT_PATH),
  rejectUnauthorized: true,
  minVersion: "TLSv1.2",
});

const mtlsAgent = new https.Agent({
  ca: readFile(CA_CERT_PATH),
  key: readFile(CLIENT_KEY_PATH),
  cert: readFile(CLIENT_CERT_PATH),
  rejectUnauthorized: true,
  minVersion: "TLSv1.2",
});

app.get("/", (req, res) => {
  res
    .type("text/plain")
    .send(cow("CLIENTE", "MS Cliente activo. Usa /token, /call/backend-a o /call/backend-b."));
});

app.get("/token/backend-a", (req, res) => {
  const token = issueJwt("backend-a", "cliente-demo");
  res.json({ token });
});

app.get("/token/backend-b", (req, res) => {
  const token = issueJwt("backend-b", "cliente-demo");
  res.json({ token });
});

app.get("/call/backend-a", async (req, res) => {
  const token = issueJwt("backend-a", "cliente-demo");

  try {
    const response = await axios.get(`${BACKEND_A_URL}/secure`, {
      httpsAgent: tlsAgent,
      headers: { Authorization: `Bearer ${token}` },
      timeout: 8000,
      proxy: false,
    });

    res.type("text/plain").send(cow("CLIENTE OK", `Respuesta de Backend A:\n\n${response.data}`));
  } catch (error) {
    const detail = error.response?.data || error.message;
    res
      .status(500)
      .type("text/plain")
      .send(cow("CLIENTE FALLO", `Error consumiendo Backend A:\n\n${detail}`));
  }
});

app.get("/call/backend-b", async (req, res) => {
  const token = issueJwt("backend-b", "cliente-demo");

  try {
    const response = await axios.get(`${BACKEND_B_URL}/secure`, {
      httpsAgent: mtlsAgent,
      headers: { Authorization: `Bearer ${token}` },
      timeout: 8000,
      proxy: false,
    });

    res.type("text/plain").send(cow("CLIENTE OK", `Respuesta de Backend B:\n\n${response.data}`));
  } catch (error) {
    const detail = error.response?.data || error.message;
    res
      .status(500)
      .type("text/plain")
      .send(cow("CLIENTE FALLO", `Error consumiendo Backend B:\n\n${detail}`));
  }
});

app.listen(Number(CLIENT_PORT), () => {
  console.log(`MS Cliente en http://localhost:${CLIENT_PORT}`);
});
