const jwt = require("jsonwebtoken");
const { readText } = require("./tls");
const { cow } = require("./cow");

function issueJwt({ privateKeyPath, subject, roles, issuer, audience, expiresIn }) {
  const privateKey = readText(privateKeyPath);

  return jwt.sign(
    {
      sub: subject,
      roles,
    },
    privateKey,
    {
      algorithm: "RS256",
      issuer,
      audience,
      expiresIn,
      keyid: "jwt-rsa-1",
    },
  );
}

function requireJwtRole({ publicKeyPath, requiredRole, issuer, audience }) {
  const publicKey = readText(publicKeyPath);

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
        issuer,
        audience,
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

module.exports = {
  issueJwt,
  requireJwtRole,
};
