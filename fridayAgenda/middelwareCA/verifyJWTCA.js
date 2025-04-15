import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

// Middleware för att verifiera JWT-token
export function verifyJWT(req, res, next) {
  // Hämta Authorization-headern
  const authHeader = req.headers.authorization;

  // Kontrollera att token finns medskickad
  if (!authHeader) {
    return res.status(401).json({ error: "JWT-token saknas." });
  }

  // Hämta enbart själva token (format: "Bearer [token]")
  const token = authHeader.split(" ")[1];

  // Verifiera token med jwt-biblioteket
  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    // Om verifieringen misslyckas (t.ex. ogiltig eller utgången token)
    if (err) {
      return res
        .status(403)
        .json({ error: "JWT-token är ogiltig eller har gått ut." });
    }

    // Om verifieringen lyckas, spara payloaden (användardata) i req-objektet
    req.user = payload;

    // Fortsätt till nästa middleware/route-handler
    next();
  });
}
