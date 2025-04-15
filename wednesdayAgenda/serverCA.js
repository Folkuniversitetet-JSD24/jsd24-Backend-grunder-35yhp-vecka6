import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

// Simpel "databas" för demo
const users = [{ id: 1, username: "admin", password: "1234", role: "admin" }];

/* LOGIN ROUTE */
// När en användare försöker logga in (POST request)
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Kontrollera användarens inloggningsuppgifter
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user)
    return res.status(401).json({ error: "Fel användarnamn eller lösenord" });

  // Skapa JWT-token med användarens id och roll som payload
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" } // Token giltig 1 timme
  );

  // Skicka JWT tillbaka till klienten
  res.json({ token });
});

// Skyddad route, kräver giltig JWT-token i headern (utan middleware))
app.get("/secret", (req, res) => {
  // Kontrollera att JWT-token skickas med i Authorization-header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    // Skicka felmeddelande om JWT saknas helt (401 Unauthorized)
    return res.status(401).json({ error: "JWT-token saknas." });
  }

  // Token är "Bearer [token]", vi tar ut själva token

  //     Vad gör den? När JWT används i HTTP-headers skickas den vanligen enligt standarden: Authorization: Bearer <JWT-token>
  const token = authHeader.split(" ")[1];
  // Den tar hela header-värdet, t.ex.: "Bearer eyJhbGciOiJIUzI1Ni..." Den delar upp strängen vid mellanslaget (" ") vilket ger en array med två delar: ["Bearer", "eyJhbGciOiJIUzI1Ni..."] Sedan hämtar den andra delen [1], alltså själva token: "eyJhbGciOiJIUzI1Ni..."

  try {
    // Anropar jwt.verify som kollar:
    // 1. Att JWT-token är giltig och korrekt signerad.
    // 2. Att JWT-token inte har gått ut (expired).
    // Om verifieringen lyckas får vi tillbaka "payload", alltså innehållet i JWT:n.
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    res.json({
      message: "Du är inloggad!",
      user: payload, // Innehåller data som userId, username, role, osv.
    });
  } catch (err) {
    // Om token är ogiltig, manipulerad, eller har gått ut så fångas felet här.
    // Då svarar vi med statuskod 403 (Forbidden) och ett tydligt felmeddelande.
    res.status(403).json({ error: "JWT-token är ogiltig." });
  }
});

app.listen(8080, () => console.log("✅ Server körs på http://localhost:8080"));
