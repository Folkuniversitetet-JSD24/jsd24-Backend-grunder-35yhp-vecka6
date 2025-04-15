import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(express.json());

// Enkel användardatabas (en array, endast för demonstration)
let users = [];

// Registrera ny användare (med bcrypt)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Enkel användardatabas (en array, endast för demonstration)
  const hashedPassword = await bcrypt.hash(password, 10); // Hasha lösenordet med bcrypt, "10" är antalet saltningsrundor (standard är 10-12)

  // Spara användaren med hashat lösenord
  users.push({ username, password: hashedPassword });

  res.json({ message: "Användare registrerad!" });
});

// Inloggning med JWT och bcrypt-verifiering
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user) return res.status(401).json({ error: "Användare finns ej." });

  // Jämför det inskickade lösenordet med det hashade lösenordet i databasen
  const match = await bcrypt.compare(password, user.password); // Kolla hash med bcrypt

  if (!match) return res.status(401).json({ error: "Fel lösenord." });

  // Skapa JWT-token med användarens namn i payload
  const token = jwt.sign({ username }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  res.json({ token });
});

// Skyddad route som kräver giltig JWT-token (via middleware)
app.get("/protected", verifyJWT, (req, res) => {
  res.json({ message: `Välkommen, ${req.user.username}!` });
});

app.listen(8080, () => console.log("✅ Server på http://localhost:8080"));
