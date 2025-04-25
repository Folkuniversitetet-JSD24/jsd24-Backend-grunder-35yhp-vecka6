import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import verifyJWT from "./middleware/verifyJWT.js";

dotenv.config(); // Ladda miljövariabler från .env-filen

const app = express();
app.use(express.json());

let users = [];

// POST route för att regga en ny användare och använda bcrypt för att hasha lösenordet
app.post("/register", async (req, res) => {
  const { userName, password } = req.body;

  // const saltRounds = 12;

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ userName, password: hashedPassword });

  res.status(201).json({ message: "Ny användare är registrerad i databasen." });
});

// POST för att logga in med JWT- och bcrypt-verfieringar
app.post("/login", async (req, res) => {
  const { userName, password } = req.body;

  const user = users.find((u) => u.userName === userName);

  if (!user) {
    await bcrypt.compare(
      password,
      "$2b$10$invalidsaltpaddinghaxhaxhax12345678901234567890Mandus"
    );

    return res.status(401).json({ error: "Fel användarnamn eller lösenord." });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match)
    return res.status(401).json({ error: "Fel användarnamn eller lösenord." });

  // Skapa en JWT-token till användaren med hens namn i payload
  const token = jwt.sign({ userName }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION,
  });

  res.status(200).json({ token });
});

// GET för en skyddad route som kräver en JWT-token via vårt verifyJWT middleware
app.get("/protected", verifyJWT, (req, res) => {
  res.json({ message: " Välkommen till den skydda icke public routen." });
});

// Starta och lyssna på vår server.

app.listen(8765, () => console.log("server körs på http://localhost:8765"));
