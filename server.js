import express from "express";
import  jwt from 'jsonwebtoken';
import  dotenv  from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

// Låtsas databas
const users = [
    {id: 1, userName: "Mandus", password: "1234", role: "admin"},
    {id: 2, userName: "Chatti", password: "abcd", role: "guest"}
];

app.post("/login", (req,res) =>{
    const {userName, password} = req.body;

    const user = users.find((u) => u.userName === userName && u.password === password);

    if (!user) {
        return res.status(401).json({error: "Fel användarnamn eller lösenord"})        
    }

    // Skapa jwt token med användares id och roll som payload
    const token = jwt.sign(
        {userId: user.id, role: user.role},
        process.env.JWT_SECRET,
        {expiresIn: "1h"}
    );

    // Skicka tillbaka jwt token till klienten
    res.json({token});
});

app.get("/secret", (req, res) =>{
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({error: "JWT token saknas!"})      
    }


    const token = authHeader.split(" ")[1];

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);

        res.json({message: "Du är inloggad", user: payload,});
    } catch (error) {
        res.status(403).json({error: "JWT-token är ogiltig."});
    }

})

app.listen(8765, ( ) => console.log("server körs på http://localhost:8765"));