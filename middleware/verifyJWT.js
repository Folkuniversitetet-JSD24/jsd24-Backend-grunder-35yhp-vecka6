import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();        // Ladda miljövariabler från .env-filen

// Middleware för att verifiera JWT-token
export default function verifyJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    // Kontrollera att token skickas med
    if (!authHeader) {
        return res.status(401).json({error: "JWT-token saknas!"})
    }

    const token = authHeader.split(" ")[1];

    // Verifiera token med jwt biblioteket
    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
        // Om verifieringen misslyckades(exempel om den är ogiltig eller utgången)
        if (err) {
            return res.status(403).json({error: "JWT-token är ogiltig eller är utgången."})
        }

        res.user = payload;

        next();
    });
};

