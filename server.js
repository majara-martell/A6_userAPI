// server.js
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const jwt = require("jsonwebtoken");
const userService = require("./user-service.js");

const app = express();
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("JWT_SECRET environment variable is not set");
    process.exit(1);
}

const ExtractJWT = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
    jwtFromRequest: ExtractJWT.fromAuthHeaderWithScheme('jwt'),
    secretOrKey: process.env.JWT_SECRET,
};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    if (jwt_payload) {
        done(null, {
            _id: jwt_payload._id,
            userName: jwt_payload.userName
        });
    } else {
        done(null, false);
    }
}));

app.use(passport.initialize());
app.use(cors());
app.use(express.json());

// Initialize database connection
let dbConnected = false;
const initDB = async () => {
    if (!dbConnected) {
        try {
            await userService.connect();
            dbConnected = true;
            console.log("Database connected");
        } catch (err) {
            console.error("Database connection failed:", err);
            throw err;
        }
    }
};

app.post("/api/user/register", async (req, res) => {
    try {
        await initDB();
        const msg = await userService.registerUser(req.body);
        res.json({ message: msg });
    } catch (msg) {
        res.status(422).json({ message: msg });
    }
});

app.post("/api/user/login", async (req, res) => {
    try {
        await initDB();
        const user = await userService.checkUser(req.body);
        const payload = {
            _id: user._id,
            userName: user.userName
        };
        const token = jwt.sign(payload, JWT_SECRET);
        res.json({ message: "login successful", token });
    } catch (msg) {
        res.status(422).json({ message: msg });
    }
});

app.get("/api/user/favourites", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        await initDB();
        const data = await userService.getFavourites(req.user._id);
        res.json(data);
    } catch (msg) {
        res.status(422).json({ error: msg });
    }
});

app.put("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        await initDB();
        const data = await userService.addFavourite(req.user._id, req.params.id);
        res.json(data);
    } catch (msg) {
        res.status(422).json({ error: msg });
    }
});

app.delete("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        await initDB();
        const data = await userService.removeFavourite(req.user._id, req.params.id);
        res.json(data);
    } catch (msg) {
        res.status(422).json({ error: msg });
    }
});

app.get("/api/user/history", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        await initDB();
        const data = await userService.getHistory(req.user._id);
        res.json(data);
    } catch (msg) {
        res.status(422).json({ error: msg });
    }
});

app.put("/api/user/history/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        await initDB();
        const data = await userService.addHistory(req.user._id, req.params.id);
        res.json(data);
    } catch (msg) {
        res.status(422).json({ error: msg });
    }
});

app.delete("/api/user/history/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        await initDB();
        const data = await userService.removeHistory(req.user._id, req.params.id);
        res.json(data);
    } catch (msg) {
        res.status(422).json({ error: msg });
    }
});

app.use((req, res) => {
    res.status(404).end();
});

// Export for Vercel
module.exports = app;
/* 
const express = require("express");
const cors = require("cors");
const path = require("path");
require('dotenv').config();
const userService = require("./user-service.js");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const passportJWT = require("passport-jwt");

const app = express();
const HTTP_PORT = process.env.PORT || 8080;

// JWT Setup
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
    secretOrKey: process.env.JWT_SECRET,
};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    console.log('JWT payload received:', jwt_payload);
    if (jwt_payload) {
        done(null, {
            _id: jwt_payload._id,
            userName: jwt_payload.userName
        });
    } else {
        done(null, false);
    }
}));

// Middleware
app.use(express.static(path.join(__dirname)));
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

// Basic route for testing
app.get('/', (req, res) => {
    res.json({ message: "User API is running" });
});

// Public routes (no authentication required)
app.post("/api/user/register", async (req, res) => {
    try {
        console.log("Register attempt for:", req.body.userName);
        const msg = await userService.registerUser(req.body);
        res.json({ message: msg });
    } catch (error) {
        console.error("Register error:", error);
        res.status(422).json({ message: error });
    }
});

app.post("/api/user/login", async (req, res) => {
    try {
        console.log("Login attempt for:", req.body.userName);
        const user = await userService.checkUser(req.body);
        
        const payload = {
            _id: user._id,
            userName: user.userName
        };
        
        const token = jwt.sign(payload, process.env.JWT_SECRET);
        res.json({ message: "login successful", token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(422).json({ message: error });
    }
});

// Protected routes (authentication required)
app.get("/api/user/favourites", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        const data = await userService.getFavourites(req.user._id);
        res.json(data);
    } catch (error) {
        res.status(422).json({ error: error });
    }
});

app.put("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        const data = await userService.addFavourite(req.user._id, req.params.id);
        res.json(data);
    } catch (error) {
        res.status(422).json({ error: error });
    }
});

app.delete("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        const data = await userService.removeFavourite(req.user._id, req.params.id);
        res.json(data);
    } catch (error) {
        res.status(422).json({ error: error });
    }
});

app.get("/api/user/history", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        const data = await userService.getHistory(req.user._id);
        res.json(data);
    } catch (error) {
        res.status(422).json({ error: error });
    }
});

app.put("/api/user/history/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        const data = await userService.addHistory(req.user._id, req.params.id);
        res.json(data);
    } catch (error) {
        res.status(422).json({ error: error });
    }
});

app.delete("/api/user/history/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
    try {
        const data = await userService.removeHistory(req.user._id, req.params.id);
        res.json(data);
    } catch (error) {
        res.status(422).json({ error: error });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

// Initialize database and start server (like your working example)
userService.connect().then(() => {
    app.listen(HTTP_PORT, () => {
        console.log(`User API listening on: ${HTTP_PORT}`);
        console.log("MongoDB connected successfully");
        console.log("Environment check:");
        console.log("- MONGO_URL:", process.env.MONGO_URL ? "✓ Set" : "✗ Missing");
        console.log("- JWT_SECRET:", process.env.JWT_SECRET ? "✓ Set" : "✗ Missing");
    });
}).catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
});

module.exports = app;
*/

