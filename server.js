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

const HTTP_PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;

const ExtractJWT = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: JWT_SECRET
};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    userService.getUserById(jwt_payload._id)
        .then(user => done(null, user))
        .catch(err => done(null, false));
}));

app.use(passport.initialize());
app.use(cors());
app.use(express.json());



app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then(msg => res.json({ message: msg }))
        .catch(msg => res.status(422).json({ message: msg }));
});


app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
        .then(user => {
            const payload = {
                _id: user._id,
                userName: user.userName
            };
            const token = jwt.sign(payload, JWT_SECRET);
            res.json({ message: "login successful", token });
        })
        .catch(msg => res.status(422).json({ message: msg }));
});

app.get("/api/user/favourites", passport.authenticate("jwt", { session: false }), (req, res) => {
    userService.getFavourites(req.user._id)
        .then(data => res.json(data))
        .catch(msg => res.status(422).json({ error: msg }));
});

app.put("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(msg => res.status(422).json({ error: msg }));
});

app.delete("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(msg => res.status(422).json({ error: msg }));
});

app.get("/api/user/history", passport.authenticate("jwt", { session: false }), (req, res) => {
    userService.getHistory(req.user._id)
        .then(data => res.json(data))
        .catch(msg => res.status(422).json({ error: msg }));
});

app.put("/api/user/history/:id", passport.authenticate("jwt", { session: false }), (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(msg => res.status(422).json({ error: msg }));
});

app.delete("/api/user/history/:id", passport.authenticate("jwt", { session: false }), (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(msg => res.status(422).json({ error: msg }));
});

userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => console.log("API listening on: " + HTTP_PORT));
    })
    .catch(err => {
        console.log("unable to start the server: " + err);
        process.exit();
});
