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

app.use(cors());
app.use(express.json());
app.use(passport.initialize());

// Register
app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then(msg => res.json({ message: msg }))
        .catch(msg => res.status(422).json({ message: msg }));
});

// Login
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

// Protected Routes
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

/*
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  userName: String,
  fullName: String,
  role: String,
  password: String,
  favourites: [String],
  history: [String],
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

// ===== JWT Passport Strategy =====
let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

let jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
  secretOrKey: process.env.JWT_SECRET,
};

let strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
  console.log('payload received', jwt_payload);

  if (jwt_payload) {
    next(null, {
      _id: jwt_payload._id,
      userName: jwt_payload.userName,
      fullName: jwt_payload.fullName,
      role: jwt_payload.role,
    });
  } else {
    next(null, false);
  }
});

passport.use(strategy);
app.use(passport.initialize());

//===== Routes =====
app.post('/api/user/register', async (req, res) => {
  const { userName, fullName, role, password } = req.body;

  try {
    const existingUser = await User.findOne({ userName });
    if (existingUser) return res.status(400).json({ error: 'Username already exists' });

    const newUser = new User({ userName, fullName, role, password });
    await newUser.save();
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

//Login and return JWT
app.post('/api/user/login', async (req, res) => {
  const { userName, password } = req.body;

  try {
    const user = await User.findOne({ userName });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    let payload = {
      _id: user._id,
      userName: user.userName,
      fullName: user.fullName,
      role: user.role,
    };

    let token = jwt.sign(payload, jwtOptions.secretOrKey);
    res.json({ message: 'login successful', token: token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

//Protected route: Favourites
app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const user = await User.findById(req.user._id);
  res.json(user?.favourites || []);
});

//Protected route: History
app.get('/api/user/history', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const user = await User.findById(req.user._id);
  res.json(user?.history || []);
});

//===== Start Server =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
*/