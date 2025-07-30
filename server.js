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
