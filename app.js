// Load environment variables
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';

// DB connection
import connect from './src/config/connect.js';

// Models
import User from './src/models/userModels.js'; // Ensure model import order

// Routes
import userRoutes from './src/routes/userRoutes.js';
import orderRoutes from './src/routes/orderRoutes.js';
import localRoutes from './src/routes/local.js';
import categoryRoutes from './src/routes/categoryRoutes.js';
import productRoutes from './src/routes/productRoutes.js';
import adminRoutes from './src/routes/adminRoutes.js';

const app = express();

// Resolve __dirname in ES Module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Session & Cookie Middleware
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
      httpOnly: true, // Mitigate XSS
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax', // CSRF protection
    },
  })
);

// Built-in Middlewares for parsing JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple Logger Middleware
app.use((req, res, next) => {
  const now = new Date().toISOString();
  console.log(`[${now}] ${req.method} ${req.originalUrl}`);
  next();
});

// Static File Serving
app.use(express.static(path.join(__dirname, 'public')));
app.use('/static', express.static(path.join(__dirname, 'src', 'assets')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// View Engine Configuration
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src', 'views'));

// Prevent Admin Route Caching
app.use('/admin', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

// User session middleware — must run BEFORE routes to set res.locals.user
app.use(async (req, res, next) => {
  if (req.session?.userId) {
    try {
      const user = await User.findById(req.session.userId).select('name email phone');
      res.locals.user = user ? user.toObject() : null;
    } catch (e) {
      res.locals.user = null;
    }
  } else {
    res.locals.user = null;
  }
  next();
});

// Check login route
app.get('/check-login', (req, res) => {
  if (req.session && req.session.userId) return res.json({ loggedIn: true });
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      if (decoded) return res.json({ loggedIn: true });
    } catch (e) {}
  }
  return res.json({ loggedIn: false });
});

// Register Routes
app.use('/admin', adminRoutes);
app.use('/', localRoutes);
app.use('/api/users', userRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/products', productRoutes);
app.use('/category', categoryRoutes);

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  if (res.headersSent) return next(err);

  res.status(err.status || 500);
  const errorMessage = err.message || 'Internal Server Error';

  if (req.originalUrl.startsWith('/api/')) {
    res.json({ message: errorMessage });
  } else {
    res.render('error', { message: errorMessage });
  }
});

// Server Bootstrap
const start = async () => {
  const PORT = process.env.PORT || 3000;
  const HOST = '0.0.0.0';

  try {
    await connect(process.env.MONGO_URI);
    console.log('✅ Connected to MongoDB');

    app.listen(PORT, HOST, () => {
      console.log(`✅ Server running at: http://localhost:${PORT}`);
      console.log(`✅ Admin dashboard available at: http://localhost:${PORT}/admin`);
    });
  } catch (error) {
    console.error('❌ Error during server startup:', error);
    process.exit(1);
  }
};

start();
