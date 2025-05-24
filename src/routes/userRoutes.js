
import express from 'express';
import rateLimit from 'express-rate-limit';
import {
  register,
  login,
  // refreshToken ,
  logout,
  getProfile,
  editProfile,
  forgotPassword,
  resetPassword,
  verifyPhone,
} from '../controllers/userControllers.js';
import verifyToken from '../Middleware/userMiddleware.js';
import { requireLogin, requireApiLogin } from '../Middleware/userMiddleware.js';

const router = express.Router();

// Rate limiter for forgot password route
const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

/** ---------- Public Routes ---------- **/

// User registration (API)
router.post('/register', register);

// User login (API)
router.post('/login', login);

// Refresh token (API)
// router.post('/refresh-token', refreshToken );

// Forgot password (API, rate-limited)
router.post('/forgot-password', forgotPasswordLimiter, forgotPassword);

// Reset password (API)
router.post('/reset-password', resetPassword);

// Phone number verification (API, optional)
router.post('/verify-phone', verifyPhone);

// Serve the policy page (EJS page)
router.get('/policy', (req, res) => {
  res.render('policy', { title: 'Policy' });
});

/** ---------- Protected Routes ---------- **/

// Profile route (API, token-based)
router.get('/profile', verifyToken, getProfile);

// Edit profile (API, token-based)
router.put('/profile', verifyToken, editProfile);

// Profile route (EJS, session-based)
router.get('/profile-page', requireLogin, getProfile);

// Profile route (API, session-based, returns JSON error if not logged in)
router.get('/profile-api', requireApiLogin, getProfile);

/** ---------- Page Routes ---------- **/

// Home page (EJS, session-based)
router.get('/', requireLogin, (req, res) => {
  res.render('home', { user: res.locals.user });
});

/** ---------- Logout Route ---------- **/

// Logout (API and session)
router.post('/logout', logout);

export default router;