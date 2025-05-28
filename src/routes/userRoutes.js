import express from 'express';
import rateLimit from 'express-rate-limit';
import {
  register,
  login,
  logout,
  getProfile,
  editProfile,
  requestPasswordReset,
  resetPasswordWithOTP,
} from '../controllers/userControllers.js';

import authMiddleware from '../Middleware/userMiddleware.js';

// import {getOrdersForUser,} from '../controllers/orderController.js';

const router = express.Router();

// Constants
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS_PER_WINDOW = 5;

// Rate limiter for auth
const authLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: MAX_REQUESTS_PER_WINDOW,
  message: 'Too many requests from this IP, please try again later.',
  skip: (req) => process.env.NODE_ENV === 'test'
});

/** ---------- Public Routes ---------- **/

// Register & Login
router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);

// Password Reset
router.post('/request-password-reset', requestPasswordReset);
router.post('/reset-password', resetPasswordWithOTP);

// Privacy Policy
router.get('/policy', (req, res) => {
  res.render('policy', {
    title: 'Privacy Policy',
    currentYear: new Date().getFullYear()
  });
});

/** ---------- Web Routes (NO session-based protection) ---------- **/
const webRoutes = express.Router();

webRoutes.get('/', (req, res) => {
  res.render('home', {
    user: res.locals.user,
    currentYear: new Date().getFullYear()
  });
});

router.use(webRoutes);

/** ---------- Shared Routes (Hybrid API/Web) ---------- **/

// Logout (token/cookie both supported)
router.post('/logout', logout);

// Profile route supporting API and Web
router.get('/profile-api', (req, res, next) => {
  const isApiRequest =
    req.headers['content-type'] === 'application/json' ||
    req.headers['accept']?.includes('application/json');

  // REMOVE requireLogin, only use authMiddleware for API
  if (isApiRequest) {
    return authMiddleware(req, res, next);
  } else {
    return next();
  }
}, getProfile);

// Directly add the protected routes to the main router
router.get('/profile', authMiddleware, getProfile);
router.put('/profile', authMiddleware, editProfile);
// router.get('/orders', authMiddleware, getOrdersForUser);

export default router;
