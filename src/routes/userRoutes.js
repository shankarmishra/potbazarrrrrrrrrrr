import express from 'express';
import rateLimit from 'express-rate-limit';
import {
  register,
  login,
  logout,
  getProfile,
  editProfile,
  // forgotPassword,
  // resetPassword,
  // verifyPhone,
} from '../controllers/userControllers.js';
import { verifyToken, requireLogin, requireApiLogin } from '../Middleware/userMiddleware.js';

const router = express.Router();

// Constants
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS_PER_WINDOW = 5;

// Rate limiters
const authLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: MAX_REQUESTS_PER_WINDOW,
  message: 'Too many requests from this IP, please try again later.',
  skip: (req) => process.env.NODE_ENV === 'test' // Skip during tests
});

const passwordResetLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: 3, // More strict for password reset
  message: 'Too many password reset attempts, please try again later.'
});

/** ---------- Public Routes ---------- **/

// User authentication routes
router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);

// Password management
// // router.post('/forgot-password', passwordResetLimiter, forgotPassword);
// router.post('/reset-password', resetPassword);

// Phone verification
// router.post('/verify-phone', verifyPhone);

// Policy page
router.get('/policy', (req, res) => {
  res.render('policy', { 
    title: 'Privacy Policy',
    currentYear: new Date().getFullYear() 
  });
});

/** ---------- Protected API Routes (Token-based) ---------- **/
const apiRoutes = express.Router();

apiRoutes.use(verifyToken); // All API routes require token verification

apiRoutes.get('/profile', getProfile);
apiRoutes.put('/profile', editProfile);

router.use('/api', apiRoutes); // Mount under /api prefix

/** ---------- Protected Web Routes (Session-based) ---------- **/
const webRoutes = express.Router();

webRoutes.use(requireLogin); // All web routes require session

webRoutes.get('/profile', getProfile);
webRoutes.get('/', (req, res) => {
  res.render('home', { 
    user: res.locals.user,
    currentYear: new Date().getFullYear()
  });
});

router.use(webRoutes);

/** ---------- Hybrid Routes (API/Web) ---------- **/

// Logout (works for both API and web)
router.post('/logout', logout);

// Profile API endpoint (works with both token and session)
router.get('/profile-api', (req, res, next) => {
  // Check if it's an API request
  if (req.headers['content-type'] === 'application/json' || 
      req.headers['accept'].includes('application/json')) {
    return verifyToken(req, res, next);
  }
  // Otherwise treat as web request
  return requireLogin(req, res, next);
}, getProfile);

export default router;