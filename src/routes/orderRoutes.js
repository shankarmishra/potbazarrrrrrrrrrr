import express from 'express';
import authMiddleware from '../Middleware/userMiddleware.js'; // Token-based
import {
  createTransaction,
  createOrder,
  getOrderbyUserId
} from '../controllers/orderController.js';

const router = express.Router();

// Async error handling wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/** ---------- Protected Routes (Token-based) ---------- **/

// Create a transaction (token-protected)
router.post('/transaction', authMiddleware, asyncHandler(createTransaction));

// Create an order (token-protected)
router.post('/', authMiddleware, asyncHandler(createOrder));

// Get orders by user ID (token-protected)
router.get('/user/:userId', authMiddleware, asyncHandler(getOrderbyUserId));

/** ---------- Public View Route ---------- **/

// Checkout page (EJS view, public)
router.get('/checkoutpage', (req, res) => {
  res.render('checkoutpage');
});

/** ---------- Global Error Handling ---------- **/

// Centralized error handler
router.use((err, req, res, next) => {
  console.error('Order route error:', err.stack);
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
  });
});

/** ---------- 404 Fallback ---------- **/

router.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Order route not found',
  });
});

export default router;
