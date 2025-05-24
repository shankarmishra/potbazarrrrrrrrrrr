import express from 'express';
import verifyToken, { requireLogin } from '../middleware/userMiddleware.js';
import { createTransaction, createOrder, getOrderbyUserId } from '../controllers/orderController.js';


const router = express.Router();

// Async error handling wrapper
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Create a transaction (protected)
router.post('/transaction', requireLogin, createTransaction);

// Create an order (protected)
router.post('/', verifyToken, asyncHandler(createOrder));

// Get orders by user ID (protected)
router.get('/user/:userId', verifyToken, asyncHandler(getOrderbyUserId));

// Checkout page (session/EJS, not protected by JWT)
router.get('/checkoutpage', (req, res) => {
    res.render('checkoutpage');
});

// Global error handling middleware
router.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.statusCode || 500).json({
        success: false,
        message: err.message || 'Internal Server Error',
    });
});

// Handle invalid routes for this module
router.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Order route not found',
    });
});

export default router;
