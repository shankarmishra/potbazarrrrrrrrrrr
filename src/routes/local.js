import express from 'express';
import {
  showHomePage,
  getProducts,
  getProductDetails,
} from '../controllers/productController.js';
import {
  login,
  register,
  logout,
  // forgotPassword,
} from '../controllers/userControllers.js';
import authMiddleware from '../Middleware/userMiddleware.js';
import Category from '../models/categoryModels.js';
import Order from '../models/orderModels.js';
import User from '../models/userModels.js';
import jwt from 'jsonwebtoken';

import { getOrdersForUser, getOrdersForUserApi } from '../controllers/orderController.js';

const router = express.Router();

// Helper function to get view data
const getViewData = async (req) => {
  const categories = await Category.find().lean();
  return {
    user: req.user || res.locals.user || null,
    categories,
    currentYear: new Date().getFullYear(),
  };
};

/* ============================
   PUBLIC ROUTES
============================ */

// Home and product-related
router.get('/', showHomePage);
router.get('/products', getProducts);
router.get('/products/:id', getProductDetails);

// Authentication pages
router.get('/login', (req, res) =>
  res.render('login', {
    redirect: req.query.redirect || '',
    error: req.query.error || '',
  })
);
router.get('/register', (req, res) => res.render('register'));
router.get('/forgot-password', (req, res) => res.render('forgot-password'));
router.get('/policy', (req, res) =>
  res.render('policy', { currentYear: new Date().getFullYear() })
);
router.get('/blog', (req, res) => res.render('blog'));

// Auth handlers
router.post('/login', login);
router.post('/register', register);
// router.post('/forgot-password', forgotPassword);
router.post('/logout', logout);

/* ============================
   PROTECTED ROUTES (Token-based)
============================ */

// Cart page - only for logged-in users
router.get('/cart', authMiddleware, async (req, res) => {
  const viewData = await getViewData(req);
  res.render('cart', viewData);
});

router.get('/checkout', authMiddleware, async (req, res) => {
  const viewData = await getViewData(req);
  res.render('checkoutpage', viewData);
});

// EJS page for orders
router.get('/orders', authMiddleware, getOrdersForUser);

// API for orders (returns JSON)
router.get('/api/orders', authMiddleware, getOrdersForUserApi);

router.get('/profile', authMiddleware, async (req, res) => {
  const viewData = await getViewData(req);
  res.render('profile', viewData);
});

/* ============================
   API ROUTES (Token/Session)
============================ */

router.get('/check-login', async (req, res) => {
  try {
    const token =
      req.cookies?.token ||
      (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
        ? req.headers.authorization.split(' ')[1]
        : null);

    // console.log('Token from cookie:', req.cookies?.token);
    // console.log('Token used:', token);

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      // console.log('Decoded:', decoded);
    } catch (err) {
      console.error('JWT verify error:', err);
      return res.json({ success: true, loggedIn: false });
    }

    const user = await User.findById(decoded.id).select('name email addresses').lean();
    if (!user) {
      return res.json({ success: true, loggedIn: false });
    }

    // Find default address or fallback to first address or null
    let defaultAddress = null;
    if (Array.isArray(user.addresses) && user.addresses.length > 0) {
      defaultAddress = user.addresses.find(addr => addr.isDefault) || user.addresses[0];
    }

    res.json({
      success: true,
      loggedIn: true,
    });
  } catch (error) {
    console.error('❌ Error in /check-login:', error);
    res.status(500).json({ success: false, loggedIn: false, message: 'Internal server error' });
  }
});


export default router;
