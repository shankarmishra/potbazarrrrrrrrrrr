import express from 'express';
import { showHomePage, getProducts } from '../controllers/productController.js';
import { requireLogin } from '../middleware/userMiddleware.js'; // Correct casing
import Category from '../models/categoryModels.js';

const router = express.Router();

// Home page
router.get('/', showHomePage);

// Public pages (no middleware)
router.get('/login', (req, res) => res.render('login'));
router.get('/register', (req, res) => res.render('register'));
router.get('/policy', (req, res) => res.render('policy'));
router.get('/blog', (req, res) => res.render('blog'));
router.get('/forgot-password', (req, res) => res.render('forgot-password'));

// Protected pages (middleware required)
router.get('/cart', requireLogin, async (req, res) => {
  const categories = await Category.find().lean();
  res.render('cart', {
    user: req.user || res.locals.user || null,
    categories
  });
});
router.get('/checkout', requireLogin, async (req, res) => {
  const categories = await Category.find().lean();
  res.render('checkoutpage', {
    user: req.user || res.locals.user || null,
    categories
  });
});
router.get('/products', getProducts);
router.get('/orders', async (req, res) => {
  const categories = await Category.find().lean();
  res.render('orders', {
    user: req.user || res.locals.user || null,
    categories
  });
});

// Admin Login and Register Pages
// Add admin routes here if needed, e.g.:
// router.get('/admin/login', (req, res) => res.render('admin-login'));

// Example login handler
router.post('/login', async (req, res) => {
  // ...find user logic...
  if (user && user.password === password) {
    req.session.userId = user._id;
    return res.redirect('/');
  } else {
    return res.redirect('/login');
  }
});

// Check login status
router.get('/check-login', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ loggedIn: true });
  } else {
    return res.json({ loggedIn: false });
  }
});

export default router;