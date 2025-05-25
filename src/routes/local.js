import express from 'express';
import { 
  showHomePage, 
  getProducts,
  getProductDetails // <-- UNCOMMENTED: Now properly exported from productController.js
} from '../controllers/productController.js';
import { 
  login,
  register,
  logout,
  // forgotPassword
} from '../controllers/userControllers.js';
import { 
  verifyToken,
  requireLogin, 
  requireApiLogin 
} from '../Middleware/userMiddleware.js';
import Category from '../models/categoryModels.js';
import Order from '../models/orderModels.js';
import User from '../models/userModels.js'; // Needed for /api/check-login
import jwt from 'jsonwebtoken';

const router = express.Router();

// Helper function to get common view data
const getViewData = async (req) => {
  const categories = await Category.find().lean();
  return {
    user: req.user || res.locals.user || null,
    categories,
    currentYear: new Date().getFullYear()
  };
};

// ======================
// PUBLIC ROUTES
// ======================
router.get('/', showHomePage);
router.get('/products', getProducts);
router.get('/products/:id', getProductDetails);

// Authentication pages
router.get('/login', (req, res) => res.render('login', { 
  redirect: req.query.redirect || '',
  error: req.query.error || ''
}));
router.get('/register', (req, res) => res.render('register'));
router.get('/forgot-password', (req, res) => res.render('forgot-password'));
router.get('/policy', (req, res) => res.render('policy', { currentYear: new Date().getFullYear() }));
router.get('/blog', (req, res) => res.render('blog'));

// Authentication handlers
router.post('/login', login);
router.post('/register', register);
// router.post('/forgot-password', forgotPassword);
router.post('/logout', logout);

// ======================
// PROTECTED ROUTES
// ======================
router.get('/cart', requireLogin, async (req, res) => {
  const viewData = await getViewData(req);
  res.render('cart', viewData);
});

router.get('/checkout', requireLogin, async (req, res) => {
  const viewData = await getViewData(req);
  res.render('checkoutpage', viewData);
});

router.get('/orders', requireLogin, async (req, res) => {
  try {
    const viewData = await getViewData(req);
    const orders = await Order.find({ user: req.user._id })
      .populate('items.product')
      .sort({ createdAt: -1 })
      .lean();

    res.render('orders', { 
      ...viewData,
      orders: orders.map(order => ({
        ...order,
        createdAt: order.createdAt.toLocaleDateString(),
        deliveryDate: order.deliveryDate?.toLocaleDateString() || 'Processing'
      }))
    });
  } catch (error) {
    console.error('Error fetching orders:', error);
    const viewData = await getViewData(req);
    res.render('orders', { 
      ...viewData,
      error: 'Failed to load orders'
    });
  }
});

router.get('/profile', requireLogin, async (req, res) => {
  const viewData = await getViewData(req);
  res.render('profile', viewData);
});

// ======================
// API ROUTES
// ======================
// ======================
// API ROUTES
// ======================
router.get('/check-login', async (req, res) => {
  try {
    let userId = null;

    // 1. Check session
    if (req.session && req.session.userId) {
      userId = req.session.userId;
    }

    // 2. Check JWT in cookie or Authorization header
    if (!userId) {
      let token = null;
      if (req.cookies && req.cookies.token) token = req.cookies.token;
      if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        token = req.headers.authorization.split(' ')[1];
      }
      if (token) {
        try {
          const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
          userId = decoded.id;
        } catch (e) {
          // Invalid token, ignore
        }
      }
    }

    if (!userId) {
      return res.json({ success: true, loggedIn: false });
    }

    // Get user with addresses
    const user = await User.findById(userId)
      .select('name email addresses')
      .lean();

    if (!user) {
      return res.json({ success: true, loggedIn: false });
    }

    // Find default address or first address
    const defaultAddress = Array.isArray(user.addresses)
      ? (user.addresses.find(addr => addr.isDefault) || user.addresses[0] || null)
      : null;

    res.json({
      success: true,
      loggedIn: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        address: defaultAddress ? {
          street: defaultAddress.street,
          city: defaultAddress.city,
          state: defaultAddress.state,
          pinCode: defaultAddress.pinCode,
          country: defaultAddress.country,
          isDefault: defaultAddress.isDefault
        } : null
      }
    });

  } catch (error) {
    console.error('Error in check-login:', error);
    res.status(500).json({
      success: false,
      loggedIn: false,
      message: 'Server error'
    });
  }
});

// ======================
// ADMIN ROUTES
// ======================
router.get('/admin', requireLogin, async (req, res) => {
  // Add admin role check if needed
  const viewData = await getViewData(req);
  res.render('admin/dashboard', viewData);
});

export default router;