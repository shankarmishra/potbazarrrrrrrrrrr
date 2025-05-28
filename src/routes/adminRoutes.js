import express from 'express';
import {
  adminLogin,
  adminRegister,
  getAdminDashboard,
  getAdminProducts,
  getAdminProductEdit,
  getAdminOrders,
  getAdminUsers,
  createCategory,
  adminLogout,
  createSubcategory,
  adminRequestPasswordReset,      // <-- Add this
  adminResetPasswordWithOTP       // <-- Add this
} from '../controllers/adminController.js';
import {
  createProduct,
  deleteProduct
} from '../controllers/productController.js';

import { verifyAdmin } from '../Middleware/adminAuthMiddleware.js';

// Add these imports for rendering the subcategory page
import Category from '../models/categoryModels.js';
import Subcategory from '../models/Subcategorymodel.js';

const router = express.Router();

// Public Admin Routes
router.get('/login', (req, res) => res.render('admin/adminlogin', { error: null, success: null }));
router.post('/login', adminLogin);
router.get('/register', (req, res) => res.render('admin/adminregister', { error: null, success: null }));
router.post('/register', adminRegister);
router.get('/forgot-password', (req, res) => res.render('admin/adminforgotpassword', { error: null, success: null }));

// Admin OTP-based password reset API (for AJAX frontend)
router.post('/request-password-reset', adminRequestPasswordReset);
router.post('/reset-password', adminResetPasswordWithOTP);

// Protected Admin Routes
router.get('/dashboard', verifyAdmin, getAdminDashboard);
router.get('/products', verifyAdmin, getAdminProducts);
router.get('/product/edit/:id', verifyAdmin, getAdminProductEdit);
router.get('/orders', verifyAdmin, getAdminOrders);
router.get('/users', verifyAdmin, getAdminUsers);
router.get('/category/create', verifyAdmin, (req, res) => res.render('admin/categoryCreate', { error: null, success: null }));
router.post('/category/create', verifyAdmin, createCategory);
router.get('/logout', verifyAdmin, adminLogout);

// ----------- Subcategory Routes -----------

// Render subcategory creation page
router.get('/category/subcategory/add', verifyAdmin, async (req, res) => {
  const categories = await Category.find();
  const subcategories = await Subcategory.find().populate('category');
  res.render('admin/subcategory', {
    isAdmin: true,
    categories, // your categories array
    subcategories, // your subcategories array
    subcategoryError: null,
    subcategorySuccess: null
  });
});

// Handle subcategory creation
router.post('/api/category/subcategory/add', verifyAdmin, createSubcategory);

export default router;
