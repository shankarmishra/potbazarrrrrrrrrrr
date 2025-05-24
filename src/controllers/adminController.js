import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import Product from '../models/productModels.js';
import Order from '../models/orderModels.js';
import Admin from '../models/adminmodel.js';
import Category from '../models/categoryModels.js';
import User from '../models/userModels.js';

dotenv.config();

// Admin Login
export const adminLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).render('admin/adminlogin', { error: 'Invalid email or password', success: null });
    }

    const isPasswordValid = bcrypt.compareSync(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).render('admin/adminlogin', { error: 'Invalid email or password', success: null });
    }

    const token = jwt.sign(
      { id: admin._id, email, role: 'admin' },
      process.env.JWT_SECRET || 'default_jwt_secret',
      { expiresIn: '1d' }
    );

    res.cookie('adminToken', token, { httpOnly: true });
    res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('❌ Error during admin login:', error);
    res.status(500).render('admin/adminlogin', { error: 'Server error during login', success: null });
  }
};

// Admin Register
export const adminRegister = async (req, res) => {
  const { email, password, phone, address } = req.body;

  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount >= 5) {
      return res.status(403).render('admin/adminregister', { error: 'Admin limit reached.', success: null });
    }

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).render('admin/adminregister', { error: 'Admin already exists.', success: null });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newAdmin = new Admin({ email, password: hashedPassword, phone, address });
    await newAdmin.save();

    res.status(201).render('admin/adminlogin', { success: 'Admin registered. Please log in.', error: null });
  } catch (error) {
    console.error('❌ Error during admin registration:', error);
    res.status(500).render('admin/adminregister', { error: 'Server error during registration', success: null });
  }
};

// Admin Forgot Password
export const adminForgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).render('admin/adminforgotpassword', { error: 'Admin not found', success: null });
    }

    console.log(`📧 Password reset link sent to ${email}`);
    res.render('admin/adminforgotpassword', { success: 'Reset link sent to your email.', error: null });
  } catch (error) {
    console.error('❌ Error during forgot password:', error);
    res.status(500).render('admin/adminforgotpassword', { error: 'Server error during forgot password', success: null });
  }
};

// Admin Reset Password
export const adminResetPassword = async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).render('admin/adminresetpassword', { error: 'Admin not found', email, success: null });
    }

    admin.password = bcrypt.hashSync(newPassword, 10);
    await admin.save();

    res.render('admin/adminlogin', { success: 'Password reset. Please log in.', error: null });
  } catch (error) {
    console.error('❌ Error during reset password:', error);
    res.status(500).render('admin/adminresetpassword', { error: 'Server error during password reset', email, success: null });
  }
};

// Admin Dashboard
export const getAdminDashboard = async (req, res) => {
  try {
    const totalProducts = await Product.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalUsers = await User.countDocuments();
    // Example: totalTransactions is the same as totalOrders, or calculate as needed
    const totalTransactions = totalOrders;

    res.render('admin/dashboard', {
      totalProducts,
      totalOrders,
      totalUsers,
      totalTransactions, // Pass this to the view
    });
  } catch (error) {
    console.error('❌ Error rendering admin dashboard:', error);
    res.status(500).send('Server Error');
  }
};

// Admin Product List
export const getAdminProducts = async (req, res) => {
  try {
    const categories = await Category.find();
    const products = await Product.find().populate('category');
    res.render('admin/addProduct', { categories, products, error: null, success: null, editProduct: null });
  } catch (error) {
    console.error('❌ Error fetching products:', error);
    res.status(500).send('Server error');
  }
};

// Admin Product Edit
export const getAdminProductEdit = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).send('Product not found');

    res.render('admin/productEdit', { product });
  } catch (error) {
    console.error('❌ Error fetching product:', error);
    res.status(500).send('Server error');
  }
};

// Admin Order List
export const getAdminOrders = async (req, res) => {
  try {
    const orders = await Order.find();
    res.render('admin/orderList', { orders });
  } catch (error) {
    console.error('❌ Error fetching orders:', error);
    res.status(500).send('Server error');
  }
};

// Admin User List
export const getAdminUsers = async (req, res) => {
  try {
    const users = await User.find();
    res.render('admin/userList', { users });
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).send('Server error');
  }
};

// Admin Add Category
export const createCategory = async (req, res) => {
  const { name } = req.body;

  try {
    const existing = await Category.findOne({ name });
    if (existing) {
      return res.render('admin/categoryCreate', { error: 'Category already exists', success: null });
    }

    const newCategory = new Category({ name });
    await newCategory.save();

    res.render('admin/categoryCreate', { success: 'Category created successfully', error: null });
  } catch (error) {
    console.error('❌ Error creating category:', error);
    res.status(500).render('admin/categoryCreate', { error: 'Server error', success: null });
  }
};

// Admin Logout
export const adminLogout = (req, res) => {
  res.clearCookie('adminToken');
  res.redirect('/admin/login');
};
