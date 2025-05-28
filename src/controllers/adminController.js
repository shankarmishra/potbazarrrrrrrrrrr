import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import Product from '../models/productModels.js';
import Order from '../models/orderModels.js';
import Admin from '../models/adminmodel.js';
import Category from '../models/categoryModels.js';
import User from '../models/userModels.js';
import Subcategory from '../models/Subcategorymodel.js'; // Import at the top
import nodemailer from 'nodemailer'; // Make sure this is at the top
import crypto from 'crypto'; // For OTP generation if not already imported

dotenv.config();

// Helper: Generate 6-digit OTP
const generateAdminOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Helper: Send OTP email to admin
const sendAdminOTPEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Admin Password Reset OTP',
    text: `Your OTP for admin password reset is: ${otp}`
  });
};

// Admin Login
export const adminLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(401).render('admin/adminlogin', {
        error: 'Invalid email or password',
        success: null,
      });
    }

    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).render('admin/adminlogin', {
        error: 'Invalid email or password',
        success: null,
      });
    }

    const token = jwt.sign(
      { id: admin._id, email: admin.email, role: 'admin' },
      process.env.JWT_SECRET || 'default_jwt_secret',
      { expiresIn: '1d' }
    );

    res.cookie('adminToken', token, { httpOnly: true });
    res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('❌ Admin Login Error:', error);
    res.status(500).render('admin/adminlogin', {
      error: 'Server error during login',
      success: null,
    });
  }
};

// Admin Register
export const adminRegister = async (req, res) => {
  const { email, password, phone, address } = req.body;

  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount >= 5) {
      return res.status(403).render('admin/adminregister', {
        error: 'Admin limit reached.',
        success: null,
      });
    }

    const existingAdmin = await Admin.findOne({ email: email.toLowerCase() });
    if (existingAdmin) {
      return res.status(400).render('admin/adminregister', {
        error: 'Admin already exists.',
        success: null,
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({
      email: email.toLowerCase(),
      password: hashedPassword,
      phone,
      address,
    });

    await newAdmin.save();
    res.status(201).render('admin/adminlogin', {
      success: 'Admin registered. Please log in.',
      error: null,
    });
  } catch (error) {
    console.error('❌ Admin Registration Error:', error);
    res.status(500).render('admin/adminregister', {
      error: 'Server error during registration',
      success: null,
    });
  }
};

// Admin Forgot Password
// 1. Request OTP for admin password reset
export const adminRequestPasswordReset = async (req, res) => {
  const { email } = req.body;
  try {
    const admin = await Admin.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(404).json({ success: false, message: 'Admin not found' });
    }
    const otp = generateAdminOTP();
    admin.resetToken = otp;
    admin.resetTokenExpires = Date.now() + 10 * 60 * 1000; // 10 min
    await admin.save();
    await sendAdminOTPEmail(email, otp);
    return res.json({ success: true, message: 'OTP sent to admin email' });
  } catch (error) {
    console.error('❌ Admin OTP Error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// 2. Verify OTP and reset admin password
export const adminResetPasswordWithOTP = async (req, res) => {
  const { email, otp, newPassword, confirmPassword } = req.body;
  if (!email || !otp || !newPassword || !confirmPassword)
    return res.status(400).json({ success: false, message: 'All fields are required' });

  if (newPassword !== confirmPassword)
    return res.status(400).json({ success: false, message: 'Passwords do not match' });

  try {
    const admin = await Admin.findOne({
      email: email.toLowerCase(),
      resetToken: otp,
      resetTokenExpires: { $gt: Date.now() }
    });
    if (!admin) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }
    admin.password = await bcrypt.hash(newPassword, 10);
    admin.resetToken = undefined;
    admin.resetTokenExpires = undefined;
    await admin.save();
    return res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('❌ Admin Reset Password Error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Admin Dashboard
export const getAdminDashboard = async (req, res) => {
  try {
    const totalProducts = await Product.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalUsers = await User.countDocuments();
    const totalTransactions = totalOrders;

    res.render('admin/dashboard', {
      isAdmin: true,
      totalProducts,
      totalOrders,
      totalUsers,
    });
  } catch (error) {
    console.error('❌ Dashboard Load Error:', error);
    res.status(500).send('Server Error');
  }
};

// Admin Product List
export const getAdminProducts = async (req, res) => {
  try {
    const categories = await Category.find();
    const products = await Product.find().populate('category');
    res.render('admin/addProduct', {
      isAdmin: true,
      categories,
      products,
      editProduct: null,
      error: null,
      success: null,
    });
  } catch (error) {
    console.error('❌ Fetching Products Error:', error);
    res.status(500).send('Server Error');
  }
};

// Admin Product Edit
export const getAdminProductEdit = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).send('Product not found');

    res.render('admin/productEdit', { product });
  } catch (error) {
    console.error('❌ Product Edit Fetch Error:', error);
    res.status(500).send('Server Error');
  }
};

// Admin Order List
export const getAdminOrders = async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('user', 'name email')
      .populate('items.product', 'name images');
    res.render('admin/orderList', {
      isAdmin: true,
      orders,
    });
  } catch (error) {
    console.error('❌ Orders Fetch Error:', error);
    res.status(500).send('Server Error');
  }
};

// Admin User List
export const getAdminUsers = async (req, res) => {
  try {
    const users = await User.find();
    res.render('admin/userList', {
      isAdmin: true,
      users // your users array
    });
  } catch (error) {
    console.error('❌ Users Fetch Error:', error);
    res.status(500).send('Server Error');
  }
};

// Admin Add Category
export const createCategory = async (req, res) => {
  const { name } = req.body;

  try {
    const existing = await Category.findOne({ name: name.trim() });
    if (existing) {
      return res.render('admin/categoryCreate', {
        error: 'Category already exists',
        success: null,
      });
    }

    const newCategory = new Category({ name: name.trim() });
    await newCategory.save();

    res.render('admin/categoryCreate', {
      success: 'Category created successfully',
      error: null,
    });
  } catch (error) {
    console.error('❌ Create Category Error:', error);
    res.status(500).render('admin/categoryCreate', {
      error: 'Server error',
      success: null,
    });
  }
};

// Admin Create Subcategory
export const createSubcategory = async (req, res) => {
  const { name, description, category } = req.body;
  try {
    // Check for duplicate
    const exists = await Subcategory.findOne({ name: name.trim(), category });
    if (exists) {
      const categories = await Category.find();
      const subcategories = await Subcategory.find().populate('category');
      return res.render('admin/subcategory', {
        isAdmin: true,
        categories,
        subcategories,
        subcategoryError: 'Subcategory already exists for this category.',
        subcategorySuccess: null
      });
    }
    const newSubcat = new Subcategory({ name: name.trim(), description, category });
    await newSubcat.save();
    const categories = await Category.find();
    const subcategories = await Subcategory.find().populate('category');
    res.render('admin/subcategory', {
      isAdmin: true,
      categories,
      subcategories,
      subcategoryError: null,
      subcategorySuccess: 'Subcategory created successfully!'
    });
  } catch (error) {
    console.error('❌ Create Subcategory Error:', error);
    const categories = await Category.find();
    const subcategories = await Subcategory.find().populate('category');
    res.render('admin/subcategory', {
      isAdmin: true,
      categories,
      subcategories,
      subcategoryError: 'Server error',
      subcategorySuccess: null
    });
  }
};

// Admin Logout
export const adminLogout = (req, res) => {
  res.clearCookie('adminToken');
  res.redirect('/admin/login');
};
