import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import Product from '../models/productModels.js';
import Order from '../models/orderModels.js';
import Admin from '../models/adminmodel.js';
import Category from '../models/categoryModels.js';
import User from '../models/userModels.js';
import Subcategory from '../models/Subcategorymodel.js'; // Import at the top

dotenv.config();

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
export const adminForgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const admin = await Admin.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(404).render('admin/adminforgotpassword', {
        error: 'Admin not found',
        success: null,
      });
    }

    console.log(`📧 Reset link sent to: ${email}`);
    res.render('admin/adminforgotpassword', {
      success: 'Reset link sent to your email.',
      error: null,
    });
  } catch (error) {
    console.error('❌ Forgot Password Error:', error);
    res.status(500).render('admin/adminforgotpassword', {
      error: 'Server error during forgot password',
      success: null,
    });
  }
};

// Admin Reset Password
export const adminResetPassword = async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const admin = await Admin.findOne({ email: email.toLowerCase() });
    if (!admin) {
      return res.status(404).render('admin/adminresetpassword', {
        error: 'Admin not found',
        email,
        success: null,
      });
    }

    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();

    res.render('admin/adminlogin', {
      success: 'Password reset. Please log in.',
      error: null,
    });
  } catch (error) {
    console.error('❌ Reset Password Error:', error);
    res.status(500).render('admin/adminresetpassword', {
      error: 'Server error during password reset',
      email,
      success: null,
    });
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
    const orders = await Order.find();
    res.render('admin/orderList', {
      isAdmin: true,
      orders, // your orders array
      // ...any other variables
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
