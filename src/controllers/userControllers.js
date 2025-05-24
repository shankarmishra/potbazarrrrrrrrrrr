import User from '../models/userModels.js';
import Category from '../models/categoryModels.js';
import Product from '../models/productModels.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import validator from 'validator';
import crypto from 'crypto';

dotenv.config();

// Helper functions
const generateTokens = (userId) => ({
  accessToken: jwt.sign({ id: userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20d' }),
  refreshToken: jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' })
});

const sanitizeUser = (user) => {
  const userObj = user.toObject();
  delete userObj.password;
  delete userObj.refreshToken;
  delete userObj.resetToken;
  delete userObj.resetTokenExpires;
  return userObj;
};

// Register Controller
const register = async (req, res) => {
  const { name, phone, email, password, street, city, state, pinCode, country } = req.body;

  // Validation
  if (!name || !phone || !email || !password || !street || !city || !state || !pinCode) {
    return res.status(400).json({ success: false, message: 'All required fields must be provided' });
  }

  try {
    // Input validation
    if (!validator.isLength(name, { min: 2, max: 50 })) {
      return res.status(400).json({ success: false, message: 'Name must be 2-50 characters' });
    }
    if (!validator.isMobilePhone(phone, 'any')) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
    }
    if (!/^\d{6}$/.test(pinCode)) {
      return res.status(400).json({ success: false, message: 'PIN code must be 6 digits' });
    }

    // Check for existing user
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      const field = existingUser.email === email ? 'Email' : 'Phone';
      return res.status(409).json({ success: false, message: `${field} already registered` });
    }

    // Create user with hashed password
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      name,
      phone,
      email,
      password: hashedPassword,
      addresses: [{
        street,
        city,
        state,
        pinCode,
        country: country || 'India',
        isDefault: true
      }]
    });

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(newUser._id);
    newUser.refreshToken = refreshToken;
    await newUser.save();

    // Set session if web request
    if (req.session) {
      req.session.userId = newUser._id;
    }

    // Always return JSON for API
    return res.status(201).json({
      success: true,
      message: 'Registration successful! Please log in.',
      redirect: '/login?success=1'
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Login Controller
const login = async (req, res) => {
  const { email, phone, password } = req.body;

  if ((!email && !phone) || !password) {
    return res.status(400).json({ success: false, message: 'Email/phone and password are required' });
  }

  try {
    // Find user
    const query = email ? { email } : { phone };
    const user = await User.findOne(query).select('+password +refreshToken');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate new tokens
    const { accessToken, refreshToken } = generateTokens(user._id);
    user.refreshToken = refreshToken;
    await user.save();

    // Set session if web request
    if (req.session) {
      req.session.userId = user._id;
    }

    // 👉 Only send token and success message, not user data
    return res.status(200).json({
      success: true,
      message: 'Login successful!',
      token: accessToken,
      refreshToken: refreshToken,
      redirect: '/'
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'Login failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Refresh Token Controller
const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ success: false, message: 'Refresh token is required' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findOne({ _id: decoded.id, refreshToken });

    if (!user) {
      return res.status(403).json({ success: false, message: 'Invalid refresh token' });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);
    user.refreshToken = newRefreshToken;
    await user.save();

    return res.json({
      success: true,
      message: 'Token refreshed',
      data: {
        token: accessToken,
        refreshToken: newRefreshToken
      }
    });

  } catch (error) {
    console.error('Refresh token error:', error);
    return res.status(403).json({
      success: false,
      message: 'Invalid or expired refresh token',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Logout Controller
const logout = async (req, res) => {
  try {
    // Clear token if API request
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        await User.findByIdAndUpdate(decoded.id, { $unset: { refreshToken: 1 } });
      } catch (error) {
        console.error('Token verification error:', error);
      }
    }

    // Clear session if web request
    if (req.session) {
      await new Promise((resolve, reject) => {
        req.session.destroy((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      res.clearCookie('connect.sid');
    }

    return res.json({ success: true, message: 'Logout successful' });

  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({
      success: false,
      message: 'Logout failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Get Profile Controller
const getProfile = async (req, res) => {
  try {
    const userId = req.user?.id || req.session?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    // Explicitly select addresses
    const user = await User.findById(userId).select('-password -refreshToken -resetToken -resetTokenExpires');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Always include addresses and default address (if any)
    const userObj = user.toObject();
    let defaultAddress = null;
    if (Array.isArray(userObj.addresses) && userObj.addresses.length > 0) {
      const defaultAddress = userObj.addresses.find(addr => addr.isDefault) || userObj.addresses[0];
      userObj.address = {
        street: defaultAddress.street || '',
        city: defaultAddress.city || '',
        state: defaultAddress.state || '',
        pinCode: defaultAddress.pinCode || '',
        country: defaultAddress.country || '',
        isDefault: defaultAddress.isDefault || false
      };
    } else {
      userObj.address = {
        street: '',
        city: '',
        state: '',
        pinCode: '',
        country: '',
        isDefault: false
      };
    }

    return res.json({
      success: true,
      message: 'Profile retrieved',
      data: userObj
    });

  } catch (error) {
    console.error('Get profile error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to get profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Edit Profile Controller
const editProfile = async (req, res) => {
  try {
    const userId = req.user?.id || req.session?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const { name, phone, email, addresses } = req.body;

    // Validate inputs
    if (name && !validator.isLength(name, { min: 2, max: 50 })) {
      return res.status(400).json({ success: false, message: 'Name must be 2-50 characters' });
    }
    if (phone && !validator.isMobilePhone(phone, 'any')) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }
    if (email && !validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // Check for existing email/phone
    const existingConditions = [];
    if (phone) existingConditions.push({ phone, _id: { $ne: userId } });
    if (email) existingConditions.push({ email, _id: { $ne: userId } });

    if (existingConditions.length > 0) {
      const existingUser = await User.findOne({ $or: existingConditions });
      if (existingUser) {
        const field = existingUser.email === email ? 'Email' : 'Phone';
        return res.status(409).json({ success: false, message: `${field} already in use` });
      }
    }

    // Prepare update
    const updateData = {};
    if (name) updateData.name = name;
    if (phone) updateData.phone = phone;
    if (email) updateData.email = email;
    if (addresses) {
      updateData.addresses = addresses;
      if (!addresses.some(addr => addr.isDefault)) {
        updateData.addresses[0].isDefault = true;
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    return res.json({
      success: true,
      message: 'Profile updated',
      data: sanitizeUser(updatedUser)
    });

  } catch (error) {
    console.error('Edit profile error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to update profile',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Forgot Password Controller
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }

  try {
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = Date.now() + 3600000; // 1 hour

    user.resetToken = resetToken;
    user.resetTokenExpires = resetTokenExpires;
    await user.save();

    // In production, send email with reset link
    console.log(`Password reset token for ${email}: ${resetToken}`);

    return res.json({
      success: true,
      message: 'Reset token generated',
      data: { resetToken }
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to process request',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Reset Password Controller
const resetPassword = async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) {
    return res.status(400).json({ success: false, message: 'Reset token and new password are required' });
  }

  try {
    // Find user with valid token
    const user = await User.findOne({
      resetToken,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    // Update password
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();

    return res.json({
      success: true,
      message: 'Password reset successful'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to reset password',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Verify Phone Controller
const verifyPhone = async (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ success: false, message: 'Phone number is required' });
  }

  try {
    if (!validator.isMobilePhone(phone, 'any')) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }

    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    return res.json({
      success: true,
      message: 'Phone verification successful',
      data: { userId: user._id }
    });

  } catch (error) {
    console.error('Verify phone error:', error);
    return res.status(500).json({
      success: false,
      message: 'Phone verification failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
  editProfile,
  forgotPassword,
  resetPassword,
  verifyPhone
};