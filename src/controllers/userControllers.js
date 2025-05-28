import User from '../models/userModels.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import validator from 'validator';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

dotenv.config();

// Constants
const PASSWORD_MIN_LENGTH = 8;
const NAME_MIN_LENGTH = 2;
const NAME_MAX_LENGTH = 50;
const TOKEN_EXPIRY = {
  ACCESS: '20d',
  REFRESH: '30d'
};
const RESET_TOKEN_EXPIRY = 3600000; // 1 hour in ms

// Helper functions
const generateTokens = (userId) => ({
  accessToken: jwt.sign({ id: userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: TOKEN_EXPIRY.ACCESS
  }),
  refreshToken: jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: TOKEN_EXPIRY.REFRESH
  })
});

const sanitizeUser = (user) => {
  const userObj = user.toObject ? user.toObject() : user;
  delete userObj.password;
  delete userObj.refreshToken;
  delete userObj.resetToken;
  delete userObj.resetTokenExpires;
  return userObj;
};

const validateUserInput = (data, isRegistration = false) => {
  const errors = {};

  if (isRegistration) {
    if (!data.name || !validator.isLength(data.name, {
      min: NAME_MIN_LENGTH,
      max: NAME_MAX_LENGTH
    })) {
      errors.name = `Name must be ${NAME_MIN_LENGTH}-${NAME_MAX_LENGTH} characters`;
    }

    if (!data.password || data.password.length < PASSWORD_MIN_LENGTH) {
      errors.password = `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
    }

    if (!data.pinCode || !/^\d{6}$/.test(data.pinCode)) {
      errors.pinCode = 'PIN code must be 6 digits';
    }

    if (!data.street || !data.city || !data.state) {
      errors.address = 'Street, city, and state are required';
    }
  }

  if (data.email && !validator.isEmail(data.email)) {
    errors.email = 'Invalid email format';
  }

  if (data.phone && !validator.isMobilePhone(data.phone, 'any')) {
    errors.phone = 'Invalid phone number';
  }

  return Object.keys(errors).length ? errors : null;
};

// Register
const register = async (req, res) => {
  const { name, phone, email, password, street, city, state, pinCode, country } = req.body;

  const validationErrors = validateUserInput(req.body, true);
  if (validationErrors) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: validationErrors
    });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      const field = existingUser.email === email ? 'Email' : 'Phone';
      return res.status(409).json({
        success: false,
        message: `${field} already registered`
      });
    }

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

    const { accessToken, refreshToken } = generateTokens(newUser._id);
    await User.findByIdAndUpdate(newUser._id, { refreshToken });

    if (req.headers['user-agent']?.includes('Mozilla')) {
      res.cookie('token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 20 * 24 * 60 * 60 * 1000
      });
    }

    // Only send token and success, do not send user data
    return res.status(201).json({
      success: true,
      message: 'Registration successful',
      token: accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Login
const login = async (req, res) => {
  const { email, phone, password } = req.body;

  if ((!email && !phone) || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email/phone and password are required'
    });
  }

  try {
    const query = email ? { email } : { phone };
    const user = await User.findOne(query).select('+password +refreshToken');

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role }, // <-- include role
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '7d' }
    );
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Only send token and success, do not send user data
    return res.status(200).json({
      success: true,
      message: 'Login successful',
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Refresh Token
const refreshTokenController = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      success: false,
      message: 'Refresh token is required'
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findOne({
      _id: decoded.id,
      refreshToken
    });

    if (!user) {
      return res.status(403).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);
    await User.findByIdAndUpdate(user._id, { refreshToken: newRefreshToken });

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
      message: error.name === 'TokenExpiredError' ? 'Refresh token expired' : 'Invalid refresh token'
    });
  }
};

// Logout
const logout = async (req, res) => {
  try {
    const userId = req.user?.id;

    if (userId) {
      await User.findByIdAndUpdate(userId, {
        $unset: { refreshToken: 1 }
      });
    }

    if (req.headers['user-agent']?.includes('Mozilla')) {
      res.clearCookie('token');
    }

    return res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Get Profile
const getProfile = async (req, res) => {
  try {
    const userId = req.user?._id; // <-- FIXED: use _id
    if (!userId) {
      console.error('No userId in req.user:', req.user);
      return res.status(401).json({
        success: false,
        message: 'Not authenticated'
      });
    }

    const user = await User.findById(userId).select('-password -refreshToken -resetToken -resetTokenExpires');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Send only sanitized user data on success
    return res.status(200).json({
      success: true,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Get profile error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Edit Profile
const editProfile = async (req, res) => {
  try {
    const userId = req.user?._id; // <-- FIXED: use _id
    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated'
      });
    }

    const validationErrors = validateUserInput(req.body);
    if (validationErrors) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    const { email, phone, name, street, city, state, pinCode, country } = req.body;

    // Check for duplicate email/phone
    const existingConditions = [];
    if (email) existingConditions.push({ email, _id: { $ne: userId } });
    if (phone) existingConditions.push({ phone, _id: { $ne: userId } });

    if (existingConditions.length > 0) {
      const existingUser = await User.findOne({ $or: existingConditions });
      if (existingUser) {
        const field = existingUser.email === email ? 'Email' : 'Phone';
        return res.status(409).json({
          success: false,
          message: `${field} already in use`
        });
      }
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Update fields
    if (email) user.email = email;
    if (phone) user.phone = phone;
    if (name) user.name = name;

    if (street && city && state && pinCode) {
      user.addresses[0] = {
        street,
        city,
        state,
        pinCode,
        country: country || 'India',
        isDefault: true
      };
    }

    await user.save();

    return res.json({
      success: true,
      message: 'Profile updated',
      data: sanitizeUser(user)
    });

  } catch (error) {
    console.error('Edit profile error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Helper: Generate 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Helper: Send OTP email
const sendOTPEmail = async (email, otp) => {
  // Configure your transporter (use your SMTP credentials)
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER, // set in .env
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for Password Reset',
    text: `Your OTP for password reset is: ${otp}`
  });
};

// Request OTP for password reset
const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, message: 'Email is required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  const otp = generateOTP();
  user.resetToken = otp;
  user.resetTokenExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  await user.save();

  await sendOTPEmail(email, otp);

  return res.json({ success: true, message: 'OTP sent to email' });
};

// Verify OTP and reset password
const resetPasswordWithOTP = async (req, res) => {
  const { email, otp, newPassword, confirmPassword } = req.body;
  if (!email || !otp || !newPassword || !confirmPassword)
    return res.status(400).json({ success: false, message: 'All fields are required' });

  if (newPassword !== confirmPassword)
    return res.status(400).json({ success: false, message: 'Passwords do not match' });

  const user = await User.findOne({ email, resetToken: otp, resetTokenExpires: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });

  user.password = await bcrypt.hash(newPassword, 12);
  user.resetToken = undefined;
  user.resetTokenExpires = undefined;
  await user.save();

  return res.json({ success: true, message: 'Password reset successful' });
};

// --- Export these new controllers ---
export {
  register,
  login,
  logout,
  refreshTokenController as refreshToken,
  getProfile,
  editProfile,
  requestPasswordReset,
  resetPasswordWithOTP
};
