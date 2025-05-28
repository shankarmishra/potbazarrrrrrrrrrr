import mongoose from 'mongoose';

const adminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  phone: {
    type: String,
    required: true,
  },
  address: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['admin'],
    default: 'admin',
  },
  // Add these fields for OTP-based password reset
  resetToken: {
    type: String,
    select: false,
  },
  resetTokenExpires: {
    type: Date,
    select: false,
  },
});

const Admin = mongoose.model('Admin', adminSchema);
export default Admin;