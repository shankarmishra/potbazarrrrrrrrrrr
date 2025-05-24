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
    required: true, // Ensure phone is required
  },
  address: {
    type: String,
    required: true, // Ensure address is required
  },
  role: {
    type: String,
    enum: ['admin'],
    default: 'admin',
  },
});

const Admin = mongoose.model('Admin', adminSchema);
export default Admin;