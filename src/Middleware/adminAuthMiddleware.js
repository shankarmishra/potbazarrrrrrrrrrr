import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

export const verifyAdmin = (req, res, next) => {
  const token = req.cookies?.adminToken;

  // If token is missing, redirect to login
  if (!token) {
    console.warn('⚠️ No admin token found. Redirecting to login.');
    return res.redirect('/admin/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');

    // Check if the decoded token has admin privileges
    if (decoded.role !== 'admin') {
      console.warn('🚫 Access denied: User is not an admin.');
      return res.status(403).send('Access denied: Not an admin');
    }

    // Attach decoded admin data to the request
    req.admin = decoded;
    next();
  } catch (error) {
    console.error('❌ Invalid or expired admin token:', error.message);
    res.clearCookie('adminToken');
    res.redirect('/admin/login');
  }
};
