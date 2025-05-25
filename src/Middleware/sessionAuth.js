const jwt = require('jsonwebtoken');

// Middleware to check if the user is logged in (session-based authentication)
export const requireLogin = (req, res, next) => {
  if (req.session && req.session.user) {
    res.locals.user = req.session.user; // Make user info available in views
    return next();
  }

  // If not logged in, redirect to login page or return an error
  const accept = req.headers.accept || '';
  if (accept.includes('application/json')) {
    return res.status(401).json({ message: 'Unauthorized. Please log in.' });
  } else {
    return res.redirect('/login');
  }
};

const auth = async (req, res, next) => {
  try {
    // Check header first, then cookies
    const token = req.headers.authorization?.split(' ')[1] || 
                 req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

module.exports = auth;
