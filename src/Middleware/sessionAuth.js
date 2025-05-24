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
