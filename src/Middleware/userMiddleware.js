import jwt from 'jsonwebtoken';

const authMiddleware = (req, res, next) => {
  let token = null;
  if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  } else if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer ')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = { _id: decoded.id, role: decoded.role }; // <-- FIXED: use _id
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
};

export default authMiddleware;
