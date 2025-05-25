import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import User from '../models/userModels.js';

dotenv.config();

// Constants
const AUTH_SCHEME = 'Bearer';
const TOKEN_EXPIRED_ERROR = 'TokenExpiredError';
const JWT_ERRORS = {
  TokenExpiredError: 'Session expired. Please log in again.',
  JsonWebTokenError: 'Invalid authentication token',
  NotBeforeError: 'Token not yet valid'
};

/**
 * Verify JWT token and attach user to request
 * @param {string} token - JWT token to verify
 * @returns {object} decoded token payload
 * @throws {Error} if token is invalid
 */
const verifyJwtToken = (token) => {
  return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, {
    clockTolerance: 15, // 15 seconds leeway for clock skew
    ignoreExpiration: false // strictly validate expiration
  });
};

/**
 * Extract token from authorization header or cookies
 * @param {object} req - Express request object
 * @returns {string|null} token or null if not found
 */
const extractToken = (req) => {
  // 1. Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith(`${AUTH_SCHEME} `)) {
    return authHeader.split(' ')[1];
  }

  // 2. Check cookies (for web clients)
  if (req.cookies?.token) {
    return req.cookies.token;
  }

  return null;
};

/**
 * Middleware to verify JWT access token (strict validation for API routes)
 */
const verifyToken = async (req, res, next) => {
  try {
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({ 
        success: false,
        code: 'MISSING_TOKEN',
        message: 'Authentication required. No token provided.' 
      });
    }

    const decoded = verifyJwtToken(token);
    
    // Verify user exists and is active
    const user = await User.findById(decoded.id)
      .select('-password -refreshToken')
      .lean();
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        code: 'USER_NOT_FOUND', 
        message: 'User account no longer exists' 
      });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ 
        success: false,
        code: 'ACCOUNT_INACTIVE',
        message: 'Account is not active' 
      });
    }

    // Attach user to request
    req.user = { 
      ...decoded, 
      ...user,
      authMethod: 'jwt' 
    };
    
    next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
    
    const errorMessage = JWT_ERRORS[error.name] || 'Authentication failed';
    const statusCode = error.name === TOKEN_EXPIRED_ERROR ? 401 : 403;
    
    return res.status(statusCode).json({ 
      success: false,
      code: error.name || 'AUTH_ERROR',
      message: errorMessage 
    });
  }
};

/**
 * Middleware to require session OR JWT login (for EJS/browser routes)
 */
const requireLogin = async (req, res, next) => {
  try {
    // 1. Check session-based auth first
    if (req.session?.userId) {
      const user = await User.findById(req.session.userId)
        .select('-password -refreshToken')
        .lean();
      
      if (user) {
        req.user = user;
        res.locals.user = user; // For EJS templates
        req.user.authMethod = 'session';
        return next();
      }
    }

    // 2. Check JWT-based auth
    const token = extractToken(req);
    if (token) {
      const decoded = verifyJwtToken(token);
      const user = await User.findById(decoded.id)
        .select('-password -refreshToken')
        .lean();
      
      if (user) {
        req.user = user;
        res.locals.user = user;
        req.user.authMethod = 'jwt';
        return next();
      }
    }

    // 3. If no valid auth, redirect to login with original URL
    const redirectUrl = req.originalUrl !== '/' 
      ? `?redirect=${encodeURIComponent(req.originalUrl)}` 
      : '';
    return res.redirect(`/login${redirectUrl}`);

  } catch (error) {
    console.error('Authentication error:', error.message);
    
    // Handle JWT errors differently for web
    if (JWT_ERRORS[error.name]) {
      return res.redirect(`/login?error=${encodeURIComponent(error.name)}`);
    }
    
    return res.redirect('/login?error=auth');
  }
};

/**
 * Middleware to require session OR JWT login for API routes (returns JSON)
 */
const requireApiLogin = async (req, res, next) => {
  try {
    // 1. Check session-based auth
    if (req.session?.userId) {
      const user = await User.findById(req.session.userId)
        .select('-password -refreshToken')
        .lean();
      
      if (user) {
        req.user = { ...user, authMethod: 'session' };
        return next();
      }
    }

    // 2. Check JWT-based auth
    const token = extractToken(req);
    if (token) {
      const decoded = verifyJwtToken(token);
      const user = await User.findById(decoded.id)
        .select('-password -refreshToken')
        .lean();
      
      if (user) {
        req.user = { ...user, authMethod: 'jwt' };
        return next();
      }
    }

    // 3. If no valid auth, return 401
    return res.status(401).json({ 
      success: false,
      code: 'NOT_AUTHENTICATED',
      message: 'Please log in to access this resource' 
    });

  } catch (error) {
    console.error('API authentication error:', error.message);
    
    const errorMessage = JWT_ERRORS[error.name] || 'Authentication failed';
    const statusCode = error.name === TOKEN_EXPIRED_ERROR ? 401 : 403;
    
    return res.status(statusCode).json({ 
      success: false,
      code: error.name || 'AUTH_ERROR',
      message: errorMessage 
    });
  }
};

/**
 * Middleware for role-based access control
 * @param {string[]} roles - Allowed roles
 */
const requireRole = (roles) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        code: 'NOT_AUTHENTICATED',
        message: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

// Export all middleware functions
export { 
  verifyToken as default,
  verifyToken,
  requireLogin,
  requireApiLogin,
  requireRole
};