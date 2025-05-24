import jwt from 'jsonwebtoken';

const adminAuthMiddleware = (req, res, next) => {
    // Ensure req.cookies exists
    if (!req.cookies || !req.cookies.adminToken) {
        return res.status(401).redirect('/adminlogin'); // Redirect to login if token is missing
    }

    const token = req.cookies.adminToken;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify the token
        req.admin = decoded; // Store admin info in request object
        res.locals.isAdmin = true; // Pass isAdmin flag to templates
        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        console.error('❌ Invalid token:', error);
        return res.status(401).redirect('/adminlogin'); // Redirect to login if token is invalid
    }
};

export default adminAuthMiddleware;