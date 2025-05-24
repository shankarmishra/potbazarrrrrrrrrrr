import express from 'express';
import multer from 'multer';
import {
    adminLogin,
    adminForgotPassword,
    adminResetPassword,
    adminRegister,
    getAdminDashboard,
    getAdminOrders,
    getAdminUsers,
    createCategory,
    adminLogout
} from '../controllers/adminController.js';
import adminAuthMiddleware from '../Middleware/adminAuthMiddleware.js';
import {
    getAdminProducts,
    createProduct,
    showEditProduct,
    editProduct,
    deleteProduct
} from '../controllers/productController.js';
import Subcategory from '../models/Subcategorymodel.js';

const router = express.Router();
const upload = multer({ dest: 'public/uploads/product_images/' });

// ----------- Public Admin Routes -----------
router.get('/login', (req, res) => {
    res.render('admin/adminlogin', { error: null, success: null });
});
router.post('/login', adminLogin);

router.get('/register', (req, res) => {
    res.render('admin/adminregister', { error: null, success: null });
});
router.post('/register', adminRegister);

router.get('/forgot-password', (req, res) => {
    res.render('admin/adminforgotpassword', { error: null });
});
router.post('/forgot-password', adminForgotPassword);

router.post('/reset-password', adminResetPassword);

// ----------- Protected Admin Routes -----------
router.use(adminAuthMiddleware); // Protect all routes below

router.get('/dashboard', getAdminDashboard);
router.get('/orders', getAdminOrders);
router.get('/users', getAdminUsers);
router.post('/categories', createCategory);

// Product Management (Admin)
router.get('/products', getAdminProducts); // Show add product form + list
router.post('/products/add', upload.array('images', 5), createProduct);
router.get('/products/edit/:id', showEditProduct);
router.post('/products/edit/:id', upload.array('images', 5), editProduct);
router.delete('/products/delete/:id', deleteProduct);

// Subcategory Routes (AJAX for dynamic dropdowns, etc.)
router.get('/subcategories/:categoryId', async (req, res) => {
    try {
        const subs = await Subcategory.find({ category: req.params.categoryId });
        res.json(subs);
    } catch (err) {
        res.status(500).json([]);
    }
});

// Admin Logout
router.get('/logout', adminLogout);

// Optional: Cache control for admin routes
// router.use((req, res, next) => {
//   res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
//   next();
// });

export default router;
