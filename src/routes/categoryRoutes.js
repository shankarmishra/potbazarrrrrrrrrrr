import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import adminAuthMiddleware from '../Middleware/adminAuthMiddleware.js';
import {
  getAdminPage,
  createCategory,
  showEditCategory,
  editCategory,
  deleteCategory,
  addSubcategory,
  deleteSubcategory,
  getSubcategoriesPage
} from '../controllers/categoryController.js';
import {
  createProduct,
  deleteProduct
} from '../controllers/productController.js';

// Ensure upload directories exist
const ensureDirExists = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const fullPath = req.baseUrl + req.path;
    let uploadPath;
    if (fullPath.includes('/category')) {
      uploadPath = 'public/uploads/category_images/';
    } else if (fullPath.includes('/subcategory')) {
      uploadPath = 'public/uploads/subcategory_images/';
    } else if (fullPath.includes('/product')) {
      uploadPath = 'public/uploads/product_images/';
    } else {
      return cb(new Error('Invalid upload path'));
    }
    ensureDirExists(uploadPath);
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ storage, fileFilter });

const router = express.Router();

// Apply admin authentication middleware to all routes below
router.use(adminAuthMiddleware);

// Admin dashboard
router.get('/admin', getAdminPage);

// Category routes
router.get('/add', getAdminPage); // Show add category form
router.post('/add', upload.single('image_file'), createCategory);
router.get('/edit/:id', showEditCategory);
router.post('/edit/:id', upload.single('image_file'), editCategory);
router.post('/delete/:id', deleteCategory);

// Subcategory routes
router.get('/subcategory/add', getSubcategoriesPage);
router.post('/subcategory/add', upload.single('image_file'), addSubcategory);
router.post('/subcategory/delete/:subId', deleteSubcategory);

// Product routes (admin)
router.get('/product/add', getAdminPage);
router.post('/product/add', upload.single('image_file'), createProduct);
router.delete('/products/delete/:id', deleteProduct);

export default router;