import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { verifyAdmin } from '../Middleware/adminAuthMiddleware.js';
import Subcategory from '../models/Subcategorymodel.js';
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
  deleteProduct,
  editProduct,
  showEditProduct
} from '../controllers/productController.js';

// Ensure upload directories exist
const ensureDirExists = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath;
    if (req.baseUrl.includes('/category') && req.path.includes('/product')) {
      uploadPath = 'public/uploads/product_images/';
    } else if (req.baseUrl.includes('/category') && req.path.includes('/subcategory')) {
      uploadPath = 'public/uploads/subcategory_images/';
    } else if (req.baseUrl.includes('/category')) {
      uploadPath = 'public/uploads/category_images/';
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
router.use(verifyAdmin);

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
router.post('/product/add', upload.array('images', 5), createProduct);
router.post('/products/edit/:id', upload.array('images', 5), editProduct);
router.get('/products/edit/:id', showEditProduct); // <-- Make sure this GET route exists!
router.delete('/products/delete/:id', deleteProduct);

// Get subcategories by category ID (AJAX)
router.get('/subcategories/:categoryId', async (req, res) => {
  const subs = await Subcategory.find({ category: req.params.categoryId });
  res.json(subs);
});

export default router;