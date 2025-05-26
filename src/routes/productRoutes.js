import express from 'express';
import { getProducts, getProductDetails, submitReview, addProduct } from '../controllers/productController.js';
import authMiddleware from '../Middleware/userMiddleware.js'; // Token-based
import Product from '../models/productModels.js';


const router = express.Router();

/** ---------- Public Routes ---------- **/

// Get products by category
router.get('/products/:categoryId', getProducts);

// Get all products or by subcategory
router.get('/products', getProducts);

// Get product details
router.get('/productdetails', getProductDetails);

// Get stock for product by ID
router.get('/product/stock/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).select('stock');
    if (!product) {
      return res.status(404).json({ stock: 0, message: 'Product not found' });
    }
    res.json({ stock: product.stock });
  } catch (error) {
    res.status(500).json({ stock: 0, message: 'Error fetching stock' });
  }
});

/** ---------- Protected Routes ---------- **/

// Submit review (JWT/cookie protected)
router.post('/submit-review', authMiddleware, submitReview);



/** ---------- 404 Fallback for Invalid Product Routes ---------- **/
router.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found in productRoutes',
  });
});

export default router;
