import Product from "../models/productModels.js";
import Category from "../models/categoryModels.js";
import Review from "../models/reviewModels.js";
import Subcategory from "../models/Subcategorymodel.js";
import User from '../models/userModels.js';
import mongoose from 'mongoose';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

// Constants
const MIN_IMAGES = 2;
const MAX_IMAGES = 5;
const MAX_RECOMMENDATIONS = 6;
const VALID_RATINGS = [1, 2, 3, 4, 5];

// Helper functions
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const getUserFromSession = async (req) => {
  if (req.session?.userId) {
    return await User.findById(req.session.userId).lean();
  }
  return null;
};

const validateProductInput = (data, files) => {
  const errors = [];
  
  if (!data.name || data.name.trim().length < 3) {
    errors.push('Product name must be at least 3 characters');
  }
  
  if (!data.price || isNaN(data.price) || parseFloat(data.price) <= 0) {
    errors.push('Price must be a positive number');
  }
  
  if (!data.stock || isNaN(data.stock) || parseInt(data.stock) < 0) {
    errors.push('Stock must be a non-negative number');
  }
  
  if (!data.description || data.description.trim().length < 10) {
    errors.push('Description must be at least 10 characters');
  }
  
  if (!data.category || !mongoose.Types.ObjectId.isValid(data.category)) {
    errors.push('Valid category is required');
  }
  
  if (files) {
    if (files.length < MIN_IMAGES || files.length > MAX_IMAGES) {
      errors.push(`Please upload between ${MIN_IMAGES} and ${MAX_IMAGES} images`);
    }
  }
  
  return errors.length ? errors : null;
};

const deleteOldImages = async (images) => {
  try {
    for (const image of images) {
      const imagePath = path.join(__dirname, '../public', image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
  } catch (error) {
    console.error('Error deleting old images:', error);
  }
};

// Product Controller
export const productController = {
  // Get all products with filtering
  getProducts: async (req, res) => {
    try {
      const { category, sub } = req.query;
      const categories = await Category.find().lean();
      const user = await getUserFromSession(req);

      let query = {};
      let categoryDoc = null;
      let subCategoryDoc = null;
      let categoryName = '';
      let subCategoryName = '';
      let categoryDescription = '';

      if (category) {
        categoryDoc = await Category.findOne({ 
          name: { $regex: new RegExp('^' + category + '$', 'i') } 
        });
        if (categoryDoc) {
          query.category = categoryDoc._id;
          categoryName = categoryDoc.name;
          categoryDescription = categoryDoc.description || '';
        }
      }

      if (sub) {
        subCategoryDoc = await Subcategory.findOne({ 
          name: { $regex: new RegExp('^' + sub + '$', 'i') } 
        });
        if (subCategoryDoc) {
          query.subcategory = subCategoryDoc._id;
          subCategoryName = subCategoryDoc.name;
        }
      }

      const products = await Product.find(query).lean();

      res.render('category', {
        user,
        categories,
        products,
        categoryName,
        subCategoryName,
        categoryDescription
      });

    } catch (error) {
      console.error('Error fetching products:', error);
      const categories = await Category.find().lean();
      res.render('category', {
        user: null,
        categories,
        products: [],
        categoryName: '',
        subCategoryName: '',
        categoryDescription: '',
        error: 'Error fetching products. Please try again later.'
      });
    }
  },

  // Create a new product
  createProduct: async (req, res) => {
    try {
      const { name, price, stock, description, category, subcategory } = req.body;
      const categories = await Category.find().lean();
      const products = await Product.find().populate('category').populate('subcategory').lean();

      // Validate input
      const validationErrors = validateProductInput(req.body, req.files);
      if (validationErrors) {
        return res.render('admin/addProduct', {
          categories,
          products,
          error: validationErrors.join(', '),
          success: null,
          editProduct: null
        });
      }

      // Process images
      const images = req.files.map(file => '/uploads/product_images/' + file.filename);

      const product = new Product({
        name,
        images,
        price: parseFloat(price),
        stock: parseInt(stock),
        description,
        category,
        subcategory
      });

      await product.save();

      res.redirect('/admin/products?success=Product created successfully');

    } catch (error) {
      console.error('Error creating product:', error);
      const categories = await Category.find().lean();
      const products = await Product.find().populate('category').populate('subcategory').lean();
      res.render('admin/addProduct', {
        categories,
        products,
        error: 'Failed to create product. Please try again.',
        success: null,
        editProduct: null
      });
    }
  },

  // Get product details with reviews
  getProductDetails: async (req, res) => {
    try {
      const { id } = req.query;
      if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).render('error', { message: 'Invalid product ID' });
      }

      const product = await Product.findById(id).lean();
      if (!product) {
        return res.status(404).render('error', { message: 'Product not found' });
      }

      const [recommendedProducts, reviews, categories] = await Promise.all([
        Product.find({
          category: product.category,
          _id: { $ne: id }
        }).limit(MAX_RECOMMENDATIONS).lean(),
        Review.find({ product: id }).sort({ createdAt: -1 }).lean(),
        Category.find().lean()
      ]);

      // Calculate review stats
      const totalRatings = reviews.length;
      const avgRating = totalRatings 
        ? (reviews.reduce((sum, r) => sum + r.rating, 0) / totalRatings) 
        : 0;
      
      const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
      reviews.forEach(r => ratingCounts[r.rating]++);

      const reviewStats = { 
        avgRating, 
        totalRatings, 
        ratingCounts 
      };

      const user = await getUserFromSession(req);

      res.render('productdetails', {
        product,
        recommendedProducts,
        reviews,
        reviewStats,
        categories,
        user
      });

    } catch (error) {
      console.error('Error fetching product details:', error);
      res.status(500).render('error', { message: 'Server error' });
    }
  },

  // Submit a review
  submitReview: async (req, res) => {
    try {
      const { productId, title, text, rating } = req.body;
      const userId = req.user?._id;

      // Validate input
      if (!productId || !mongoose.Types.ObjectId.isValid(productId)) {
        return res.status(400).json({ success: false, message: 'Invalid product ID' });
      }

      if (!title || title.trim().length < 3) {
        return res.status(400).json({ success: false, message: 'Title must be at least 3 characters' });
      }

      if (!text || text.trim().length < 10) {
        return res.status(400).json({ success: false, message: 'Review text must be at least 10 characters' });
      }

      const numericRating = parseInt(rating);
      if (isNaN(numericRating)) {
        return res.status(400).json({ success: false, message: 'Invalid rating' });
      }

      if (!VALID_RATINGS.includes(numericRating)) {
        return res.status(400).json({ success: false, message: 'Rating must be between 1 and 5' });
      }

      // Check for existing review
      if (userId) {
        const existingReview = await Review.findOne({ product: productId, user: userId });
        if (existingReview) {
          return res.status(400).json({ success: false, message: 'You have already reviewed this product' });
        }
      }

      // Create review
      const review = new Review({
        product: productId,
        user: userId,
        title,
        text,
        rating: numericRating
      });

      await review.save();

      return res.status(201).json({ 
        success: true, 
        message: 'Review submitted successfully',
        reviewId: review._id
      });

    } catch (error) {
      console.error('Error submitting review:', error);
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to submit review',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Show edit product form
  showEditProduct: async (req, res) => {
    try {
      const [categories, products, editProduct] = await Promise.all([
        Category.find().lean(),
        Product.find().populate('category').populate('subcategory').lean(),
        Product.findById(req.params.id).lean()
      ]);

      if (!editProduct) {
        return res.status(404).render('error', { message: 'Product not found' });
      }

      res.render('admin/addProduct', {
        categories,
        products,
        error: null,
        success: null,
        editProduct
      });

    } catch (error) {
      console.error('Error showing edit form:', error);
      res.status(500).render('error', { message: 'Server error' });
    }
  },

  // Update product
  editProduct: async (req, res) => {
    try {
      const { id } = req.params;
      const { name, price, stock, description, category, subcategory } = req.body;

      if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).render('error', { message: 'Invalid product ID' });
      }

      // Validate input
      const validationErrors = validateProductInput(req.body, req.files);
      if (validationErrors) {
        const categories = await Category.find().lean();
        const products = await Product.find().populate('category').populate('subcategory').lean();
        const editProduct = await Product.findById(id).lean();
        
        return res.render('admin/addProduct', {
          categories,
          products,
          error: validationErrors.join(', '),
          success: null,
          editProduct
        });
      }

      // Get existing product to handle image deletion
      const existingProduct = await Product.findById(id);
      if (!existingProduct) {
        return res.status(404).render('error', { message: 'Product not found' });
      }

      // Prepare update data
      const updateData = {
        name,
        price: parseFloat(price),
        stock: parseInt(stock),
        description,
        category,
        subcategory
      };

      // Handle new images if uploaded
      if (req.files && req.files.length >= MIN_IMAGES && req.files.length <= MAX_IMAGES) {
        // Delete old images
        await deleteOldImages(existingProduct.images);
        updateData.images = req.files.map(file => '/uploads/product_images/' + file.filename);
      }

      await Product.findByIdAndUpdate(id, updateData);

      res.redirect('/admin/products?success=Product updated successfully');

    } catch (error) {
      console.error('Error editing product:', error);
      res.status(500).render('error', { message: 'Failed to update product' });
    }
  },

  // Delete product
  deleteProduct: async (req, res) => {
    try {
      const { id } = req.params;

      if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid product ID' });
      }

      const product = await Product.findById(id);
      if (!product) {
        return res.status(404).json({ success: false, message: 'Product not found' });
      }

      // Delete associated images
      await deleteOldImages(product.images);

      // Delete product
      await Product.findByIdAndDelete(id);

      res.json({ success: true, message: 'Product deleted successfully' });

    } catch (error) {
      console.error('Error deleting product:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to delete product',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Get all products for admin
  getAdminProducts: async (req, res) => {
    try {
      const [categories, products] = await Promise.all([
        Category.find().lean(),
        Product.find().populate('category').populate('subcategory').lean()
      ]);

      let success = null;
      if (req.query.success) {
        success = decodeURIComponent(req.query.success);
      }

      res.render('admin/addProduct', {
        categories,
        products,
        error: null,
        success,
        editProduct: null
      });

    } catch (error) {
      console.error('Error fetching admin products:', error);
      res.status(500).render('error', { message: 'Failed to load products' });
    }
  },

  // Show home page with products
  showHomePage: async (req, res) => {
    try {
      const [categories, subcategories, products] = await Promise.all([
        Category.find().lean(),
        Subcategory.find().lean(),
        Product.find().populate('category').lean()
      ]);

      // Organize subcategories by category
      const subMap = {};
      subcategories.forEach(sub => {
        if (!subMap[sub.category]) subMap[sub.category] = [];
        subMap[sub.category].push(sub);
      });

      // Attach subcategories and products to categories
      categories.forEach(cat => {
        cat.subcategories = subMap[cat._id] || [];
        cat.products = products.filter(p => 
          p.category && String(p.category._id) === String(cat._id)
        );
      });

      const user = await getUserFromSession(req);

      res.render('home', { 
        categories, 
        products, 
        user,
        currentYear: new Date().getFullYear()
      });

    } catch (error) {
      console.error('Error loading home page:', error);
      res.status(500).render('error', { 
        message: 'Failed to load home page',
        user: null
      });
    }
  },

  // Add a new product (admin)
  addProduct: async (req, res) => {
    try {
      const { name, price, stock, description, category, subcategory } = req.body;
      const categories = await Category.find().lean();
      const products = await Product.find().populate('category').populate('subcategory').lean();

      // Validate input (reuse your helper)
      const validationErrors = validateProductInput(req.body, req.files);
      if (validationErrors) {
        return res.render('admin/addProduct', {
          categories,
          products,
          error: validationErrors.join(', '),
          success: null,
          editProduct: null
        });
      }

      // Process images
      const images = req.files.map(file => '/uploads/product_images/' + file.filename);

      const product = new Product({
        name,
        images,
        price: parseFloat(price),
        stock: parseInt(stock),
        description,
        category,
        subcategory
      });

      await product.save();

      res.redirect('/admin/products?success=Product added successfully');
    } catch (error) {
      console.error('Error adding product:', error);
      const categories = await Category.find().lean();
      const products = await Product.find().populate('category').populate('subcategory').lean();
      res.render('admin/addProduct', {
        categories,
        products,
        error: 'Failed to add product. Please try again.',
        success: null,
        editProduct: null
      });
    }
  }
};

// Export both named and default for compatibility
export const {
  getProducts,
  createProduct,
  getProductDetails,
  submitReview,
  showEditProduct,
  editProduct,
  deleteProduct,
  getAdminProducts,
  showHomePage,
  addProduct
} = productController;

export default productController;

// This code defines a product controller for managing products in an e-commerce application.
// It includes functions for fetching products, creating, editing, deleting products, and handling reviews.