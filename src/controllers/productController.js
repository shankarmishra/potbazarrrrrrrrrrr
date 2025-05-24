import Product from "../models/productModels.js";
import Category from "../models/categoryModels.js";
import Review from "../models/reviewModels.js";
import Subcategory from "../models/Subcategorymodel.js";
import User from '../models/userModels.js'; // adjust path if needed
import path from "path";
import mongoose from 'mongoose';

async function getUserFromSession(req) {
  if (req.session && req.session.userId) {
    return await User.findById(req.session.userId).lean();
  }
  return null;
}

export const getProducts = async (req, res) => {
  const { category, sub } = req.query;
  try {
    // Always fetch categories for navbar/categorybar
    const categories = await Category.find().lean();
    const user = req.user || res.locals.user || null;

    let query = {};
    let categoryDoc = null;
    let subCategoryDoc = null;
    let categoryName = '';
    let subCategoryName = '';
    let categoryDescription = '';

    // Find category by name (case-insensitive)
    if (category) {
      categoryDoc = await Category.findOne({ name: { $regex: new RegExp('^' + category + '$', 'i') } });
      if (categoryDoc) {
        query.category = categoryDoc._id;
        categoryName = categoryDoc.name;
        categoryDescription = categoryDoc.description || '';
      }
    }

    // Find subcategory by name (case-insensitive)
    if (sub) {
      subCategoryDoc = await Subcategory.findOne({ name: { $regex: new RegExp('^' + sub + '$', 'i') } });
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
    // Always pass categories even on error
    const categories = await Category.find().lean();
    res.render('category', {
      user: req.user || res.locals.user || null,
      categories,
      products: [],
      categoryName: '',
      subCategoryName: '',
      categoryDescription: '',
      error: 'Error fetching products.'
    });
  }
};

// Create a new product
const createProduct = async (req, res) => {
  try {
    const { name, price, stock, description, category, subcategory } = req.body;
    const categories = await Category.find();
    const products = await Product.find().populate('category').populate('subcategory');

    // Validate images
    let images = [];
    if (req.files && req.files.length >= 2 && req.files.length <= 5) {
      images = req.files.map(file => '/uploads/product_images/' + file.filename);
    } else {
      return res.render('admin/addProduct', {
        categories,
        products,
        error: 'Please upload 2 to 5 images.',
        success: null,
        editProduct: null
      });
    }

    // Create and save product
    const product = new Product({
      name,
      images,
      price,
      stock: Number(stock),
      description,
      category,
      subcategory
    });

    await product.save();

    // Optionally update category with product reference (if you have a products array in Category)
    // await Category.findByIdAndUpdate(category, { $push: { products: product._id } });

    res.redirect('/admin/products?success=1');
  } catch (error) {
    console.error('Error creating product:', error);
    const categories = await Category.find();
    const products = await Product.find().populate('category').populate('subcategory');
    res.render('admin/addProduct', {
      categories,
      products,
      error: 'Server error.',
      success: null,
      editProduct: null
    });
  }
};

// Get product details with reviews and recommendations
const getProductDetails = async (req, res) => {
  const { id } = req.query;
  try {
    const product = await Product.findById(id);
    if (!product) return res.status(404).send('Product not found');

    const recommendedProducts = await Product.find({
      category: product.category,
      _id: { $ne: id }
    }).limit(6);

    const reviews = await Review.find({ product: id }).sort({ createdAt: -1 });

    const totalRatings = reviews.length;
    const avgRating = totalRatings ? reviews.reduce((sum, r) => sum + r.rating, 0) / totalRatings : 0;
    const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    reviews.forEach(r => ratingCounts[r.rating]++);
    const aspects = { Camera: 0, Battery: 0, Display: 0, Value: 0 };

    const reviewStats = { avgRating, totalRatings, totalReviews: totalRatings, ratingCounts, aspects };

    // Fetch all categories and subcategories for the menu
    const categories = await Category.find().lean();
    const subcategories = await Subcategory.find().lean();

    // Attach subcategories to their categories
    const subMap = {};
    subcategories.forEach(sub => {
      if (!subMap[sub.category]) subMap[sub.category] = [];
      subMap[sub.category].push(sub);
    });
    categories.forEach(cat => {
      cat.subcategories = subMap[cat._id] || [];
    });

    const user = await getUserFromSession(req);
    res.render('productdetails', {
      product,
      recommendedProducts,
      reviews,
      reviewStats,
      categories,
      user // <-- pass user here!
    });
  } catch (error) {
    console.error('Error fetching product details:', error);
    res.status(500).send('Server Error');
  }
};

// Submit a review
const submitReview = async (req, res) => {
  try {
    const { productId, title, text, rating } = req.body;

    // Debug: log incoming request body
    console.log("Review body:", req.body);

    // Validate required fields
    if (!productId || !title || !text || rating === undefined) {
      console.error("Validation failed: Missing required fields", req.body);
      return res.status(400).json({ message: "All fields are required." });
    }

    // Check if productId is valid
    if (!mongoose.Types.ObjectId.isValid(productId)) {
      console.error("Validation failed: Invalid product ID", productId);
      return res.status(400).json({ message: "Invalid product ID." });
    }

    // Validate rating
    const numericRating = Number(rating);
    if (isNaN(numericRating) || numericRating < 1 || numericRating > 5) {
      console.error("Validation failed: Invalid rating", rating);
      return res.status(400).json({ message: "Rating must be a number between 1 and 5." });
    }

    // Optional: Get user ID if logged in
    const userId = req.user ? req.user._id : null;

    // Optional: Check if user already submitted a review
    if (userId) {
      const existingReview = await Review.findOne({ product: productId, user: userId });
      if (existingReview) {
        console.error("Validation failed: Duplicate review by user", userId);
        return res.status(400).json({ message: "You have already reviewed this product." });
      }
    }

    // Create review (only add user if present)
    const reviewData = {
      product: productId,
      title,
      text,
      rating: numericRating
    };
    if (userId) reviewData.user = userId;

    const review = new Review(reviewData);

    await review.save();

    return res.status(201).json({ success: true, message: "Review submitted successfully." });

  } catch (error) {
    console.error("Error submitting review:", error);

    // Handle duplicate key error (unique index violation)
    if (error.code === 11000) {
      return res.status(400).json({ message: "Duplicate review detected." });
    }

    return res.status(500).json({ message: "Something went wrong.", error: error.message });
  }
};


// Show edit product form
const showEditProduct = async (req, res) => {
  try {
    const categories = await Category.find();
    const products = await Product.find().populate('category').populate('subcategory');
    const editProduct = await Product.findById(req.params.id);

    res.render('admin/addProduct', {
      categories,
      products,
      error: null,
      success: null,
      editProduct
    });
  } catch (error) {
    console.error('Error showing edit form:', error);
    res.status(500).send('Server Error');
  }
};

// Edit product
const editProduct = async (req, res) => {
  try {
    const { name, price, stock, description, category, subcategory } = req.body;

    const update = {
      name,
      price,
      stock: Number(stock),
      description,
      category,
      subcategory
    };

    if (req.files && req.files.length >= 2 && req.files.length <= 5) {
      update.images = req.files.map(file => '/uploads/product_images/' + file.filename);
    }

    await Product.findByIdAndUpdate(req.params.id, update);

    const categories = await Category.find();
    const products = await Product.find().populate('category').populate('subcategory');

    res.render('admin/addProduct', {
      categories,
      products,
      error: null,
      success: 'Product updated successfully!',
      editProduct: null
    });
  } catch (error) {
    console.error('Error editing product:', error);
    const categories = await Category.find();
    const products = await Product.find().populate('category').populate('subcategory');
    res.render('admin/addProduct', {
      categories,
      products,
      error: 'Server error.',
      success: null,
      editProduct: null
    });
  }
};

// Delete product
const deleteProduct = async (req, res) => {
  try {
    if (!req.params.id || req.params.id.length !== 24) {
      return res.status(400).json({ success: false, message: 'Invalid product ID' });
    }

    const deletedProduct = await Product.findByIdAndDelete(req.params.id);
    if (!deletedProduct) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

// Admin: fetch all products
const getAdminProducts = async (req, res) => {
  try {
    const categories = await Category.find();
    const products = await Product.find().populate('category').populate('subcategory');
    let success = null;

    if (req.query.success) success = 'Product added successfully!';
    if (req.query.deleted) success = 'Product deleted successfully!';

    res.render('admin/addProduct', {
      categories,
      products,
      error: null,
      success,
      editProduct: null
    });
  } catch (error) {
    console.error('Error fetching admin products:', error);
    res.status(500).send('Server Error');
  }
};

// Home page
const showHomePage = async (req, res) => {
  try {
    const categories = await Category.find().lean();
    const subcategories = await Subcategory.find().lean();

    const subMap = {};
    subcategories.forEach(sub => {
      if (!subMap[sub.category]) subMap[sub.category] = [];
      subMap[sub.category].push(sub);
    });

    categories.forEach(cat => {
      cat.subcategories = subMap[cat._id] || [];
    });

    const products = await Product.find().populate('category').lean();

    categories.forEach(cat => {
      cat.products = products.filter(p => p.category && String(p.category._id) === String(cat._id));
    });

    // Pass user to the view for login check (from session or res.locals)
    res.render('home', { 
      categories, 
      products, 
      user: req.user || res.locals.user || null // <-- add this line
    });
  } catch (error) {
    console.error('Error loading home page:', error);
    res.status(500).render('error', { message: 'Server Error' });
  }
};

export {
  createProduct,
  getProductDetails,
  submitReview,
  showEditProduct,
  editProduct,
  deleteProduct,
  getAdminProducts,
  showHomePage
};
