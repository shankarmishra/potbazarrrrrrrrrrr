import Category from '../models/categoryModels.js';
import Subcategory from '../models/Subcategorymodel.js';
import Product from '../models/productModels.js';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

dotenv.config();

// Helper function to fetch all data
const fetchAllData = async () => {
  const categories = await Category.find();
  const subcategories = await Subcategory.find().populate('category');
  const products = await Product.find().populate({
    path: 'subcategory',
    populate: { path: 'category' }
  });
  return { categories, subcategories, products };
};

// Get Admin Page
export const getAdminPage = async (req, res) => {
  try {
    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: null,
      subcategoryError: null,
      subcategorySuccess: null
    });
  } catch (error) {
    console.error('Error fetching admin page:', error);
    res.status(500).render('admin/addCategory', {
      categories: [],
      subcategories: [],
      products: [],
      error: 'Could not fetch data.',
      success: null,
      subcategoryError: null,
      subcategorySuccess: null
    });
  }
};

// Add Subcategory
// Helper function to fetch subcategory page data
const fetchSubcategoryData = async () => {
  const categories = await Category.find();
  const subcategories = await Subcategory.find().populate('category');
  const products = await Product.find().populate({
    path: 'subcategory',
    populate: { path: 'category' }
  });
  return { categories, subcategories, products };
};

// Render Subcategory Page
export const getSubcategoriesPage = async (req, res) => {
  try {
    const categories = await Category.find().lean();
    const subcategories = await Subcategory.find().populate('category', 'name').lean();

    res.render('admin/subcategory', {
      categories,
      subcategories,
      subcategoryError: null,
      subcategorySuccess: req.query.success || null
    });
  } catch (error) {
    console.error(error);
    res.render('admin/subcategory', {
      categories: [],
      subcategories: [],
      subcategoryError: 'Failed to load subcategories.',
      subcategorySuccess: null
    });
  }
};


// Add Subcategory
export const addSubcategory = async (req, res) => {
  const { name, description, category } = req.body;
  try {
    const categoryExists = await Category.findById(category);
    if (!categoryExists) {
      const data = await fetchSubcategoryData();
      return res.render('admin/subcategory', {
        ...data,
        subcategoryError: 'Invalid category selected.',
        subcategorySuccess: null
      });
    }

    const existing = await Subcategory.findOne({ name, category });
    if (existing) {
      const data = await fetchSubcategoryData();
      return res.render('admin/subcategory', {
        ...data,
        subcategoryError: 'Subcategory already exists for this category.',
        subcategorySuccess: null
      });
    }

    let image_uri = '';
    if (req.file) {
      image_uri = `/uploads/subcategory_images/${req.file.filename}`;
    }

    await Subcategory.create({ name, description, image_uri, category });

    // Fetch fresh data to render with success message
    const data = await fetchSubcategoryData();

    res.render('admin/subcategory', {
      ...data,
      subcategorySuccess: 'Subcategory added successfully.',
      subcategoryError: null
    });

  } catch (error) {
    console.error('Error adding subcategory:', error);
    const data = await fetchSubcategoryData();
    res.render('admin/subcategory', {
      ...data,
      subcategoryError: 'Error adding subcategory.',
      subcategorySuccess: null
    });
  }
};


// Delete Subcategory
export const deleteSubcategory = async (req, res) => {
  const { subId } = req.params;
  try {
    // Delete all products in this subcategory
    await Product.deleteMany({ subcategory: subId });

    // Now delete the subcategory itself
    await Subcategory.findByIdAndDelete(subId);

    const data = await fetchSubcategoryData();
    res.render('admin/subcategory', {
      ...data,
      subcategorySuccess: 'Subcategory and all its products deleted successfully.',
      subcategoryError: null
    });
  } catch (error) {
    console.error('Error deleting subcategory:', error);
    const data = await fetchSubcategoryData();
    res.render('admin/subcategory', {
      ...data,
      subcategoryError: 'Error deleting subcategory.',
      subcategorySuccess: null
    });
  }
};


// Create Category
export const createCategory = async (req, res) => {
  const { name, description } = req.body;
  try {
    let { categories, subcategories, products } = await fetchAllData();

    // Check for existing category
    const exists = await Category.findOne({ name });
    if (exists) {
      return res.render('admin/addCategory', {
        categories,
        subcategories,
        products,
        error: 'Category already exists.',
        success: null,
        subcategoryError: null,
        subcategorySuccess: null
      });
    }

    // Handle image upload
    let image_uri = '';
    if (req.file) {
      image_uri = `/uploads/category_images/${req.file.filename}`;
    }

    await Category.create({ name, description, image_uri });

    // Refresh data
    ({ categories, subcategories, products } = await fetchAllData());
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: 'Category added successfully.',
      subcategoryError: null,
      subcategorySuccess: null
    });
  } catch (error) {
    console.error('Error adding category:', error);
    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: 'Error adding category.',
      success: null,
      subcategoryError: null,
      subcategorySuccess: null
    });
  }
};

// Show Edit Category Form
export const showEditCategory = async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.redirect('/admin');
    }

    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/editCategory', {
      category,
      categories,
      subcategories,
      products,
      error: null,
      success: null,
      subcategoryError: null,
      subcategorySuccess: null
    });
  } catch (error) {
    console.error('Error loading edit category form:', error);
    res.redirect('/admin');
  }
};

// Handle Edit Category
export const editCategory = async (req, res) => {
  const { name, description } = req.body;
  try {
    let updateFields = { name, description };

    if (req.file) {
      updateFields.image_uri = `/uploads/category_images/${req.file.filename}`;
    }

    await Category.findByIdAndUpdate(req.params.id, updateFields);

    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: 'Category updated successfully.',
      subcategoryError: null,
      subcategorySuccess: null
    });
  } catch (error) {
    console.error('Error updating category:', error);
    const category = await Category.findById(req.params.id);
    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/editCategory', {
      category,
      categories,
      subcategories,
      products,
      error: 'Error updating category.',
      success: null,
      subcategoryError: null,
      subcategorySuccess: null
    });
  }
};

// Delete Category
export const deleteCategory = async (req, res) => {
  const { id } = req.params;
  try {
    let { categories, subcategories, products } = await fetchAllData();

    // Find all subcategories for this category
    const subcats = await Subcategory.find({ category: id });

    // For each subcategory, delete all its products
    for (const subcat of subcats) {
      await Product.deleteMany({ subcategory: subcat._id });
    }

    // Delete all subcategories for this category
    await Subcategory.deleteMany({ category: id });

    // Now delete the category itself
    await Category.findByIdAndDelete(id);

    // Refresh data
    ({ categories, subcategories, products } = await fetchAllData());
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: 'Category and all its subcategories/products deleted successfully.',
      subcategoryError: null,
      subcategorySuccess: null
    });
  } catch (error) {
    console.error('Error deleting category:', error);
    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: 'Error deleting category.',
      success: null,
      subcategoryError: null,
      subcategorySuccess: null
    });
  }
};

// Add Product
export const addProduct = async (req, res) => {
  const { name, description, price, subcategory } = req.body;
  try {
    let { categories, subcategories, products } = await fetchAllData();

    // Validate subcategory exists
    const subcategoryExists = await Subcategory.findById(subcategory);
    if (!subcategoryExists) {
      return res.render('admin/addCategory', {
        categories,
        subcategories,
        products,
        error: null,
        success: null,
        subcategoryError: null,
        subcategorySuccess: null,
        productError: 'Invalid subcategory selected.',
        productSuccess: null
      });
    }

    // Check for existing product
    const existing = await Product.findOne({ name, subcategory });
    if (existing) {
      return res.render('admin/addCategory', {
        categories,
        subcategories,
        products,
        error: null,
        success: null,
        subcategoryError: null,
        subcategorySuccess: null,
        productError: 'Product already exists in this subcategory.',
        productSuccess: null
      });
    }

    // Handle image upload
    let image_uri = '';
    if (req.file) {
      image_uri = `/uploads/product_images/${req.file.filename}`;
    }

    await Product.create({ name, description, price, image_uri, subcategory });

    // Refresh data
    ({ categories, subcategories, products } = await fetchAllData());
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: null,
      subcategoryError: null,
      subcategorySuccess: null,
      productError: null,
      productSuccess: 'Product added successfully.'
    });
  } catch (error) {
    console.error('Error adding product:', error);
    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: null,
      subcategoryError: null,
      subcategorySuccess: null,
      productError: 'Error adding product.',
      productSuccess: null
    });
  }
};

// Delete Product
export const deleteProduct = async (req, res) => {
  const { productId } = req.params;
  try {
    await Product.findByIdAndDelete(productId);

    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: null,
      subcategoryError: null,
      subcategorySuccess: null,
      productError: null,
      productSuccess: 'Product deleted successfully.'
    });
  } catch (error) {
    console.error('Error deleting product:', error);
    const { categories, subcategories, products } = await fetchAllData();
    res.render('admin/addCategory', {
      categories,
      subcategories,
      products,
      error: null,
      success: null,
      subcategoryError: null,
      subcategorySuccess: null,
      productError: 'Error deleting product.',
      productSuccess: null
    });
  }
};

// Get Products
export const getProducts = async (req, res) => {
  const { category, sub } = req.query;
  try {
    const categories = await Category.find().lean();

    let categoryObj = null;
    let subCategoryObj = null;
    let categoryName = '';
    let subCategoryName = '';
    let categoryDescription = '';

    // Support category by ID or name
    if (category) {
      if (mongoose.Types.ObjectId.isValid(category)) {
        categoryObj = await Category.findById(category).lean();
      }
      if (!categoryObj) {
        categoryObj = await Category.findOne({ name: { $regex: new RegExp('^' + category + '$', 'i') } }).lean();
      }
      if (categoryObj) {
        categoryName = categoryObj.name;
        categoryDescription = categoryObj.description || '';
      }
    }

    // Support subcategory by ID or name
    if (sub) {
      if (mongoose.Types.ObjectId.isValid(sub)) {
        subCategoryObj = await Subcategory.findById(sub).lean();
      }
      if (!subCategoryObj) {
        subCategoryObj = await Subcategory.findOne({ name: { $regex: new RegExp('^' + sub + '$', 'i') } }).lean();
      }
      if (subCategoryObj) {
        subCategoryName = subCategoryObj.name;
      }
    }

    // Build product filter
    let filter = {};
    if (subCategoryObj) {
      filter.subcategory = subCategoryObj._id;
    } else if (categoryObj) {
      const subcats = await Subcategory.find({ category: categoryObj._id }).lean();
      filter.subcategory = { $in: subcats.map(s => s._id) };
    }

    const products = await Product.find(filter).populate({
      path: 'subcategory',
      populate: { path: 'category' }
    }).lean();

    res.render('category', {
      user: req.user || res.locals.user || null,
      categories,
      products,
      categoryName,
      subCategoryName,
      categoryDescription
    });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.render('category', {
      user: req.user || res.locals.user || null,
      categories: [],
      products: [],
      categoryName: '',
      subCategoryName: '',
      categoryDescription: '',
      error: 'Error fetching products.'
    });
  }
};

// Edit Product
export const showEditProduct = async (req, res) => {
  const { id } = req.params;
  try {
    const product = await Product.findById(id).populate('subcategory').lean();
    const categories = await Category.find().lean();
    const subcategories = await Subcategory.find().populate('category').lean();

    if (!product) {
      return res.status(404).render('admin/editProduct', {
        product: null,
        categories,
        subcategories,
        error: 'Product not found.',
        success: null
      });
    }

    res.render('admin/editProduct', {
      product,
      categories,
      subcategories,
      error: null,
      success: null
    });
  } catch (error) {
    console.error('Error fetching product for edit:', error);
    res.status(500).render('admin/editProduct', {
      product: null,
      categories: [],
      subcategories: [],
      error: 'Error fetching product.',
      success: null
    });
  }
};

// Update Product
export const editProduct = async (req, res) => {
  const { id } = req.params;
  const { name, description, price, subcategory } = req.body;

  try {
    let updateData = { name, description, price, subcategory };

    // Handle image upload
    if (req.files && req.files.length > 0) {
      updateData.image_uri = `/uploads/product_images/${req.files[0].filename}`;
    }

    await Product.findByIdAndUpdate(id, updateData);

    // Optionally, you can fetch the updated product data and return it
    const updatedProduct = await Product.findById(id).populate('subcategory').lean();

    res.render('admin/editProduct', {
      product: updatedProduct,
      categories: await Category.find().lean(),
      subcategories: await Subcategory.find().populate('category').lean(),
      error: null,
      success: 'Product updated successfully.'
    });
  } catch (error) {
    console.error('Error updating product:', error);
    res.render('admin/editProduct', {
      product: null,
      categories: await Category.find().lean(),
      subcategories: await Subcategory.find().populate('category').lean(),
      error: 'Error updating product.',
      success: null
    });
  }
};