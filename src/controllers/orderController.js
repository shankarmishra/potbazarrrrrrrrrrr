import Order from '../models/orderModels.js';
import mongoose from 'mongoose';
import asyncHandler from '../utils/asyncHandler.js';
import crypto from 'crypto';
import Transaction from '../models/transactionModels.js';
import Razorpay from 'razorpay';
import Product from '../models/productModels.js';
import Category from '../models/categoryModels.js'; // <-- Import Category model

// Constants
const DEFAULT_DELIVERY_DAYS = 3;
const MIN_ORDER_AMOUNT = 1; // 1 INR
const MAX_ORDER_AMOUNT = 1000000; // 10,00,000 INR
const ORDER_STATUSES = ['Order Placed', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];

// Initialize Razorpay instance
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || '',
    key_secret: process.env.RAZORPAY_PAY_SECRET || '',
});

// Helper functions
const validateCartItems = async (cartItems) => {
    if (!Array.isArray(cartItems) || cartItems.length === 0) {
        return { valid: false, message: "Cart must contain at least one item" };
    }

    for (const item of cartItems) {
        if (!mongoose.Types.ObjectId.isValid(item.product)) {
            return { valid: false, message: "Invalid product ID in cart" };
        }

        if (!item.quantity || item.quantity < 1) {
            return { valid: false, message: "Invalid quantity for product" };
        }

        const product = await Product.findById(item.product);
        if (!product) {
            return { valid: false, message: `Product not found: ${item.product}` };
        }

        if (product.quantity < item.quantity) {
            return { 
                valid: false, 
                message: `Insufficient stock for product: ${product.name}` 
            };
        }

        if (!product.price || product.price <= 0) {
            return { 
                valid: false, 
                message: `Invalid price for product: ${product.name}` 
            };
        }
    }

    return { valid: true };
};

const calculateOrderTotal = (cartItems) => {
    return cartItems.reduce((total, item) => {
        return total + (item.quantity * item.price);
    }, 0);
};

const verifyPaymentSignature = (orderId, paymentId, signature) => {
    const generatedSignature = crypto
        .createHmac('sha256', process.env.RAZORPAY_PAY_SECRET || '')
        .update(`${orderId}|${paymentId}`)
        .digest('hex');

    return generatedSignature === signature;
};

// Create Razorpay Transaction (Order)
const createTransaction = asyncHandler(async (req, res) => {
    const { amount, userId } = req.body;

    // Validate input
    if (!amount || isNaN(amount) || amount < MIN_ORDER_AMOUNT || amount > MAX_ORDER_AMOUNT) {
        return res.status(400).json({ 
            success: false, 
            message: `Amount must be between ₹${MIN_ORDER_AMOUNT} and ₹${MAX_ORDER_AMOUNT}` 
        });
    }

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ 
            success: false, 
            message: "Valid User ID is required" 
        });
    }

    // Check Razorpay credentials
    if (!razorpay.key_id || !razorpay.key_secret) {
        console.error('Razorpay credentials missing');
        return res.status(500).json({ 
            success: false, 
            message: "Payment service unavailable" 
        });
    }

    try {
        const options = {
            amount: Math.round(amount * 100), // amount in paise
            currency: "INR",
            receipt: `rcpt_${Date.now()}_${String(userId).slice(-6)}`,
            notes: {
                userId: userId.toString()
            }
        };
        const razorpayOrder = await razorpay.orders.create(options);
        
        res.status(200).json({
            success: true,
            message: "Order created successfully",
            data: {
                key: razorpay.key_id,
                amount: razorpayOrder.amount,
                currency: razorpayOrder.currency,
                orderId: razorpayOrder.id,
                receipt: razorpayOrder.receipt
            }
        });

    } catch (error) {
        console.error('Razorpay order creation error:', error);
        res.status(500).json({
            success: false,
            message: "Payment gateway error",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Create an Order after Payment Verification
const createOrder = asyncHandler(async (req, res) => {
    const {
        razorpayOrderId,
        razorpayPaymentId,
        razorpaySignature,
        userId,
        cartItems,
        deliveryDate,
        address
    } = req.body;

    // Validate required fields
    if (!razorpayOrderId || !razorpayPaymentId || !razorpaySignature) {
        return res.status(400).json({ 
            success: false, 
            message: "Payment verification failed" 
        });
    }

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ 
            success: false, 
            message: "Valid User ID is required" 
        });
    }

    // Address validation: must have all required fields
    if (
        !address ||
        !address.name ||
        !address.phone ||
        !address.street ||
        !address.city ||
        !address.state ||
        !address.pincode ||
        !address.country
    ) {
        return res.status(400).json({ 
            success: false, 
            message: "Complete shipping address is required (name, phone, street, city, state, pincode, country)" 
        });
    }

    // Validate cart items
    const cartValidation = await validateCartItems(cartItems);
    if (!cartValidation.valid) {
        return res.status(400).json({ 
            success: false, 
            message: cartValidation.message 
        });
    }

    // Verify payment signature
    if (!verifyPaymentSignature(razorpayOrderId, razorpayPaymentId, razorpaySignature)) {
        return res.status(400).json({ 
            success: false, 
            message: "Payment verification failed" 
        });
    }

    try {
        // Calculate order total
        const totalAmount = calculateOrderTotal(cartItems);
        const finalDeliveryDate = deliveryDate || 
            new Date(Date.now() + DEFAULT_DELIVERY_DAYS * 24 * 60 * 60 * 1000);

        // Start transaction
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // Create order
            console.log('Creating order with:', {
              user: req.user?._id,
              address,
              cartItems
            });
            const newOrderArr = await Order.create([{
                user: new mongoose.Types.ObjectId(req.user._id), // <-- FIXED
                items: cartItems.map(item => ({
                    product: new mongoose.Types.ObjectId(item.product),
                    quantity: item.quantity,
                    price: item.price
                })),
                address: {
                    name: address.name,
                    phone: address.phone,
                    street: address.street,
                    city: address.city,
                    state: address.state,
                    pincode: address.pincode,
                    country: address.country
                },
                deliveryDate: finalDeliveryDate,
                status: "Order Placed",
                totalAmount
            }], { session });

            const newOrder = newOrderArr[0]; // Get the created order object

            // Create transaction record
            await Transaction.create([{
                userId: userId,
                order: newOrder._id,
                items: cartItems.map(item => ({
                    product: item.product,
                    quantity: item.quantity,
                    price: item.price
                })),
                totalAmount,
                address: {
                    name: address.name,
                    phone: address.phone,
                    street: address.street,
                    city: address.city,
                    state: address.state,
                    pincode: address.pincode,
                    country: address.country
                },
                paymentStatus: "completed"
            }], { session });

            // Update product stock
            for (const item of cartItems) {
                await Product.findByIdAndUpdate(
                    item.product,
                    { $inc: { quantity: -item.quantity } },
                    { session }
                );
            }

            // Commit transaction
            await session.commitTransaction();
            session.endSession();

            res.status(201).json({
                success: true,
                message: "Order created successfully",
                data: {
                    orderId: newOrder._id,
                    totalAmount,
                    deliveryDate: finalDeliveryDate
                }
            });

        } catch (error) {
            // Rollback transaction on error
            await session.abortTransaction();
            session.endSession();
            throw error;
        }

    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({
            success: false,
            message: "Failed to create order",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get Orders by User ID
const getOrderbyUserId = asyncHandler(async (req, res) => {
    const { userId } = req.params;

    // Validate user ID
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ 
            success: false, 
            message: "Valid User ID is required" 
        });
    }

    try {
        const orders = await Order.find({ user: userId })
            .populate({
                path: "user",
                select: "name email",
                model: "User"
            })
            .populate('items.product', 'name')
            .sort({ createdAt: -1 })
            .lean();

        // Format response data with full delivery address
        const formattedOrders = orders.map(order => ({
            id: order._id,
            status: order.status,
            createdAt: order.createdAt,
            deliveryDate: order.deliveryDate,
            totalAmount: order.totalAmount,
            address: order.address ? {
                name: order.address.name,
                phone: order.address.phone,
                street: order.address.street,
                city: order.address.city,
                state: order.address.state,
                pincode: order.address.pincode,
                country: order.address.country
            } : null,
            items: order.items.map(item => ({
                product: {
                    id: item.product?._id,
                    name: item.product?.name,
                    price: item.product?.price,
                    images: item.product?.images || []
                },
                quantity: item.quantity,
                price: item.price
            }))
        }));

        res.render('orders', { user, orders: formattedOrders, categories });

    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({
            success: false,
            message: "Failed to retrieve orders",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// API: Get orders for logged-in user (JSON)
const getOrdersForUserApi = asyncHandler(async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user._id })
      .populate({
        path: "items.product",
        select: "name images price",
        model: "Product"
      })
      .sort({ createdAt: -1 })
      .lean();

    res.json({ success: true, orders });
  } catch (error) {
    console.error('Error fetching user orders (API):', error);
    res.status(500).json({ success: false, message: "Failed to load orders" });
  }
});

// EJS: Get orders for logged-in user (render page)
const getOrdersForUser = asyncHandler(async (req, res) => {
  try {
    const categories = await Category.find().lean();

    const orders = await Order.find({ user: req.user._id })
      .populate({
        path: "items.product",
        select: "name images price",
        model: "Product"
      })
      .sort({ createdAt: -1 })
      .lean();

    res.render('orders', { user: req.user, orders, categories });
  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).render('orders', { user: req.user, orders: [], categories: [], error: "Error fetching your orders." });
  }
});

// Admin: Get all orders (render page)
const getAllOrders = asyncHandler(async (req, res) => {
  try {
    const categories = await Category.find().lean();
    const orders = await Order.find()
      .populate('user', 'name email')
      .populate('items.product', 'name images');
    console.log(JSON.stringify(orders[0], null, 2));

    res.render('admin/orderList', { orders, isAdmin: true });
  } catch (error) {
    res.status(500).render('admin/orderList', { orders: [], isAdmin: true, categories: [], error: "Failed to retrieve orders." });
  }
});


export { 
    createTransaction, 
    createOrder, 
    getOrderbyUserId,
    getAllOrders,
    getOrdersForUser,
    getOrdersForUserApi
};