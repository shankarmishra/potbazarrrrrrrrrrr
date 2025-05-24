import Order from '../models/orderModels.js';
import mongoose from 'mongoose';
import asyncHandler from '../utils/asyncHandler.js';
import crypto from 'crypto';
import Transaction from '../models/transactionModels.js';
import Razorpay from 'razorpay';
import Product from '../models/productModels.js';

// Create Razorpay Transaction (Order)
const createTransaction = asyncHandler(async (req, res) => {
    const { amount, userId } = req.body;

    if (!amount || !userId) {
        return res.status(400).json({ success: false, message: "Amount and User ID are required" });
    }

    const razorpay = new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID || '',
        key_secret: process.env.RAZORPAY_PAY_SECRET || '',
    });

    if (!razorpay.key_id || !razorpay.key_secret) {
        return res.status(500).json({ success: false, message: "Razorpay API credentials are missing" });
    }

    const options = {
        amount: amount * 100, // Convert to paise
        currency: "INR",
        receipt: `receipt#${Date.now()}`,
    };

    try {
        const razorpayOrder = await razorpay.orders.create(options);
        res.status(200).json({
            success: true,
            message: "Order created successfully",
            key: process.env.RAZORPAY_KEY_ID || '',
            amount: razorpayOrder.amount,
            currency: razorpayOrder.currency,
            orderId: razorpayOrder.id,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed to create order",
            error: error.message,
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
        address,
    } = req.body;

    if (!razorpayOrderId || !razorpayPaymentId || !razorpaySignature || !userId || !cartItems || !cartItems.length || !address) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    const generatedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_PAY_SECRET || '')
        .update(`${razorpayOrderId}|${razorpayPaymentId}`)
        .digest('hex');

    if (generatedSignature !== razorpaySignature) {
        return res.status(400).json({ success: false, message: "Invalid payment signature" });
    }

    const totalAmount = cartItems.reduce((total, item) => total + item.quantity * item.price, 0);

    try {
        const finalDeliveryDate = deliveryDate || new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);

        // Validate all product IDs in cartItems
        for (const item of cartItems) {
            if (!item.product || !mongoose.Types.ObjectId.isValid(item.product)) {
                return res.status(400).json({ success: false, message: "Invalid product in cart" });
            }
        }

        const newOrder = await Order.create({
            user: userId,
            address,
            deliveryDate: finalDeliveryDate,
            items: cartItems.map(item => ({
                product: new mongoose.Types.ObjectId(item.product),
                quantity: item.quantity,
            })),
            status: "Order Placed",
        });

        await Transaction.create({
            userId: userId,
            order: newOrder._id,
            orderId: razorpayOrderId,
            paymentId: razorpayPaymentId,
            status: "completed",
            totalAmount: totalAmount,
            address: address,
        });

        // Update product stock
        for (const item of cartItems) {
            const product = await Product.findById(item.product);
            if (product) {
                if (product.quantity >= item.quantity) {
                    product.quantity -= item.quantity;
                    await product.save();
                } else {
                    return res.status(400).json({
                        success: false,
                        message: `Insufficient stock for product: ${product.name}`,
                    });
                }
            } else {
                return res.status(400).json({
                    success: false,
                    message: "One or more products in the cart are not found",
                });
            }
        }

        res.json({
            success: true,
            message: "Payment verified and order created successfully",
            order: newOrder,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed to create transaction or order",
            error: error.message,
        });
    }
});

// Get Orders by User ID
const getOrderbyUserId = asyncHandler(async (req, res) => {
    const { userId } = req.params;

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ success: false, message: "Valid User ID is required" });
    }

    try {
        const orders = await Order.find({ user: userId })
            .populate({
                path: "user",
                select: "name email",
                model: "User"
            })
            .populate({
                path: "items.product",
                select: "name price image_uri",
                model: "Product"
            })
            .sort({ createdAt: -1 });

        res.status(200).json({ 
            success: true, 
            orders: orders || [] 
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Failed to get orders",
            error: error.message,
        });
    }
});

export { createTransaction, createOrder, getOrderbyUserId };
