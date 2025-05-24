import mongoose from 'mongoose';

const { Schema } = mongoose;

const ItemSchema = new Schema({
    product: {
        type: Schema.Types.ObjectId,
        ref: 'Product',
        required: true,
    },
    quantity: {
        type: Number,
        required: true,
    },
});

const orderSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    deliveryDate: { 
        type: Date,
    },
    address: { 
        type: String,
        required: true,
    },
    items: {
        type: [ItemSchema],
        required: true,
    },
    status: { 
        type: String,
        enum: [
            "Order Placed",
            "Shipping",
            "Out for Delivery",
            "Delivered",
            "Cancelled",
        ],
        default: 'Order Placed',
        required: true,
    },
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);
export default Order;
