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
    price: {
        type: Number,
        required: true,
    }
}, { _id: false });

// Address schema for full details
const AddressSchema = new Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true },
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: String, required: true },
    country: { type: String, default: "India", required: true }
}, { _id: false });

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
        type: AddressSchema,
        required: true,
    },
    items: [ItemSchema], // <-- YAHAN SIRF ItemSchema ka array likho
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
    totalAmount: {
        type: Number,
        required: false
    }
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);
export default Order;
