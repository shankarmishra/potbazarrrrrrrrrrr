import mongoose, { Schema } from 'mongoose';

// Address sub-schema (same as in orderModels.js)
const AddressSchema = new Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true },
    street: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: String, required: true },
    country: { type: String, default: "India", required: true }
}, { _id: false });

const TransactionSchema = new Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    items: [
        {
            product: { 
                type: mongoose.Schema.Types.ObjectId, 
                ref: 'Product', 
                required: true 
            },
            quantity: { 
                type: Number, 
                required: true 
            },
            price: { 
                type: Number, 
                required: true 
            }
        }
    ],
    totalAmount: { 
        type: Number, 
        required: true 
    },
    address: { 
        type: AddressSchema, // <-- FIXED: now an object, not string
        required: true 
    },
    paymentStatus: { 
        type: String, 
        enum: ['pending', 'completed', 'failed'], 
        default: 'pending' 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
});

// Create index for faster queries
TransactionSchema.index({ userId: 1, createdAt: -1 });

const Transaction = mongoose.model('Transaction', TransactionSchema);
export default Transaction;
