import mongoose from 'mongoose';
import validator from 'validator';

// Address Subschema
const addressSchema = new mongoose.Schema({
  street: {
    type: String,
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 100,
  },
  city: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50,
  },
  state: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50,
  },
  pinCode: {
    type: String,
    required: true,
    trim: true,
    validate: {
      validator: (value) => /^\d{6}$/.test(value),
      message: 'Pin code must be a 6-digit number',
    },
  },
  country: {
    type: String,
    required: true,
    trim: true,
    default: 'India',
  },
  isDefault: {
    type: Boolean,
    default: false,
  },
});

// User Schema
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    phone: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      validate: {
        validator: (value) => validator.isMobilePhone(value, 'any'),
        message: 'Invalid phone number',
      },
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
      validate: {
        validator: validator.isEmail,
        message: 'Invalid email address',
      },
    },
    password: {
      type: String,
      required: true,
      minlength: 8,
      select: false,
    },
    addresses: [addressSchema],
    resetToken: {
      type: String,
      select: false,
    },
    resetTokenExpires: {
      type: Date,
      select: false,
    },
  },
  {
    timestamps: true,
  }
);

// Ensure only one default address
userSchema.pre('save', function (next) {
  if (this.isModified('addresses')) {
    const defaultAddresses = this.addresses.filter((addr) => addr.isDefault);
    if (defaultAddresses.length > 1) {
      const keepId = defaultAddresses[0]._id?.toString();
      this.addresses = this.addresses.map((addr) => ({
        ...addr.toObject(),
        isDefault: addr._id?.toString() === keepId,
      }));
    } else if (defaultAddresses.length === 0 && this.addresses.length > 0) {
      this.addresses[0].isDefault = true;
    }
  }
  next();
});

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });

const User = mongoose.model('User', userSchema);
export default User;
