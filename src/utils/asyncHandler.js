// src/utils/asyncHandler.js

const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next); // catch errors and pass them to the next middleware
};

export default asyncHandler;  // Ensure this export is present
