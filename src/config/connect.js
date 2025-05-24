import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config(); // Load environment variables from .env

const connect = async (url = process.env.MONGO_URI) => {
    console.log("MONGO_URI:","mongodb+srv://hunter:Mr4mAoBBuGbUO02h@cluster0.46abq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0");

    try {
        await mongoose.connect(url, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("✅ Database connected successfully");
    } catch (error) {
        console.error("❌ Error connecting to database:", error);
        process.exit(1); // Exit process on failure
    }

    // Graceful shutdown handling
    process.on("SIGINT", async () => {
        await mongoose.connection.close();
        console.log("🔌 MongoDB connection closed.");
        process.exit(0);
    });
};

export default connect;
