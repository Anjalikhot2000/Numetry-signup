require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const multer = require("multer");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cloudinary = require("./cloudinaryconfig");

const app = express();
const port = process.env.PORT || 5000;

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1); // Exit if the database connection fails
  });

// Define User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  photoUrl: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Middleware
app.use(
  cors({
    origin: ["http://localhost:5173", "https://numetry-proj.vercel.app"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Multer Setup for File Uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Auth Routes
// Signup Route
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password, photo } = req.body;

    if (!name || !email || !password || !photo) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      photoUrl: photo,
    });

    const savedUser = await newUser.save();

    res.status(201).json({ message: "User signed up successfully!" });
  } catch (error) {
    console.error("Error in signup route:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Signup Route with File Upload (if needed)
app.post("/api/signup", upload.single("photo"), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const photo = req.file;

    // Validate Inputs
    if (!name || !email || !password || !photo) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    // Check if User Already Exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email is already registered" });
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Convert File to Base64
    const photoBase64 = `data:${photo.mimetype};base64,${photo.buffer.toString("base64")}`;

    // Upload Photo to Cloudinary
    const cloudinaryResponse = await cloudinary.uploader.upload(photoBase64, {
      folder: "user_photos", // Optional folder in Cloudinary
    });

    // Create New User
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      photoUrl: cloudinaryResponse.secure_url, // Save Cloudinary URL
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({
      message: "Internal server error",
      error: error.message, // Include error details for debugging
    });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
