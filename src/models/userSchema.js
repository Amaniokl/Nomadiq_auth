// Importing Mongoose using ES6 import syntax
import mongoose from "mongoose";

// Defining the User Schema
const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, lowercase: true, sparse: true },
    phone: { type: String, unique: true, sparse: true },
    password: { type: String },
    refreshToken: { type: String },
  },
  { timestamps: true }
);

// Exporting the User model using a named export
export const User = mongoose.model("User", UserSchema);