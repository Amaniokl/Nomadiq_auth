import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { User } from '../models/userSchema.js';
import { verifyOTP, sendOTP } from '../services/otpService.js';
import { sendEmail } from '../services/emailService.js';
import { ApiError } from '../utils/apiError.js';
import { ApiResponse } from '../utils/apiResponse.js';
import { Redis } from "ioredis"
import { generateOtp } from '../utils/generateOtp.js'
// index.js or app.js
import { isValidEmail, isValidPassword, isValidPhone } from '../services/validator.js';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();
const redis = new Redis();

export const sendOtpToUserByPhone = async (req, res) => {

  try {
    const { phone } = req.body;
    const user = await User.findOne({ phone });
    // console.log(user);
    // phone = phone?.trim();

    if (!(phone)) {
      return res.status(400).json({ error: "Require phone number" });
    }

   

    if (user) {
      throw new Error("User already exists in the database");
    }

    await sendOTP(phone);
    res.status(201).json({ message: "OTP sent for verification." });
  } catch (error) {
    console.log(error);
    
    res.status(500).json({ error: "Error registering user" });
  }
};

export const verifyOtpNumberRegister = async (req, res) => {
  const { phone, otp, password } = req.body;
  try {
    // email = email?.trim().toLowerCase();
    // phone = phone?.trim();

    if (!(phone)) {
      return res.status(400).json({ error: "Require phone number" });
    }

    // if (phone && !isValidPhone(phone)) {
    //   return res.status(400).json({ error: "Invalid phone number" });
    // }

    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long, should contain one uppercase and lowercase letters" });
    }


    const response = await verifyOTP(phone, otp);
    if (!response) {
      return res.status(400).json(new ApiResponse(400, null, "Invalid OTP"));
    }

    const user = await User.findOne({ phone });
    if (user) {
      throw new ApiError(400, "User is already registered");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const savedUserInDb = new User({ phone, password: hashedPassword });
    console.log(savedUserInDb);

    await savedUserInDb.save();

    res.status(200).json(new ApiResponse(200, null, "Phone verified successfully and user is registered"));
  } catch (error) {
    console.error(error); // Log the error for debugging
    if (error instanceof ApiError) {
      return res.status(error.statusCode).json(new ApiResponse(error.statusCode, null, error.message));
    }
    res.status(500).json(new ApiResponse(500, null, "Error verifying OTP"));
  }
}; // Connect to your Redis instance

export const sendOtpToUserByEmail = async (req, res) => {

  try {
    const { email } = req.body;
    const Email = email?.trim().toLowerCase();
    if (!Email) {
      throw new ApiError(400, null, "Email is required");
    }
    if (Email && !isValidEmail(Email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const user = await User.findOne({ Email });
    if (user) {
      throw new Error("User already exists in the database");
    }

    const otp = generateOtp();
    // console.log(otp);

    await redis.setex(`otp:${Email}`, 300, otp); // Store OTP with a 5-minute expiration
    // console.log("909090");
    const storedOtp = await redis.get(`otp:${Email}`);
    console.log(storedOtp);

    await sendEmail(Email, "Otp for verification of NOMADIQ", otp);
    console.log("sdfsd");

    res.status(201).json({ message: "OTP sent for verification." });
  } catch (error) {
    console.log(error);
    
    res.status(500).json({ error: "Error registering user" });
  }
};

export const verifyOtpEmailRegister = async (req, res) => {
  const { email, otp, password } = req.body;
  try {
    const Email = email?.trim().toLowerCase();
    console.log(Email);
    
    if (!(Email)) {
      return res.status(400).json({ error: "Require email " });
    }

    if (Email && !isValidEmail(Email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long, should contain one uppercase and lowercase letters" });
    }

    const storedOtp = await redis.get(`otp:${Email}`);

    if (!storedOtp || storedOtp !== otp) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // OTP is valid, proceed to register the user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email: Email, password: hashedPassword });
    await newUser.save();

    // Clear OTP after successful verification
    await redis.del(`otp:${Email}`);

    res.status(200).json({ message: "Email verified successfully and user is registered" });
  } catch (error) {
    res.status(500).json({ error: "Error verifying OTP" });
  }
};

export const loginPhone = async (req, res) => {
  // console.log("sdfsd");
  try {
    let { phone, password } = req.body;
    // console.log(email);

    // const Email = email?.trim().toLowerCase();
    // phone = phone?.trim();

    if (!( phone)) {
      return res.status(400).json({ error: "Require phone number" });
    }

    // if (Email && !isValidEmail(Email)) {
    //   return res.status(400).json({ error: "Invalid email format" });
    // }


    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long, should contain one uppercase and lowercase letters" });
    }

    const user = await User.findOne({phone});


    if (!user) {
      return res.status(400).json({ error: "User not found in database" })
    }
    console.log(user);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    // console.log(user);

   
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY || "15m" } // shorter expiry for access token
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );
    // console.log();

    // Save refresh token to DB
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ message: "Login successful" });
  } catch (error) {
    console.error("❌ Login error:", error.message);
    res.status(500).json({ error: "Error logging in" });
  }
};

export const loginEmail=async(req, res)=>{
  // console.log("sdfsd");
  try {
    let { email,  password } = req.body;
    // console.log(email);

    const Email = email?.trim().toLowerCase();
    // phone = phone?.trim();

    if (!(Email )) {
      return res.status(400).json({ error: "Require email " });
    }

    if (Email && !isValidEmail(Email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }


    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long, should contain one uppercase and lowercase letters" });
    }

    const user = await User.findOne({
      email: Email
    });


    if (!user) {
      return res.status(400).json({ error: "User not found in database" })
    }
    console.log(user);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    // console.log(user);

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY || "15m" } // shorter expiry for access token
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );
    // console.log();

    // Save refresh token to DB
    user.refreshToken = refreshToken;
    await user.save();

    // Set cookies
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ message: "Login successful" });
  } catch (error) {
    console.error("❌ Login error:", error.message);
    res.status(500).json({ error: "Error logging in" });
  }
}

export const refreshAccessToken = async (req, res) => {
  try {
    const oldRefreshToken = req.cookies?.refreshToken;

    if (!oldRefreshToken) {
      return res.status(401).json({ error: "Refresh token missing" });
    }

    // Verify old refresh token
    const decoded = jwt.verify(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.refreshToken !== oldRefreshToken) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    // ✅ Generate new access token
    const newAccessToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY || "15m" }
    );

    // 🔁 Optional: Rotate refresh token
    const newRefreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    // Save new refresh token in DB
    user.refreshToken = newRefreshToken;
    await user.save();

    // Set new tokens as cookies
    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // ✅ Return token for dev/debugging (optional)
    res.json({ message: "Access token refreshed", accessToken: newAccessToken });

  } catch (err) {
    console.error("❌ Refresh token error:", err.message);
    res.status(403).json({ error: "Token expired or invalid" });
  }
};

export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      const user = await User.findOne({ refreshToken });

      if (user) {
        user.refreshToken = null;
        await user.save();
      }
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("❌ Logout error:", error.message);
    res.status(500).json({ error: "Logout failed" });
  }
};

export const verifyToken = (req, res) => {
  res.status(200).json({ user: req.user });
};

export const forgotPasswordByEmailSendOtp = async (req, res) => {
  const { email } = req.body;
  try {
    const Email = email?.trim().toLowerCase();
    if (!Email) {
      return res.status(400).json({ error: "Require email " });
    }

    if (Email && !isValidEmail(Email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const user = await User.findOne({ Email });

    if (!user) {
      return res.status(400).json({ error: "User not found in database" })
    }

    const otp = generateOtp();
    await redis.setex(`otp:${Email}`, 300, otp);

    await sendEmail(Email, "Password Reset OTP", `Your OTP is ${otp}`);

    res.status(200).json({ message: "OTP sent for password reset." });
  } catch (error) {
    console.error("❌ Forgot password error:", error.message);
    res.status(500).json({ error: "Error sending OTP" });
  }
}

export const forgotPasswordByEmailVerifyOtp = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const Email = email?.trim().toLowerCase();
    if (!Email) {
      return res.status(400).json({ error: "Require email " });
    }

    if (Email && !isValidEmail(Email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const storedOtp = await redis.get(`otp:${Email}`);

    if (!storedOtp || storedOtp !== otp) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    if (!isValidPassword(newPassword)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long, should contain one uppercase and lowercase letters" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ email: Email }, { password: hashedPassword });

    // Clear OTP after successful verification
    await redis.del(`otp:${Email}`);

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("❌ Forgot password verification error:", error.message);
    res.status(500).json({ error: "Error verifying OTP" });
  }
}

export const forgotPasswordByPhoneSendOtp = async (req, res) => {
  const { phone } = req.body;
  try {

    if (!(phone)) {
      return res.status(400).json({ error: "Require phone number" });
    }

    if (phone && !isValidPhone(phone)) {
      return res.status(400).json({ error: "Invalid phone number" });
    }

    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(400).json({ error: "User not found in database" })
    }

    await sendOTP(phone);

    res.status(200).json({ message: "OTP sent for password reset." });
  } catch (error) {
    console.error("❌ Forgot password error:", error.message);
    res.status(500).json({ error: "Error sending OTP" });
  }
}

export const forgotPasswordByPhoneVerifyOtp = async (req, res) => {
  const { phone, otp, newPassword } = req.body;
  try {
    if (!(phone)) {
      return res.status(400).json({ error: "Require phone number" });
    }

    if (phone && !isValidPhone(phone)) {
      return res.status(400).json({ error: "Invalid phone number" });
    }

    if (!isValidPassword(newPassword)) {
      return res.status(400).json({ error: "Password must be at least 8 characters long, should contain one uppercase and lowercase letters" });
    }

    const response = await verifyOTP(phone, otp);
    if (!response) {
      return res.status(400).json(new ApiResponse(400, null, "Invalid OTP"));
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updateOne({ phone }, { password: hashedPassword });

    res.status(200).json(new ApiResponse(200, null, "Password reset successfully"));
  } catch (error) {
    console.error("❌ Forgot password verification error:", error.message);
    res.status(500).json({ error: "Error verifying OTP" });
  }
}
