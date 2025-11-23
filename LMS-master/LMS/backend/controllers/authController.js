import validator from "validator";
import bcrypt from "bcryptjs";
import User from "../models/userModel.js";
import { genToken } from "../configs/token.js";
import sendMail from "../configs/Mail.js";

// ========================= SIGNUP ==============================
export const signUp = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check existing email
    const existUser = await User.findOne({ email });
    if (existUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Validate email
    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Please enter a valid Email" });
    }

    // Validate password strength
    if (!password || password.length < 8) {
      return res.status(400).json({ message: "Please enter a strong password" });
    }

    // Hash password
    const hashPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashPassword,
      role,
    });

    // Generate token
    const token = genToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json(user);
  } catch (error) {
    console.error("Signup Error:", error);
    return res.status(500).json({ message: `Signup error: ${error}` });
  }
};

// ========================= LOGIN ==============================
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check existing user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }

    // Validate password match
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    // Generate token
    const token = genToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json(user);
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: `Login error: ${error}` });
  }
};

// ========================= LOGOUT ==============================
export const logOut = async (req, res) => {
  try {
    res.clearCookie("token");
    return res.status(200).json({ message: "Logout successfully" });
  } catch (error) {
    return res.status(500).json({ message: `Logout error: ${error}` });
  }
};

// ========================= GOOGLE SIGNUP =======================
export const googleSignup = async (req, res) => {
  try {
    const { name, email, role } = req.body;

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        name,
        email,
        role,
      });
    }

    const token = genToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json(user);
  } catch (error) {
    console.error("Google Signup Error:", error);
    return res.status(500).json({ message: `Google Signup error: ${error}` });
  }
};

// ========================= SEND OTP ============================
export const sendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();

    user.resetOtp = otp;
    user.otpExpires = Date.now() + 5 * 60 * 1000;
    user.isOtpVerified = false;

    await user.save();
    await sendMail(email, otp);

    return res.status(200).json({ message: "Email sent successfully" });
  } catch (error) {
    console.error("Send OTP Error:", error);
    return res.status(500).json({ message: `Send OTP error: ${error}` });
  }
};

// ========================= VERIFY OTP ==========================
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });

    if (!user || user.resetOtp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    user.isOtpVerified = true;
    user.resetOtp = undefined;
    user.otpExpires = undefined;

    await user.save();

    return res.status(200).json({ message: "OTP verified" });
  } catch (error) {
    console.error("Verify OTP Error:", error);
    return res.status(500).json({ message: `Verify OTP error: ${error}` });
  }
};

// ========================= RESET PASSWORD ======================
export const resetPassword = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user || !user.isOtpVerified) {
      return res.status(400).json({ message: "OTP verification required" });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    user.password = hashPassword;
    user.isOtpVerified = false;

    await user.save();

    return res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res.status(500).json({ message: `Reset password error: ${error}` });
  }
};
