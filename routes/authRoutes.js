import express from "express";
import { isAuthenticated, login, logout, refreshAccessToken, resetPassword, sendResetOtp, sendVerifyOtp, verifyEmail, verifyResetOtp } from "../controllers/authController.js";
import userAuth from "../middleware/userAuth.js";

const authRouter = express.Router();

authRouter.post('/login', login);
authRouter.post('/logout', userAuth, logout);
authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp);
authRouter.post('/verify-account', userAuth, verifyEmail);
authRouter.get('/is-auth', userAuth, isAuthenticated);
authRouter.post('/refresh-token', refreshAccessToken);
authRouter.post('/send-reset-otp', sendResetOtp);
authRouter.post('/verify-reset-otp', verifyResetOtp);
authRouter.post('/reset-password', resetPassword);

export default authRouter