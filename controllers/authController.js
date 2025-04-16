import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";
import crypto from "crypto";
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from "../config/emailTemplate.js";

const generateHMAC = (userAgent, userId) => {
    const secretKey = process.env.DEVICE_SECRET;
    const rawString = `${userId}-${userAgent}`;
    return crypto.createHmac('sha256', secretKey).update(rawString).digest('hex');
};

export const login = async (req, res) => {
    const {email, password} = req.body;

    if(!email || !password) {
        return res.status(400).json({success: false, message: 'Email and password are required'});
    }

    try {
        const user = await userModel.findOne({email});
        if (!user) {
            return res.status(404).json({success: false, message: 'User not found'});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch){
            return res.status(401).json({success: false, message: 'Incorrect password'});
        }

        const token = jwt.sign({id: user._id, email: user.email, username: user.username, location: user.location}, process.env.JWT_SECRET, {expiresIn: '1d'});
        const refreshToken = jwt.sign({id: user._id}, process.env.REFRESH_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'lax',
            maxAge: 1 * 24 * 60 * 60 * 1000
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({success: true, message: 'User logged in successfully'});
    } catch (error) {
        return res.status(500).json({success: false, message: error.message});
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'lax'
        });
        
        res.clearCookie('refreshToken', {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production', 
            sameSite: 'lax'
        });

        return res.json({success: true, message: 'User logged out successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const refreshAccessToken = async (req, res) => {
    const refreshToken = req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.split(' ')[1]
        : req.cookies?.refreshToken;

    if (!refreshToken) {
        return res.status(400).json({ success: false, message: 'Not Authorized. Login Again' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

        const userId = decoded.id;
        const user = await userModel.findById(userId);

        const newAccessToken = jwt.sign({id: user._id, email: user.email, username: user.username, location: user.location}, JWT_SECRET, {expiresIn: '1d'});
        const newRefreshToken = jwt.sign({id: decoded.id}, process.env.REFRESH_SECRET, {expiresIn: '7d'});

        res.cookie('token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV  === 'production',
            sameSite: 'lax',
            maxAge: 1 * 24 * 60 * 60 * 1000
        });

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ success: true, message: "Token refreshed successfully" });
    } catch (error) {
        return res.status(401).json({ success: false, message: "Invalid or expired token. Login again." });
    }
}

export const sendVerifyOtp = async (req, res) => {
    try {
        const {userId, deviceFingerprint} = req.body;

        const user = await userModel.findById(userId);

        const userAgent = req.headers['user-agent'];
        const deviceHMAC = generateHMAC(userAgent, user._id);
        const deviceData = user.verifiedDevices.get(deviceHMAC);

        if (!deviceData) {
            if (user.verifyOtp && user.verifyOtpExpiredAt > Date.now()) {
                return res.json({ success: true, isVerified: false, message: 'OTP is still valid. Please check your email' });
            }

            const otp = Math.floor(100000 + Math.random() * 900000);
            user.verifyOtp = otp;
            user.verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000;
    
            await user.save();
    
            const mailOptions = {
                from: process.env.SENDER_EMAIL,
                to: user.email,
                subject: 'Verify your account',
                html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
            }
    
            await transporter.sendMail(mailOptions);
    
            return res.json({success: true, isVerified: false, message: 'Verification code sent to your email'});
        } else if (deviceData && deviceData.isVerified) {
            return res.json({success: true, isVerified: true, message: 'Login Successful'});
        } else {
            if (user.verifyOtp && user.verifyOtpExpiredAt > Date.now()) {
                return res.json({ success: true, isVerified: false, message: 'OTP is still valid. Please check your email' });
            }
        
            const otp = Math.floor(100000 + Math.random() * 900000);
            user.verifyOtp = otp;
            user.verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000;
        
            await user.save();
        
            const mailOptions = {
                from: process.env.SENDER_EMAIL,
                to: user.email,
                subject: 'Verify your account',
                html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
            }
        
            await transporter.sendMail(mailOptions);
        
            return res.json({ success: true, isVerified: false, message: 'Verification code sent to your email' });
        }
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const verifyEmail = async (req, res) => {
    const {userId, otp, deviceFingerprint} = req.body;
        
    if(!userId || !otp || !deviceFingerprint) {
        return res.status(400).json({success: false, message: 'Missing required fields'});
    }

    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({success: false, message: 'User not found'});
        }

        if (user.verifyOtp !== otp) {
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if (user.verifyOtpExpiredAt < Date.now()) {
            return res.json({success: false, message: 'OTP expired'});
        }

        const userAgent = req.headers['user-agent'];
        const deviceHMAC = generateHMAC(userAgent, user._id);

        user.isVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpiredAt = 0;
        user.verifiedDevices.set(deviceHMAC, { device: deviceFingerprint, isVerified: true });
        await user.save();

        return res.json({success: true, message: 'User verified successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const isAuthenticated = async (req, res) => {
    try {
        const { userId } = req.body;
        if(!userId) {
            res.status(400).json({success: false, message: "Token is invalid"});
        }

        const user = await userModel.findById(userId);

        const userAgent = req.headers["user-agent"];
        const deviceHMAC = generateHMAC(userAgent, userId);

        if (user && user.verifiedDevices.get(deviceHMAC) && user.verifiedDevices.get(deviceHMAC).isVerified) {
            return res.status(200).json({success: true, message: 'User already authenticated'});
        } else {
            res.clearCookie('token', {
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production', 
                sameSite: 'lax'
            });
    
            res.clearCookie('refreshToken', {
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production', 
                sameSite: 'lax'
            });

            return res.status(401).json({success: false, message: 'Email has been changed. Please log in again.'});
        }
    } catch (error) {
        return res.status(401).json({success: false, message: error.message});
    }
}

export const sendResetOtp = async (req, res) => {
    const {email} = req.body;

    if(!email){
        return res.status(400).json({success: false, message: 'Email is required'});
    }

    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: 'User not found'});
        }

        const otp = Math.floor(100000 + Math.random() * 900000);

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true, message: 'OTP sent to your email'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const verifyResetOtp = async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP Expired' });
        }

        return res.json({ success: true, message: 'OTP verified successfully' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

export const resetPassword = async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email and new password are required' });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (!user.resetOtp || user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP has expired' });
        }

        const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long, contain at least one uppercase letter and one number.'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = ''; 
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({ success: true, message: 'Password has been reset successfully' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};