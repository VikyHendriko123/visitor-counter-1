import mongoose from "mongoose";

const verifiedDeviceSchema = new mongoose.Schema({
    device: { type: String, required: true },
    isVerified: { type: Boolean, default: false }, 
    createdAt: { type: Date, default: Date.now } 
}, { _id: false });

const userSchema = new mongoose.Schema({
    username: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    location: {type: String, required: true},
    password: {type: String, required: true},
    verifyOtp: {type: String, default: ''},
    verifyOtpExpiredAt: {type: Number, default: 0},
    isVerified: {type: Boolean, default: false},
    resetOtp: {type: String, default: ''},
    resetOtpExpiredAt: {type: Number, default: 0},
    verifiedDevices: {
        type: Map,
        of: verifiedDeviceSchema, 
        default: {}
    }
})

const userModel = mongoose.models.users || mongoose.model('User', userSchema);

export default userModel