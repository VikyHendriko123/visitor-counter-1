import userModel from "../models/userModel.js";

export const getUserData = async (req, res) => {
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({success: false, message: 'User not found'});
        }
        res.json({
            success: true,
            userData: {
                userId: userId,
                username: user.username,
                isVerified: user.isVerified,
                location: user.location,
                email: user.email
            }
        })
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}