import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if(!token){
        return res.status(400).json({success: false, message: 'Not Authorized. Login Again'});
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        req.body.userId = tokenDecode.id;
        next();
    } catch (error) {
        return res.status(400).json({ success: false, message: "Invalid or Expired Token. Login Again" });
    }    
}

export default userAuth