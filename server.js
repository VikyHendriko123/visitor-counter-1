import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import 'dotenv/config';
import bodyParser from "body-parser";
import dotenv from "dotenv";
import rateLimit from 'express-rate-limit';

import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";
import visitorRouter from "./routes/visitorRoutes.js";

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

app.set('trust proxy', 1);
connectDB();

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 50,
  message: { success: false, message: 'Too many requests, please try again later' },
  standardHeaders: true, 
  legacyHeaders: false
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({ 
  origin: ["http://localhost:5000", "http://10.0.2.2:5000", "visitor-counter-production.up.railway.app"], 
  credentials: true,  
  allowedHeaders: ['Content-Type', 'Authorization'] 
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//API Endpoints
app.get("/", (req, res) => {
  res.send("Server is running!");
});

app.use('/api/auth', authRateLimiter, authRouter);
app.use('/api/user', userRouter);
app.use('/api/visitor', visitorRouter);

app.listen(port, "0.0.0.0", () => {
    console.log(`Server started on port ${port}`);
});
