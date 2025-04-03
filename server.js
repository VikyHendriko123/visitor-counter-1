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
const port = process.env.EXPRESS_PORT;

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
app.use(cors({ origin: "*", credentials: true }));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//API Endpoints
app.use('/api/auth',  authRateLimiter, authRouter);
app.use('/api/user', userRouter);
app.use('/api/visitor', visitorRouter);

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
