import express from "express";
import userAuth from "../middleware/userAuth.js";
import { getVisitorByDaily, getVisitorByMonth, getVisitorByWeek } from "../controllers/visitorController.js";

const visitorRouter = express.Router();

visitorRouter.get('/daily/:date', userAuth, getVisitorByDaily);
visitorRouter.get('/weekly/:startDate/:endDate', userAuth, getVisitorByWeek);
visitorRouter.get('/monthly/:year/:month', userAuth, getVisitorByMonth);

export default visitorRouter