import getVisitorModel from "../models/visitorModel.js";

export const getVisitorByDaily = async (req, res) => {
    const { date } = req.params;
    const { userId } = req.body || req.body.userId;

    if (!date) {
        return res.status(400).json({ success: false, message: 'Missing required fields' })
    }

    if (!userId) {
        return res.status(400).json({ success: false, message: "Not Authorized. Login Again" })
    }

    try {
        const visitorModel = getVisitorModel(userId);
        const visitor = await visitorModel.findOne({ date });

        if (!visitor) {
            return res.status(404).json({ success: false, message: "No data found in the given date" });
        }

        res.json({ success: true, message: "Data successfully fetched", visitor });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
}

export const getVisitorByWeek = async (req, res) => {
    const { startDate, endDate } = req.params;
    const { userId } = req.body || req.body.userId;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: "Missing required fields" })
    }

    if (!userId) {
        return res.status(400).json({ success: false, message: "Not Authorized. Login Again" });
    }

    try {
        const visitorModel = getVisitorModel(userId);
        const visitors = await visitorModel.find({
            date: { $gte: startDate, $lte: endDate }
        }).sort({ date: 1 });

        if (!visitors.length) {
            return res.status(404).json({ success: false, message: "No data found in the given range" });
        }

        res.json({ success: true, message: "Data successfully fetched", visitors });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error fetching weekly data", error });
    }
}

export const getVisitorByMonth = async (req, res) => {
    const { year, month } = req.params;
    const { userId } = req.body || req.body.userId;

    if (!year || !month) {
        return res.status(400).json({ success: false, message: "Missing required fields" })
    }

    if (!userId) {
        return res.status(400).json({ success: false, message: "Not Authorized. Login Again" })
    }

    try {
        const visitorModel = getVisitorModel(userId);
        const regexPattern = new RegExp(`^${year}-${month.padStart(2, '0')}-\\d{2}$`);

        const visitors = await visitorModel.find({
            date: { $regex: regexPattern }
        }).sort({ date: 1 });

        if (!visitors.length) {
            return res.status(404).json({ success: false, message: "No data found for the given month" })
        }

        res.json({ success: true, message: "Data successfully fetched", visitors });
    } catch (error) {
        res.status(500).json({ success: false, message: "Error fetching monthly data", error });
    }
}


