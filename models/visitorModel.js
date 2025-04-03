import mongoose from "mongoose";

const visitorSchema = new mongoose.Schema({
    date: { type: String, required: true },
    visitorToday: { type: Number, default: 0 }, 
    cctvData: {
        type: Map,
        of: new mongoose.Schema({
            visitorTotal: { type: Number, default: 0 },
            visitorIn: { type: [Number], default: Array(24).fill(0) },
            visitorOut: { type: [Number], default: Array(24).fill(0) }
        }, { _id: false }),
        default: {}
    }
});


const getVisitorModel = (userId) => {
    const modelName = `Visitor_${userId}`;
    return mongoose.models[modelName] || mongoose.model(modelName, visitorSchema);
};

export default getVisitorModel;
