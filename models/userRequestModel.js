const mongoose = require('mongoose')

const userRequestSchema = mongoose.Schema({
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    },
    recipientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    },
    status: {
        type: String,
        enum: ["Accepted", "Rejected", "Pending"],
        default: "Pending"
    },
})

const UserRequest = mongoose.model('UserRequest', userRequestSchema);
module.exports = UserRequest;