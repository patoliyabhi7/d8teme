const mongoose = require('mongoose')

const userRequestSchema = mongoose.Schema({
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "UserProfile",
    },
    recipientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "UserProfile",
    },
    status: {
        type: String,
        enum: ["Accept", "Reject", "Pending"],
        default: "Pending"
    },
})

const UserRequest = mongoose.model('UserRequest', userRequestSchema);
module.exports = UserRequest;