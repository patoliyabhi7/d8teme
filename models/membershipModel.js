const mongoose = require('mongoose')

const membershipSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    },
    startDate: {
        type: Date,
        default: Date.now(),
        required: [true, 'Start Date is required'],
    },
    endDate: {
        type: Date,
        required: [true, 'End Date is required'],
    },
    amount: {
        type: Number,
        required: [true, 'Amount is required'],
    },
    paidOn: {
        type: Date,
        default: Date.now(),
    },
    planType: {
        type: String,
        enum: ['Monthly', 'Yearly'],
        required: [true, 'Plan Type is required'],
    },
    planCategory: {
        type: String,
        enum: ['Free', 'Basic', 'Exclusive'],
        required: [true, 'Plan Category is required'],
    }
})

// For razorpay - payment_id, signature, order_id

const Membership = mongoose.model('Membership', membershipSchema);
module.exports = Membership;