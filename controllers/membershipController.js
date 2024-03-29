const AppError = require('./../utils/appError');
const catchAsync = require('./../utils/catchAsync');
const User = require('./../models/userModel');
const Membership = require('./../models/membershipModel');
const sendEmail = require('./../utils/email');

exports.purchasePremium = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id)
    if (!user) {
        return next(new AppError("User not found or not logged in"))
    }
    const findActiveMembership = await Membership.find({ userId: user.id, endDate: { $gt: Date.now() } });
    if (findActiveMembership && findActiveMembership.length > 0) {
        res.status(400).json({
            message: `Their is currently active membership!`
        })
        return next();
    }
    const { planType, planCategory } = req.body;
    if (!planType || !planCategory) {
        res.status(400).json({
            message: `Please enter all the required fields!`
        })
        return next(new AppError("Please enter all the required fields!", 400));
    }
    const currentDate = new Date();
    if (planCategory === 'Basic') {
        if (planType === 'Monthly') {
            endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, currentDate.getDate());
            amount = 100;
        } else if (planType === 'Yearly') {
            endDate = new Date(currentDate.getFullYear() + 1, currentDate.getMonth(), currentDate.getDate());
            amount = 1000;
        }
    } else if (planCategory === 'Exclusive') {
        if (planType === 'Monthly') {
            endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, currentDate.getDate());
            amount = 200;
        } else if (planType === 'Yearly') {
            endDate = new Date(currentDate.getFullYear() + 1, currentDate.getMonth(), currentDate.getDate());
            amount = 2000;
        }
    }

    const membership = await Membership.create({
        userId: user.id,
        endDate,
        amount,
        planType,
        planCategory
    })
    if (!membership) {
        res.status(400).json({
            message: `Something went wrong while purchasing membership!`
        })
        return next(new AppError("Something went wrong while purchasing membership!", 400));
    }
    res.status(201).json({
        status: 'success',
        message: `Membership purchased successfully!`
    })
})