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
    const message = `Thank you for purchasing our ${planCategory} membership\n
                    Your purchase was successfull\n
                    Plan Category: ${planCategory}(${planType})\n
                    Amount: ${amount}\n
                    End Date: ${endDate}\n
                    Please contact us for any query\n`;
    try {
        await sendEmail({
            email: user.email,
            subject: 'Premium Membership Purchase',
            message
        })
        res.status(201).json({
            status: 'success',
            message: `Membership purchased successfully!`
        })
    } catch (error) {
        return next(new AppError("There was an error sending the mail. Try again later", 500))
    }
})

exports.getMembershipHistory = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id)
    if (!user) {
        return next(new AppError("User not found or not logged in"))
    }
    const memberships = await Membership.find({ userId: user.id })
    if (!memberships) {
        res.status(400).json({
            message: `No memberships found!`
        })
        return next(new AppError("No memberships found!", 400));
    }
    res.status(200).json({
        status: 'success',
        records: memberships.length,
        memberships
    })
})

exports.cancelMembership = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id)
    if (!user) {
        return next(new AppError("User not found or not logged in"))
    }
    const membership = await Membership.findOne({ userId: user.id, endDate: { $gt: Date.now() } });
    if (!membership) {
        res.status(400).json({
            message: `No active membership found!`
        })
        return next(new AppError("No active membership found!", 400));
    }
    const updatedMembership = await Membership.findByIdAndUpdate(membership.id, {
        endDate: Date.now()
    })
    if (!updatedMembership) {
        res.status(400).json({
            message: `Something went wrong while cancelling the membership!`
        })
        return next(new AppError("Something went wrong while cancelling the membership!", 400));
    }
    res.status(200).json({
        status: 'success',
        message: `Membership cancelled successfully!`
    })
})

