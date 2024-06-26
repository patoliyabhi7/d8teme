const AppError = require('./../utils/appError');
const catchAsync = require('./../utils/catchAsync');
const User = require('./../models/userModel');
const UserRequest = require('./../models/userRequestModel');
const sendEmail = require('./../utils/email');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const twilio = require('twilio');
const { promisify } = require('util');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;

const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        secure: true,
        httpOnly: true,
    };
    res.cookie('jwt', token, cookieOptions);

    user.password = undefined;
    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user,
        },
    });
};

const filterObj = (obj, ...allowedFields) => {
    const newObj = {};
    Object.keys(obj).forEach((el) => {
        if (allowedFields.includes(el)) newObj[el] = obj[el];
    });
    return newObj;
};

exports.protect = catchAsync(async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    if (!token) {
        return next(new AppError('You are not logged in! Please login to get access', 401));
    }
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
        return next(new AppError('The user belonging to this token does no longer exists'))
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(new AppError('User recently changed password! Please login again', 401))
    }

    req.user = currentUser;
    next();
})

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(
                new AppError(
                    'You do not have permission to perform this action',
                    403
                )
            );
        }

        next();
    };
};


exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        email: req.body.email,
        phone: req.body.phone,
        dob: req.body.dob,
        profileImage: req.body.profileImage,
        gender: req.body.gender,
        interest: req.body.interest,
        height: req.body.height,
        bodyType: req.body.bodyType,
        bodyVideoUrl: req.body.bodyVideoUrl,
        bioContent: req.body.bioContent,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    })
    createSendToken(newUser, 201, res)
})

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return next(new AppError("Email and password required!!", 404))
    }
    const user = await User.findOne({ email: email }).select('+password')
    if (user.googleId) {
        return next(new AppError("Please login via 'LOGIN WITH GOOGLE'", 404))
    }
    if (!user || !(await user.correctPassword(password, user.password)))
        return next(new AppError("Email or password incorrect", 401))

    user.lastOnline = Date.now();
    await user.save({ validateBeforeSave: false })

    createSendToken(user, 201, res)
})

// exports.logout = (req, res) => {
//     res.cookie('jwt', 'loggedout', {
//         expires: new Date(Date.now() + 10 * 1000), // expires in 10 seconds
//         httpOnly: true,
//     });
//     res.status(200).json({ status: 'success', message: 'User logged out success' });
// };

exports.forgotPassword = catchAsync(async (req, res, next) => {
    if (!req.body.email) {
        return next(new AppError("Please enter your email to reset password"))
    }
    const user = await User.findOne({ email: req.body.email })
    if (!user) {
        return next(new AppError("Their is no user with this email address", 404))
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false })

    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/employee/resetPassword/${resetToken}`

    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token (valid for 10 min)',
            message
        })
        res.status(200).json({
            status: 'success',
            message: 'Token sent to email'
        })
    } catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false })

        return next(new AppError("There was an error sending the mail. Try again later", 500))
    }
})

exports.resetPassword = catchAsync(async (req, res, next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } })
    if (!user) {
        return next(new AppError("Token is invalid or expired", 400))
    }
    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    createSendToken(user, 200, res)
})

exports.updatePassword = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id).select('+password');
    if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
        return next(new AppError("Incorrect current password", 401))
    }
    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm
    await user.save();
    createSendToken(user, 200, res);
})

exports.updateProfile = catchAsync(async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) {
        return next(new AppError('This route is not for password update. Please use /updatePassword', 400))
    }
    // const filteredBody = filterObj(req.body, 'firstname', 'lastname', 'dob', 'phone', 'email ', 'favourite')
    const filteredBody = filterObj(req.body, 'firstname', 'lastname', 'email', 'dob', 'phone', 'profileImage', 'interest', 'height', 'bodyType', 'bioContent')
    if (req.email !== req.body.email) {
        const user = await User.findOne({ email: req.body.email })
        if (user) {
            return next(new AppError('Email already exists', 400))
        }
    }
    if (req.phone !== req.body.phone) {
        const user = await User.findOne({ phone: req.body.phone })
        if (user) {
            return next(new AppError('Phone number already exists', 400))
        }
    }
    if (req.file) filteredBody.profileImage = req.file.filename;

    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, { new: true, runValidators: true })

    res.status(200).json({
        status: 'success',
        data: {
            user: updatedUser
        }
    })
})

exports.sendVerificationEmail = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return next(new AppError('User not found', 404))
    }
    if (user.validEmail) {
        return next(new AppError('Email is already verified!', 400))
    }
    // OTP generation and set cookie
    const otp = Math.floor(Math.random() * 9000 + 1000);
    res.cookie("otp", otp, { maxAge: 180000 })

    // Verification URL token generation & set cookie
    const verificationToken = crypto.randomBytes(32).toString('hex');
    res.cookie("verificationToken", verificationToken, { maxAge: 180000 })
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/v1/user/verifyEmail/${verificationToken}`

    const message = `OTP for email verification is ${otp} \nClick the link to verify email ${verificationUrl}`
    try {
        await sendEmail({ email: user.email, subject: 'Email verification OTP and Link', message })
        res.status(200).json({
            status: 'success',
            message: 'OTP & Link Sent to Email'
        })
    } catch (error) {
        res.clearCookie("otp");
        res.clearCookie("verificationToken");
        return next(new AppError("There was an error sending the mail"))
    }
})

exports.verifyEmail = catchAsync(async (req, res, next) => {
    const enteredOtp = req.body.otp;
    const paramsToken = req.params.token;

    if (!enteredOtp && !paramsToken) {
        return next(new AppError('Please enter OTP or Verification Token', 400))
    }

    if (!req.cookies.otp && enteredOtp) {
        return next(new AppError("OTP expired", 500));
    }
    if (!req.cookies.verificationToken && paramsToken) {
        return next(new AppError("Token expired", 500));
    }

    const sentOtp = req.cookies.otp;
    const sentToken = req.cookies.verificationToken;
    const currentUser = await User.findById(req.user.id)

    if (enteredOtp) {
        if (enteredOtp === sentOtp) {
            if (!currentUser) {
                return next(new AppError('User not found or not logged in', 404))
            }
            currentUser.validEmail = true;
            await currentUser.save({ validateBeforeSave: false });
            res.clearCookie("otp");
            res.clearCookie("verificationToken");
            res.status(200).json({
                status: 'success',
                message: 'Email Verification Successfull!'
            })
        }
        else {
            return next(new AppError('OTP Invalid or Expired!', 500))
        }
    }
    else if (paramsToken) {
        if (paramsToken === sentToken) {
            if (!currentUser) {
                return next(new AppError('User not found or not logged in', 404))
            }
            currentUser.validEmail = true;
            await currentUser.save({ validateBeforeSave: false });
            res.clearCookie("otp");
            res.clearCookie("verificationToken");
            res.status(200).json({
                status: 'success',
                message: 'Email Verification Successfull!'
            })
        }
        else {
            return next(new AppError("Token Invalid or Expired", 400))
        }
    }
})

exports.sendPhoneOtpSms = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return next(new AppError('User not found', 404))
    }
    if (user.validPhone) {
        return next(new AppError('Phone Number is already verified!', 400))
    }
    const otp = Math.floor(Math.random() * 9000 + 1000);
    const message = `OTP for Phone Number verification is ${otp}`
    const client = new twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN)
    try {
        await client.messages.create({
            body: message,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: user.phone
        });
        res.cookie("otp", otp, { maxAge: 180000 });
        res.status(200).json({
            status: 'success',
            message: 'SMS Sent Successfull!'
        })
    } catch (error) {
        console.log(error)
        return next(new AppError("Error while sending the SMS!", 400))
    }
})

exports.verifySmsOtp = catchAsync(async (req, res, next) => {
    const enteredOtp = req.body.otp;
    if (!enteredOtp) {
        return next(new AppError("Please enter OTP", 400));
    }

    const sentOtp = req.cookies.otp;
    if (!sentOtp) {
        return next(new AppError("OTP Expired!!", 500))
    }

    const currentUser = await User.findById(req.user.id)
    if (!currentUser) {
        return next(new AppError("User not found!", 404))
    }
    if (enteredOtp === sentOtp) {
        try {
            currentUser.validPhone = true;
            await currentUser.save({ validateBeforeSave: false })
            res.clearCookie("otp");
            res.status(200).json({
                status: 'success',
                message: 'Phone Number Verified Successfully!!'
            })
        } catch (error) {
            return next(new AppError("Error while verifying the OTP", 400))
        }
    }
    else {
        return next(new AppError("OTP Invalid or Expired", 400))
    }
})

exports.googlePassport = catchAsync(async (req, res, next) => {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:8001/api/v1/user/google/callback",
        scope: ["profile", "email"]
    }, async (accessToken, refreshToken, profile, done) => {
        // console.log("Profile: ", profile)
        const newUser = {
            googleId: profile.id,
            // displayName: profile.displayName,
            firstname: profile.name.givenName,
            lastname: profile.name.familyName,
            profileImage: profile.photos[0].value,
            email: profile.emails[0].value,
            validEmail: true
        };
        try {
            //find the user in our database
            // let user = await User.findOne({ googleId: profile.id });
            let user = await User.findOne({ $or: [{ googleId: profile.id }, { email: profile.email }] });
            if (user) {
                //If user present in our database.
                done(null, user);
            } else {
                // if user is not preset in our database save user data to database.
                user = await User.create(newUser);
                done(null, user);
            }
        } catch (err) {
            console.error(err);
        }
    }
    ));
    // used to serialize the user for the session
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(async (id, done) => {
        const user = await User.findById(id);
        done(null, user);
    });
})

exports.sendRequest = catchAsync(async (req, res, next) => {
    try {
        const currentUser = await User.findById(req.user.id);
        const recipientUser = await User.findById(req.body.id);
        if (!req.body.id) {
            res.status(400).json({
                status: 'failure',
                message: `Please enter the recipient id`
            })
            return next(new AppError("Please enter the recipient id", 400));
        }
        if (!currentUser) {
            res.status(400).json({
                status: 'failure',
                message: `User not found or not logged in!`
            })
            return next(new AppError("User not found or not logged in!", 404))
        }
        if (!recipientUser) {
            res.status(400).json({
                status: 'failure',
                message: `Recepient User not found!`
            })
            return next(new AppError("Recepient User not found!", 404))
        }
        if (currentUser.id === recipientUser.id) {
            // return next(new AppError("Both the users are same!!", 500))
            res.status(200).json({
                message: `You can't send request to yourself. As both the users are same!!`
            })
            return next();
        }
        if (currentUser.friends.includes(recipientUser.id)) {
            // return next(new AppError("Both users are already friends"))
            res.status(200).json({
                message: `Both Users are already friends`
            })
            return next();
        }
        const rowUserRequest = await UserRequest.findOne({ senderId: currentUser.id, recipientId: recipientUser.id });
        // const rowUserRequest = await UserRequest.findOne({ $or: [{ senderId: currentUser.id, recipientId: recipientUser.id }, { senderId: recipientUser.id, recipientId: currentUser.id }] })
        const reverseRequestCheck = await UserRequest.findOne({ senderId: recipientUser.id, recipientId: currentUser.id });
        if (rowUserRequest) {
            // return next(new AppError(`Request is already sent and request status is ${rowUserRequest.status}`, 400))
            res.status(200).json({
                message: `Request is already sent and request is ${rowUserRequest.status}`
            })
            return next();
        }
        if (reverseRequestCheck) {
            if (reverseRequestCheck.status === 'Accepted') {
                res.status(200).json({
                    message: `You both are already friends`
                })
            }
            if (reverseRequestCheck.status === 'Pending') {
                res.status(200).json({
                    message: `User has already sent you request and it is pending. Please review the request`
                })
            }
            if (reverseRequestCheck.status === 'Rejected') {
                res.status(200).json({
                    message: `Reject is rejected by you`
                })
            }
            return next();
        }
        const newUserRequest = await UserRequest.create({
            senderId: currentUser.id,
            recipientId: recipientUser.id
        })
        if (!newUserRequest) {
            return next(new AppError("Error while sending the request", 500))
        }
        res.status(200).json({
            status: 'success',
            message: `Request sent successfully`
        })
    } catch (error) {
        console.log(error)
        return next(new AppError("Error", 500))
    }
})

exports.respondRequest = catchAsync(async (req, res, next) => {
    const currentUser = await User.findById(req.user.id);
    if (!currentUser) {
        return next(new AppError("User not found or not logged in"))
    }
    const requestId = req.body.id;
    if (!requestId) {
        res.status(404).json({
            message: `Please enter the request ID`
        })
        return next(new AppError("Please enter the request ID", 404))
    }
    const requestRow = await UserRequest.findById(requestId); // Friend Request row data
    if (!requestRow) {
        res.status(404).json({
            message: `Friend Request not found`
        })
        return next(new AppError("Friend Request not found", 404))
    }
    const senderProfile = await User.findById(requestRow.senderId.toString());
    if (!senderProfile) {
        res.status(404).json({
            message: `Sender Profile not found or might deleted his profile`
        })
        return next(new AppError("Sender Profile not found or might deleted his profile", 404))
    }
    if (requestRow.recipientId.toString() !== currentUser.id.toString()) {
        if (requestRow.senderId.toString() === currentUser.id.toString()) {
            res.status(401).json({
                message: `You have sent request so, you cannot respond to this request`
            })
            return next(new AppError("You have sent request so, you cannot respond to this request", 404))
        }
        res.status(401).json({
            message: `You are not authorized to respond to this request`
        })
        return next(new AppError("You are not authorized to respond to this request", 404))
    }
    if (requestRow.status !== 'Pending') {
        const message = requestRow.status.startsWith("Accept") ? `You are already friends!` : `Friend request is already ${requestRow.status} by you!`;
        res.status(400).json({
            message
        })
        return next(new AppError(`Friend request is already ${requestRow.status} by you!`, 404))
    }
    const reqRes = req.body.response;
    if (!reqRes) {
        res.status(404).json({
            message: `Please enter your response to the request`
        })
        return next(new AppError("Please enter your response to the request", 404))
    }
    else if (reqRes === "Pending") {
        res.status(404).json({
            message: `Friend request is already in 'Pending' Status`
        })
        return next(new AppError("Friend request is already in 'Pending' Status", 404))
    }
    requestRow.status = reqRes;
    await requestRow.save();

    const sId = senderProfile.id.toString();
    const cId = currentUser.id.toString();
    if (reqRes === "Accepted") {
        senderProfile.friends.push(cId);
        currentUser.friends.push(sId);
        await senderProfile.save({ validateBeforeSave: false });
        await currentUser.save({ validateBeforeSave: false });
        res.status(200).json({
            status: 'Success',
            message: `Friend Request is ${reqRes}. Friend is added to your friends list`
        })
    }
    if (reqRes === "Rejected") {
        await UserRequest.deleteOne({ _id: requestId });
        res.status(200).json({
            status: 'Success',
            message: `Friend Request ${reqRes} Successfully`
        })
    }
    next();
})

exports.getFriends = catchAsync(async (req, res, next) => {
    const currentUser = await User.findById(req.user.id);
    if (!currentUser) {
        return next(new AppError("User not found or not logged in"))
    }
    const friends = currentUser.friends;
    if (!friends || friends.length === 0) {
        res.status(204).json({
            message: `You have no friends`
        })
        return next(new AppError("You have no friends", 404))
    }
    const friendsList = [];
    for (let i = 0; i < friends.length; i++) {
        const friend = await User.findById(friends[i]).select("firstname lastname email dob friends profileImage gender lastOnline height bodyType bioContent joinedOn");
        if (!friend) {
            continue;
        }
        friendsList.push(friend);
    }
    res.status(200).json({
        status: 'success',
        results: friendsList.length,
        friends: friendsList
    })
})

exports.getSentPendingRequests = catchAsync(async (req, res, next) => {
    const currentUser = await User.findById(req.user.id);
    if (!currentUser) {
        return next(new AppError("User not found or not logged in"))
    }
    const getList = await UserRequest.find({ senderId: currentUser.id, status: 'Pending' })
    if (!getList || getList.length === 0) {
        res.status(200).json({
            status: 'success',
            message: `No Pending Requests Found`
        })
        return next();
    }
    const list = [];
    for (let i = 0; i < getList.length; i++) {
        const friend = await User.findById(getList[i].recipientId).select("firstname lastname email profileImage bioContent");
        if (!friend) {
            continue;
        }
        const updatedFriend = {
            requestId: getList[i].id,
            ...friend.toObject(),
            status: getList[i].status
        };
        list.push(updatedFriend);
    }
    res.status(200).json({
        status: 'success',
        results: list.length,
        list
    })
})

exports.getReceivedPendingRequests = catchAsync(async (req, res, next) => {
    const currentUser = await User.findById(req.user.id);
    if (!currentUser) {
        return next(new AppError("User not found or not logged in"))
    }
    const getList = await UserRequest.find({ recipientId: currentUser.id, status: 'Pending' })
    if (!getList || getList.length === 0) {
        res.status(200).json({
            status: 'success',
            message: `No Pending Requests Found`
        })
        return next();
    } 
    const list = []
    for (i = 0; i < getList.length; i++) {
        const friend = await User.findById(getList[i].senderId).select("firstname lastname email profileImage bioContent");
        if (!friend) continue;
        const updatedFriend = {
            requestId: getList[i].id,
            ...friend.toObject(),
            status: getList[i].status
        }
        list.push(updatedFriend);
    }
    res.status(200).json({
        status: 'success',
        results: list.length,
        list
    })
})

exports.removeFriends = catchAsync(async (req, res, next) => {
    const currentUser = await User.findById(req.user.id);
    if (!currentUser) {
        return next(new AppError("User not found or not logged in"))
    }
    const friendId = req.body.id;
    if (!friendId) {
        res.status(404).json({
            message: `Please provide friend id`
        })
        return next(new AppError("Please provide friend id", 404))
    }
    // All 3 of these works same
    // const otherUser = await User.findOne({_id: friendId, friends: {$elemMatch: {$eq: currentUser.id}}}); 
    // const otherUser = await User.findById(friendId).where('friends').equals(currentUser._id);
    const otherUser = await User.findOne({ _id: friendId, friends: { $in: [currentUser._id] } });
    if (!otherUser) {
        res.status(404).json({
            message: `Both of you are not friends!!`
        })
        return next(new AppError("Both of you are not friends!!!", 404))
    }
    let reqRow = await UserRequest.findOneAndDelete({
        $or: [
            { senderId: currentUser.id, recipientId: otherUser.id },
            { senderId: otherUser.id, recipientId: currentUser.id }
        ]
    });
    otherUser.friends.pull(currentUser.id)
    currentUser.friends.pull(otherUser.id)
    await otherUser.save({ validateBeforeSave: false });
    await currentUser.save({ validateBeforeSave: false });

    res.status(200).json({
        status: 'success',
        message: `Friend removed successfully`
    })
})

//! Code Generated from Github Copilot
// exports.viewFriendProfile = catchAsync(async (req, res, next) => {
//     const currentUser = await User.findById(req.user.id);
//     if (!currentUser) {
//         return next(new AppError('No user found with that ID', 404));
//     }

//     const friendId = req.params.id;
//     if (!friendId) {
//         return next(new AppError('No friend ID provided', 400));
//     }

//     const friend = await User.findOne({ _id: friendId, friends: { $in: [currentUser._id] } });
//     if (!friend) {
//         return next(new AppError('This user is not your friend', 403));
//     }

//     res.status(200).json({
//         status: 'success',
//         data: {
//             friend
//         }
//     });
// });

// exports.countFriends = catchAsync(async (req, res, next) => {
//     const currentUser = await User.findById(req.user.id);
//     if (!currentUser) {
//         return next(new AppError('No user found with that ID', 404));
//     }

//     const friendCount = currentUser.friends.length;

//     res.status(200).json({
//         status: 'success',
//         data: {
//             friendCount
//         }
//     });
// });

// exports.countOtherUserFriends = catchAsync(async (req, res, next) => {
//     const currentUser = await User.findById(req.user.id);
//     if (!currentUser) {
//         return next(new AppError('No user found with that ID', 404));
//     }

//     const otherUserId = req.params.id;
//     if (!otherUserId) {
//         return next(new AppError('No user ID provided', 400));
//     }

//     const otherUser = await User.findOne({ _id: otherUserId, friends: { $in: [currentUser._id] } });
//     if (!otherUser) {
//         return next(new AppError('No friend found with that ID', 404));
//     }

//     const friendCount = otherUser.friends.length;

//     res.status(200).json({
//         status: 'success',
//         data: {
//             friendCount
//         }
//     });
// });

