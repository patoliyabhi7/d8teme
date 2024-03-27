const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcrypt')
const crypto = require('crypto')

const userSchema = mongoose.Schema({
    firstname: {
        type: String,
        required: true,
        lowercase: true
    },
    lastname: {
        type: String,
        lowercase: true
    },
    email: {
        type: String,
        required: [true, 'Email address is required'],
        unique: true,
        lowercase: true,
        trim: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    phone: {
        type: String,
        required: [function () {
            return !this.googleId; // Required if not logging in via Google
        }, 'Phone Number is required'],
        unique: true,
        sparse: true, // Allows multiple documents to have a null value for this field
        validate: {
            validator: function (v) {
                return /^[a-zA-Z0-9]{3,30}$/.test(v);
            },
            message: (props) => `${props.value} is not a valid Phone Number!`,
        }
    },    
    dob: {
        type: Date,
        required: [function () {
            return !this.googleId; 
        }, 'DOB is required'],
    },
    profileImage: {
        type: String
    },
    gender: {
        type: String,
        enum: ['Male', 'Female'],
        required: [function () {
            return !this.googleId; 
        }, 'Gender is required'],
    },
    interest: {
        type: String,
        enum: ['Male', 'Female'],
    },
    member_status: {
        type: Boolean,
        default: false
    },
    lastOnline: {
        type: Date
    },
    height: {
        type: String
    },
    bodyType: {
        type: String
    },
    bioVideoUrl: {
        type: String
    },
    bioContent: {
        type: String
    },
    password: {
        type: String,
        required: [function () {
            return !this.googleId; 
        }, 'Password is required'],
        minlength: 5,
        select: false
    },
    passwordConfirm: {
        type: String,
        required: [function () {
            return !this.googleId; 
        }, 'Confirm Password is required'],
        validate: {
            validator: function (el) {
                return el === this.password
            },
            message: "Both passwords are not same"
        }
    },
    validEmail: {
        type: Boolean,
        default: false,
    },
    validPhone: {
        type: Boolean,
        default: false,
    },
    friends: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    role: {
        type: String,
        enum: ['Admin', 'User'],
        default: 'User'
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,

    // Different google fields
    googleId: {
        type: String,
        required: [function () {
            return this.googleId; 
        }, 'GoogleId is required'],
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
})

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 12);

    this.passwordConfirm = undefined;
    next();
})

userSchema.pre('save', function (next) {
    if (!this.isModified('password') || this.isNew) return next();

    this.passwordChangedAt = Date.now() - 1000;
    next();
})

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    return await bcrypt.compare(candidatePassword, userPassword)
}

userSchema.methods.changedPasswordAfter = function (JWTTimeStamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10)

        return JWTTimeStamp < changedTimestamp
    }
}

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
    return resetToken;
}

// userSchema.methods.createEmailVerificationToken = function (){
//     const verificationToken = crypto.randomBytes(32).toString('hex');
//     const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
//     res.cookie("token", hashedToken, { maxAge: 600000 })
//     return verificationToken;
// }

const User = mongoose.model('User', userSchema);
module.exports = User