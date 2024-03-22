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
        required: true,
        unique: true,
        validate: {
            validator: function (v) {
                return /^[a-zA-Z0-9]{3,30}$/.test(v);
            },
            message: (props) => `${props.value} is not a valid Password!`,
        }
    },
    dob: {
        type: Date,
        required: true
    },
    profileImage: {
        type: String
    },
    gender: {
        type: String,
        enum: ['Male', 'Female'],
        required: true
    },
    interest: {
        type: String,
        enum: ['Male', 'Female'],
        required: true
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
        required: [true, 'Password is required'],
        minlength: 5,
        select: false
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Confirm Password is required'],
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
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date
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
    const resetToken = crypto.randomBytes(32).toString('hex')
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
    return resetToken;
}

const User = mongoose.model('User', userSchema);
module.exports = User