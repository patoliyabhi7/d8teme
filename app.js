const express = require('express')
const userRouter = require('./routes/userRoutes.js');
const cookieParser = require('cookie-parser');
const passport = require("passport")
const { googlePassport } = require('./controllers/userController.js');
const session = require("express-session")

const app = express();
app.use(express.json());
app.use(cookieParser());

googlePassport(passport);
app.use(
    session({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: false,
    })
);

app.use((err, req, res, next) => {
    res.status(err.statusCode || 500).json({
        status: 'error',
        message: err.message
    })
})

app.use(passport.initialize());
app.use(passport.session());
app.use('/api/v1/user', userRouter);

module.exports = app;