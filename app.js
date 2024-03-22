const express = require('express')
const userRouter = require('./routes/userRoutes.js');

const app = express();
app.use(express.json());

app.use('/api/v1/user', userRouter);

app.use((err,req,res,next)=>{
    res.status(err.statusCode || 500).json({
        status: 'error',
        message: err.message
    })
})

module.exports = app;