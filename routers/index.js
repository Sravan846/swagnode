const express = require('express');
const userRouter = require('./user');
const loanRouter = require('./loan');
const mainRouter = express.Router();
mainRouter.use("/user", userRouter)
mainRouter.use("/loan", loanRouter)

module.exports = mainRouter