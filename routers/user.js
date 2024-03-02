const express = require('express');
const userCTRL = require('../controllers/user.controller');
const { userRegisterValidation, userLoginValidation } = require('../middleware/validation');
const userRouter = express.Router();


/**
 * @typedef User
 * @property {string}  name
 * @property {string}  email
 * @property {string}  password
 */

/**
 * Create Training and Lession in by maintaing parent if isParent is true then is main Training and then using parent we find their lession
 * @route POST /user/add
 * @param {User.model} Training.body.required - Training Obj
 * @group User - User operation
 * @returns {object} 200 - 
 *      Return Training Obj
 *      
 * @returns {Error}  Error - Unexpected error
 * @security Admin
 */
userRouter.post("/add", userRegisterValidation, userCTRL.Register)
/**
 * @typedef UserLogin
 * @property {string} username.required
 * @property {string} password.required
 */


/**
 * User Login
 * @route POST /user/login
 * @param {UserLogin.model} data.body.required - user login object
 * @group User - User operation
 * @returns {object} 200 -
 *      Return Jwt Token in key result.token
 *
 * @returns {Error}  Error - Unexpected error
 */
userRouter.post("/login", userLoginValidation, userCTRL.login)

module.exports = userRouter