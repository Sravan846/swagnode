const userSchema = require('../model/user');
const bcrypt = require('bcrypt');
const jwtToken = require('jsonwebtoken');
module.exports = {
    Register: async (req, res) => {
        try {
            const { name, email, password } = req.body
            const checkEmail = await userSchema.findOne({ email })
            if (checkEmail) {
                return res.status(203).send({ message: "This email is already exist", isSuccess: false })
            }
            else {
                const hashPassword = await bcrypt.hash(password, 10)
                const data = await userSchema({ name, email, password: hashPassword })
                data.save()
                return res.status(200).send({ message: "User is register", isSuccess: true })
            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    },
    login: async (req, res) => {
        try {
            const { email, password } = req.body
            const checkEmail = await userSchema.findOne({ email })
            if (!checkEmail) {
                return res.status(203).send({ message: "This email is not exist", isSuccess: false })
            }
            else {
                const isMatch = await bcrypt.compare(password, checkEmail.password)
                if (isMatch) {
                    const token = jwtToken.sign({ email, userId: checkEmail.id }, process.env.SECRETKEY, { expiresIn: process.env.EXPIREIN })
                    return res.status(200).send({ message: "User is login", token, isSuccess: true })
                } else {
                    return res.status(203).send({ message: "Password is wrong", isSuccess: false })
                }
            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    }
}