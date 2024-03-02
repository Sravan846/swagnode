const jwt = require('jsonwebtoken')
const userSchema = require("../model/user")
const verifyToken = async (req, res, next) => {
    const token = req.body.token || req.query.token || req.header('authorization') || req.header['x-access-token']
    if (!token) {
        return res.status(203).send({ message: "Token is required" })
    } else {
        const bearerToken = token.split(" ")[1]
        try {
            jwt.verify(bearerToken, process.env.SECRETKEY, async (err, authData) => {
                if (err) {
                    return res.status(203).send({ message: err.message })
                }
                let user = await userSchema.findById(authData.userId)
                req.user = user
                next()
            })
        } catch (error) {
            return res.status(203).send({ message: error.message })
        }
    }
}

module.exports = verifyToken