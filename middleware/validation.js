const Joi = require("joi")

const userRegisterValidation = async (req, res, next) => {
    const Schema = Joi.object({
        name: Joi.string().required().label("name"),
        email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required().label("email"),
        password: Joi.string().required().label("password")
    })
    const { error } = Schema.validate(req.body)
    if (error) {
        return res.status(203).send({ message: error.message })
    } else {
        next()
    }
}
const userLoginValidation = async (req, res, next) => {
    const Schema = Joi.object({
        email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required().label("email"),
        password: Joi.string().required().label("password")
    })
    const { error } = Schema.validate(req.body)
    if (error) {
        return res.status(203).send({ message: error.message })
    } else {
        next()
    }
}
const loanValidation = async (req, res, next) => {
    const Schema = Joi.object({
        loanType: Joi.string().valid("personal loan", "professional loan").required().label("loan type"),
        amount: Joi.number().required().label("amount"),
        status: Joi.string().valid("pendding", "approved", "reject").label("status"),
    })
    const { error } = Schema.validate(req.body)
    if (error) {
        return res.status(203).send({ message: error.message })
    } else {
        next()
    }
}
module.exports = { userRegisterValidation, userLoginValidation, loanValidation }