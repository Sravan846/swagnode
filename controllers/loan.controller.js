const loanSchema = require('../model/loan');
const userSchema = require('../model/user');
module.exports = {
    loanRequest: async (req, res) => {
        try {
            const { loanType, amount } = req.body
            const userId = req.user
            const checkUser = await loanSchema.findOne({ requestedBy: userId, status: "pendding" })
            if (checkUser) {
                return res.status(203).send({ message: "This user  is already applied ", isSuccess: false })
            }
            else {
                const data = await loanSchema({ loanType, amount, requestedBy: userId })
                data.save()
                return res.status(200).send({ message: "Loan is added succesfully", isSuccess: true })
            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    },
    loanUpate: async (req, res) => {
        try {
            const { status, } = req.body
            const { loanId } = req.params
            const userId = req.user
            if (userId.isAdmin) {
                const checkLoanDetails = await loanSchema.findById(loanId)
                if (!checkLoanDetails) {
                    return res.status(203).send({ message: "This loan details not found", isSuccess: false })
                }
                else {
                    checkLoanDetails.status = status
                    checkLoanDetails.approvedBy = userId
                    return res.status(200).send({ message: "Loan status is approved", isSuccess: true })
                }
            } else {
                return res.status(203).send({ message: "you have not rights to access this api", isSuccess: false })

            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    },
    getAllLoans: async (req, res) => {
        try {
            const userId = req.user
            const { status } = req.query
            const checkAdmin = await userSchema.findById(loanId)
            if (!checkAdmin.isAdmin) {
                return res.status(203).send({ message: "you have not rights to access this api", isSuccess: false })
            }
            else {
                const response = await loanSchema.find({ status })
                return res.status(200).send({ message: "Get all loan details", response, isSuccess: true })
            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    },
    getLoanById: async (req, res) => {
        try {
            const { loanId } = req.params
            const checkLoanDetails = await loanSchema.findById(loanId)
            if (!checkLoanDetails) {
                return res.status(203).send({ message: "This loan details not found", isSuccess: false })
            }
            else {
                const response = await loanSchema.findById(loanId)
                return res.status(200).send({ message: "Get loan details", response, isSuccess: true })
            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    },
    deleteLoanById: async (req, res) => {
        try {
            const { loanId } = req.params
            const userId = req.user
            if (userId.isAdmin) {
                const checkLoanDetails = await loanSchema.findById(loanId)
                if (!checkLoanDetails) {
                    return res.status(203).send({ message: "This loan details not found", isSuccess: false })
                }
                else {
                    await loanSchema.findByIdAndDelete(loanId)
                    return res.status(200).send({ message: "This loan details deleted", response, isSuccess: true })
                }
            } else {
                return res.status(203).send({ message: "you have not rights to access this api", isSuccess: false })
            }
        } catch (error) {
            console.log('error', error)
            return res.status(500).send({ message: error.message, issuccess: false })
        }
    }
}