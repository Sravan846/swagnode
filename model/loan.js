const mongoose = require('mongoose');
const loanSchema = new mongoose.Schema({
    loanType: {
        type: String,
        enum: ["personal loan", "professional loan"],
        default: 'personal loan'
    },
    amount: {
        type: Number,
    },
    requestedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'userinfo'
    },
    approvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'userinfo'
    },
    status: {
        type: String,
        enum: ["pendding", "approved", "reject"],
        default: 'pendding'
    }
}, { timestamps: true })
module.exports = mongoose.model('loaninfo', loanSchema)