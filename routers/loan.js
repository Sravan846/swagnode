const express = require('express');
const loanCTRL = require('../controllers/loan.controller');
const { loanValidation } = require('../middleware/validation');
const verifyToken = require('../middleware/auth');
const loanRouter = express.Router();
loanRouter.post("/add", [verifyToken, loanValidation], loanCTRL.loanRequest)
loanRouter.put("/:loanId", verifyToken, loanCTRL.loanUpate)
loanRouter.get("/:loanId", verifyToken, loanCTRL.getLoanById)
loanRouter.delete("/:loanId", verifyToken, loanCTRL.deleteLoanById)
loanRouter.get("/", verifyToken, loanCTRL.loanRequest)

module.exports = loanRouter