const express = require("express");
const membershipController = require("./../controllers/membershipController");
const userController = require("./../controllers/userController");

const router = express.Router();

router.post("/purchasePremium", userController.protect, membershipController.purchasePremium);


module.exports = router;