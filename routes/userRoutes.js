const express = require("express");
const userController = require("./../controllers/userController");

const router = express.Router();

router.post("/signup", userController.signup);
router.post("/login", userController.login);
router.post("/forgotPassword", userController.forgotPassword);
router.patch("/resetPassword/:token", userController.resetPassword);
router.patch("/updatePassword",userController.protect, userController.updatePassword);
router.patch("/updateProfile",userController.protect, userController.updateProfile);
router.post("/sendVerificationEmail",userController.protect, userController.sendVerificationEmail);
router.post("/verifyEmail/:token?",userController.protect, userController.verifyEmail);
router.post("/sendPhoneOtpSms",userController.protect, userController.sendPhoneOtpSms);
router.post("/verifySmsOtp",userController.protect, userController.verifySmsOtp);

module.exports = router;