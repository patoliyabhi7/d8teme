const express = require("express");
const userController = require("./../controllers/userController");
const passport = require("passport");

const router = express.Router();

router.post("/signup", userController.signup);
router.post("/login", userController.login);
// router.get("/logout", userController.protect, userController.logout);
router.post("/forgotPassword", userController.forgotPassword);
router.patch("/resetPassword/:token", userController.resetPassword);
router.patch("/updatePassword", userController.protect, userController.updatePassword);
router.patch("/updateProfile", userController.protect, userController.updateProfile);
router.post("/sendVerificationEmail", userController.protect, userController.sendVerificationEmail);
router.post("/verifyEmail/:token?", userController.protect, userController.verifyEmail);
router.post("/sendPhoneOtpSms", userController.protect, userController.sendPhoneOtpSms);
router.post("/verifySmsOtp", userController.protect, userController.verifySmsOtp);
router.post("/sendRequest", userController.protect, userController.sendRequest);
router.post("/respondRequest", userController.protect, userController.respondRequest);
router.get("/getFriends", userController.protect, userController.getFriends);
router.get("/getSentPendingRequests", userController.protect, userController.getSentPendingRequests);
router.get("/getReceivedPendingRequests", userController.protect, userController.getReceivedPendingRequests);
router.post("/removeFriends", userController.protect, userController.removeFriends);

// Google Passport
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback", passport.authenticate("google", { failureRedirect: "/user/login" }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/");
    }
);

module.exports = router;