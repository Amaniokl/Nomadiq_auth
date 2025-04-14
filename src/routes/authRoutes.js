import express from 'express';
import { loginEmail, loginPhone, logout, refreshAccessToken, sendOtpToUserByEmail, sendOtpToUserByPhone, 
    verifyOtpEmailRegister, verifyOtpNumberRegister } from '../controllers/authController.js';

const router = express.Router();


router.post("/sendotpnumber", sendOtpToUserByPhone);
router.post("/verifyotpnumber", verifyOtpNumberRegister);
router.post("/sendotpemail", sendOtpToUserByEmail)
router.post("/verifyotpemail", verifyOtpEmailRegister)
router.post("/loginphone", loginPhone);
router.post("/loginemail", loginEmail);
router.post("/logout", logout)
router.post("/refreshtoken", refreshAccessToken)
router.post("/forgotpasswordmail", forgotPasswordByEmailSendOtp)
router.post("/resetpasswordmail", forgotPasswordByEmailVerifyOtp)
router.post("/forgotpasswordphone", forgotPasswordByPhoneSendOtp)
router.post("/resetpasswordphone", forgotPasswordByPhoneVerifyOtp)
export default router;
