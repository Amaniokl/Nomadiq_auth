import express from 'express';
import { loginEmail, loginPhone, logout, refreshAccessToken, sendOtpToUserByEmail, sendOtpToUserByPhone, verifyOtpEmailRegister, verifyOtpNumberRegister, verifyToken } from '../controllers/authController.js';
import { authenticateJWT } from "../middlewares/auth.js";

const router = express.Router();


router.post("/sendotpnumber", sendOtpToUserByPhone);
router.post("/verifyotpnumber", verifyOtpNumberRegister);
router.post("/sendotpemail", sendOtpToUserByEmail)
router.post("/verifyotpemail", verifyOtpEmailRegister)
router.post("/loginphone", loginPhone);
router.post("/loginemail", loginEmail);
router.post("/logout", logout)
router.post("/refreshtoken", refreshAccessToken)
router.get("/verifytoken", authenticateJWT, verifyToken);
export default router;
