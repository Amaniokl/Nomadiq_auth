import twilio from 'twilio';
import dotenv from 'dotenv';
import { ApiResponse } from '../utils/apiResponse.js';
import  {ApiError} from '../utils/apiError.js'
dotenv.config();

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
const VERIFY_SERVICE_SID = process.env.TWILIO_VERIFY_SERVICE_SID;

// Send OTP
export const sendOTP = async (phone) => {
  try {
    await client.verify.v2.services(VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: 'sms' });
    console.log(`✅ OTP sent to ${phone}`);
 
    return new ApiResponse(200, null, 'OTP sent successfully');

  } catch (error) {
    console.error('❌ Error sending OTP:', error);
    throw new Error('Failed to send OTP');
  }
};

// Verify OTP
export const verifyOTP = async (phone, otp) => {
  try {
    const verification = await client.verify.v2.services(VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code: otp });

    if (verification.status === 'approved') {
      console.log(`✅ OTP verified for ${phone}`);
      return new ApiResponse(200, null, 'OTP verified successfully');
    }

    return new ApiResponse(400, null, 'Invalid OTP');
  } catch (error) {
    console.error('❌ Error verifying OTP:', error);
    throw new Error('Failed to verify OTP');
  }
};
