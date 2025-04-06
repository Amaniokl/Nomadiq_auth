# Nomadiq_auth

# OTP Authentication Service

This is a Node.js application that implements an OTP (One-Time Password) authentication system using Twilio for sending and verifying OTPs. The application also includes user registration and login functionalities, utilizing MongoDB for data storage and Redis for caching.

## Features

- User registration with email and phone number
- OTP generation and verification
- JWT-based authentication
- Password validation
- Redis caching for OTP storage
- Error handling with custom API response and error classes

## Technologies Used

- Node.js
- Express.js
- MongoDB (with Mongoose)
- Redis
- Twilio
- JWT (JSON Web Tokens)
- dotenv for environment variable management

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or cloud instance)
- Redis (local or cloud instance)
- Twilio account (for sending OTPs)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/otp-authentication-service.git
   cd otp-authentication-service
   ```

2. Install the dependencies:

   ```bash
   npm install
   ```

3. Create a `.env` file in the root directory and add the following environment variables:

   ```plaintext
   MONGO_URI=mongodb://<username>:<password>@localhost:27017/<dbname>
   REDIS_URL=redis://localhost:6379
   TWILIO_SID=your_twilio_account_sid
   TWILIO_AUTH_TOKEN=your_twilio_auth_token
   TWILIO_VERIFY_SERVICE_SID=your_twilio_verify_service_sid
   JWT_SECRET=your_jwt_secret_key
   PORT=5000
   ```

   Replace the placeholders with your actual credentials.

### Running the Application

1. Start the MongoDB and Redis servers if they are not already running.

2. Run the application:

   ```bash
   npm start
   ```

3. The server will start on the specified port (default is 5000). You can access the API at `http://localhost:5000/api/auth`.

### API Endpoints

- **Send OTP to Phone**: `POST /api/auth/sendotpnumber`
- **Verify OTP for Phone**: `POST /api/auth/verifyotpnumber`
- **Send OTP to Email**: `POST /api/auth/sendotpemail`
- **Verify OTP for Email**: `POST /api/auth/verifyotpemail`
- **Login with Phone**: `POST /api/auth/loginphone`
- **Login with Email**: `POST /api/auth/loginemail`
- **Logout**: `POST /api/auth/logout`
- **Refresh Token**: `POST /api/auth/refreshtoken`

### Example Request

To send an OTP to a phone number, you can use the following example with `curl`:
