# FastAPI Authentication API

A FastAPI application that provides user authentication functionality, deployed on Render.

## Features

- User registration and login
- Password reset with OTP verification
- JWT token authentication
- Mobile number verification

## API Endpoints

### Authentication
- `POST /Register` - Register a new user
- `POST /Login` - Login and get access token
- `POST /forgot-password` - Request password reset
- `POST /verify-otp` - Verify OTP for password reset
- `POST /update-password` - Update password after verification

## Deployment

This application is configured for deployment on Render:

1. **Web Service Configuration**:
   - Environment: Python
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

2. **Database Configuration**:
   - PostgreSQL database
   - Environment variable: `DATABASE_URL`
   - JWT Secret: `SECRET_KEY`

3. **Environment Variables**:
   - `DATABASE_URL`: PostgreSQL connection string
   - `SECRET_KEY`: JWT secret key for token generation

## Security

- All passwords are hashed using bcrypt
- JWT tokens are used for authentication
- OTP verification for password reset
- Protected routes require valid JWT token

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: JWT secret key for token generation

## Testing

The API can be tested using tools like Postman or curl. Make sure to:
1. Register a new user
2. Login to get the access token
3. Use the token in the Authorization header for protected routes 