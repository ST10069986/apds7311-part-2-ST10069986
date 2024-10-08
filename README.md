## Secure Login Application

 *** 
 
## Overview
This project is a secure login application built with a React frontend and an Express.js backend. It demonstrates best practices for user authentication, including HTTPS implementation, secure password handling, and token-based authentication.

***

## Features

- User registration and login
- Secure password hashing
- JWT (JSON Web Token) based authentication
- HTTPS encryption for API calls
- MongoDB integration for user data storage
- Cross-Origin Resource Sharing (CORS) enabled
- Security headers set using Helmet.js

***

## Tech Stack

Frontend: React.js

Backend: Node.js with Express.js

Database: MongoDB

Additional Libraries: Axios, Mongoose, Helmet, CORS

***

## Prerequisites

- Node.js (v14 or later)
- MongoDB
- SSL Certificate (for HTTPS)

***

## Setup and Installation

- Clone the repository:
  
Copygit clone https://github.com/yourusername/secure-login-app.git

cd secure-login-app

- Install dependencies:

Copy# Install backend dependencies

npm install

***

# Install frontend dependencies

cd client

npm install

## Set up environment variables:

Create a .env file in the root directory and add the following:

CopyATLAS_URI=your_mongodb_connection_string

JWT_SECRET=your_jwt_secret

## Set up SSL Certificate:

Place your key.pem and cert.pem files in the root directory.

Start the backend server:

Copynpm start

In a new terminal, start the React frontend:

Copycd client

npm start

***

## Usage
After starting both the backend and frontend servers, navigate to https://localhost:3000 in your web browser to access the application.

***

## API Endpoints

POST /api/users/register: Register a new user
POST /api/users/login: Login a user

***

## Security Considerations

- The application uses HTTPS to encrypt data in transit.
- Passwords are hashed before storing in the database.
- JWT is used for maintaining user sessions.
- Helmet.js is implemented to set various HTTP headers for enhanced security.

***

## Group 5 Members
- Nathan Nayager: ST10039749
- Bianca Marcell Munsami: ST10069986
- Bai Hong He(Jackie):ST10030735
- Cristina Rodrigues:ST10049126
- Uzair:ST10045844
