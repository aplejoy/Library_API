# Library Management API

The **Library Management API** is developed using PHP and the Slim framework. It provides endpoints for user registration, authentication, and managing authors and books. The API uses JSON Web Tokens (JWT) for secure authentication and token management.

## Features

- **User Management:** Register, Authenticate, Show, Update, and Delete Users.
- **Author Management:** Register, Show, Update, and Delete Authors.
- **Book Management:** Register, Show, Update, and Delete Books.
- **Book-Author Management:** Manage associations between Books and Authors.
- **Token Management:** Generate and Validate tokens for secure access.

## Requirements

- PHP 7.4 or higher
- MySQLyog
- XAMPP
- Slim Framework
- Git
- Firebase (for JWT)
- Composer
- Node.js

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/aplejoy/Library_API.git
   cd Library_API
2. **Install dependencies**
   ```bash
   composer require slim/slim:3.*
   composer require firebase/php-jwt

## API Endpoints

### User Management

**Register User**:
- **Endpoint:** `/user/register`
- **Method:** `POST`
- **Payload:**
   ```json
   {
     "username": "your_username",
     "password": "your_password"
   }

**Authenticate User**:
- **Endpoint:** `/user/auth`
- **Method:** `POST`
- **Payload:**
   ```json
   {
     "username": "your_username",
     "password": "your_password"
   }

**Show User**:
-**Endpoint:** `/user/show`
-**Method:** `GET`
-**Payload:** 
  ```json
   {
     "Authorization": "Bearer your_token"
   }

##Token Management
-**Generate a Token:** Tokens are created during user authentication and recorded in the tokens table with an 'active' status.
-**Validate the Token:** The validateToken function is used to verify tokens by checking their status and decoding them to extract the user ID.
