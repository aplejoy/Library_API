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

##API Endpoints

###User Management
**Register User**:
-**Endpoint:** '/user/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "username": "your_username",
  "password": "your_password"
}'

**Authenticate User**:
-**Endpoint:** '/user/auth'
-**Method:** 'POST'
-**Payload:** 
'{
  "username": "your_username",
  "password": "your_password"
}'

**Show Users**:
-**Endpoint:** '/user/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update User**:
-**Endpoint:** '/user/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_token",
  "userid": "your_userid",
  "username": "your_new_username",
  "password": "your_new_password"
}'

**Delete Users**:
-**Endpoint:** '/user/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_token",
  "userid": "your_userid"
}'

###Author Management
**Register Author**:
-**Endpoint:** '/author/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "token": "your_token",
  "name": "author_name"
}'

**Show Authors**:
-**Endpoint:** '/author/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update Author**:
-**Endpoint:** '/author/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_token",
  "authorid": "author_id",
  "name": "author_name"
}'

**Delete Author**:
-**Endpoint:** '/author/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_token",
  "authorid": "author_id"
}'

###Book Management
**Register Book**:
-**Endpoint:** '/book/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "title": "book_title",
  "authorid": 1
}'

**Show Books**:
-**Endpoint:** '/book/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update Book**:
-**Endpoint:** '/book/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "bookid": 1,
  "title": "new_book_title",
  "authorid": 1
}'

**Delete Book**:
-**Endpoint:** '/book/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "bookid": 1
}'

###Book Authors Management
**Register Book Author**:
-**Endpoint:** '/book_author/register'
-**Method:** 'POST'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "bookid": 1,
  "authorid": 1
}'

**Show Book Authors**:
-**Endpoint:** '/book_author/show'
-**Method:** 'GET'
-**Payload:** 
'{
  "Authorization": "Bearer your_token"
}'

**Update Book Author**:
-**Endpoint:** '/book_author/update'
-**Method:** 'PUT'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "collectionid": 1,
  "bookid": 1,
  "authorid": 1
}'

**Delete Book Author**:
-**Endpoint:** '/book_author/delete'
-**Method:** 'DELETE'
-**Payload:** 
'{
  "token": "your_jwt_token",
  "collectionid": 1
}'

##Token Management
-**Generate a Token:** Tokens are created during user authentication and recorded in the tokens table with an 'active' status.
-**Validate the Token:** The validateToken function is used to verify tokens by checking their status and decoding them to extract the user ID.
