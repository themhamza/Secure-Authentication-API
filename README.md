# Secure-Authentication-API

A secure authentication and authorization system built with **FastAPI** and **MySQL**. This API supports user signup, login, role-based access control (RBAC), and rate limiting.

---

## Features

- **User Authentication**:
  - JWT-based authentication.
  - User signup and login with email and password.
  - Password encryption using bcrypt.

- **Role-Based Access Control (RBAC)**:
  - Define roles: Admin, User, and Guest.
  - Restrict access to endpoints based on user roles.

- **API Security**:
  - Rate limiting to prevent abuse.
  - Middleware to validate JWT tokens on protected routes.
  - Secure storage of secrets using environment variables.

- **Tech Stack**:
  - **Backend**: Python FastAPI.
  - **Database**: MySQL.

- **Additional Features**:
  - Error handling for common scenarios.
  - Logging to track important events.
  - Interactive API documentation using Swagger UI and ReDoc.

---

## Prerequisites

Before running the project, ensure you have the following installed:

- **Python 3.7+**
- **MySQL Server**

---

## Setup Instructions

1. **Set Up a Virtual Environment**
     - `python -m venv venv`
        - **Activate the virtual environment:**
            - `venv\Scripts\activate`
2. **Install Dependencies**
   Install the required Python packages:
    `pip install -r requirements.txt`
   
3. **Set Up MySQL Database**
   Create a MySQL database named auth_system:
   `CREATE DATABASE auth_system;`

4. **CREATE DATABASE auth_system;**
   
   Create a .env file in the root directory:
   
     `DATABASE_URL=mysql+mysqlconnector://root:hamza@localhost/auth_system
      JWT_SECRET_KEY=your-secret-key
      JWT_ALGORITHM=HS256
      JWT_EXPIRE_MINUTES=30`

6. **Run the Application**
   
     `uvicorn auth:app --reload`

---
 
 **API Documentation**
   
The API documentation is automatically generated using Swagger UI and ReDoc.

Swagger UI: http://127.0.0.1:8000/docs

---

**Endpoints**
  Authentication
  
  - Signup: POST /signup
  
      Register a new user with email and password.
  
  - Login: POST /login
  
      Authenticate a user and return a JWT token.
  
  - Admin
      Admin Route: GET /admin
  
      Accessible only to users with the Admin role.
  
  - Testing
      Rate-Limited Route: GET /limited
  
      A route with a rate limit of 5 requests per minute.
  
  **Logging**
    Logs are saved to app.log in the root directory. The log file contains information about user signups, logins, and errors.

---

**Contributing**

    Contributions are welcome! If you'd like to contribute, please follow these steps:

  - Fork the repository.

  - Create a new branch for your feature or bugfix.

  - Commit your changes.

---

**Contact**

  For questions or feedback, feel free to reach out:

`Muhammad Hamza`

Email: muhammadhamza@anayanex.com

GitHub: `themhamza`
