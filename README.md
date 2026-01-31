# 🛡️ SecureAuth | Enterprise Identity System

[![Deployment Status](https://img.shields.io/badge/Deployment-Live-success?style=for-the-badge&logo=render)](https://secure-auth-portal.onrender.com)
[![Tech Stack](https://img.shields.io/badge/Stack-PERN-blue?style=for-the-badge)](https://github.com/papitolovesspag)

> **Live Demo:** [https://secure-auth-portal.onrender.com](https://secure-auth-portal.onrender.com)

## 📖 Overview
**SecureAuth** is a production-ready identity management portal designed to demonstrate robust backend security practices. It features a dual-strategy authentication system (Local + Google OAuth 2.0), session persistence via PostgreSQL, and a responsive "Onyx Secure" UI interface.

Unlike standard tutorials, this application implements **persistent session storage** (sessions survive server restarts) and **enterprise-grade error handling**.

## 🚀 Key Features

### 🔒 Security & Authentication
* **Google OAuth 2.0:** Frictionless login using Passport.js Google Strategy.
* **Local Authentication:** Secure email/password login with **bcrypt** (Salted & Hashed).
* **Session Persistence:** Sessions are stored in a **PostgreSQL Database** (via `connect-pg-simple`) rather than Memory, ensuring scalability and preventing data loss on server restarts.
* **Flash Messaging:** Dynamic error handling for wrong passwords, existing users, or unauthorized access.

### 💻 UI/UX Architecture
* **"Onyx Secure" Theme:** A custom dark-mode interface designed for professional B2B aesthetics.
* **Responsive Dashboard:** A grid-system layout that adapts from mobile to ultrawide desktop monitors.
* **Dynamic Rendering:** EJS templates render user-specific data (Email, ID, Secrets) directly from the database.

## 🛠️ Tech Stack

* **Backend:** Node.js, Express.js
* **Database:** PostgreSQL (Hosted on Render)
* **Authentication:** Passport.js (Local + Google Strategies)
* **Security:** Bcrypt (Hashing), Connect-Flash (Alerts)
* **Frontend:** EJS (Templating), CSS3 (Custom Grid & Flexbox)
* **DevOps:** Render (Web Service + Managed DB), Git

## 📸 Screenshots

| Login Portal | User Dashboard |
|<img width="3200" height="1550" alt="Screenshot 2026-01-31 095637" src="https://github.com/user-attachments/assets/4bde722e-9430-44c9-ab99-69e0674c14fa" />|
|:-<img width="3200" height="1546" alt="Screenshot 2026-01-31 095438" src="https://github.com/user-attachments/assets/79dca5f8-1b80-46d5-9a66-2855aa4d6041" />
--:|
| (PASTE LOGIN LINK HERE) | (PASTE DASHBOARD LINK HERE) |

## ⚙️ Installation & Local Setup

Follow these steps to get the project running on your local machine.

### 1. Prerequisites
Ensure you have the following installed:
* [Node.js](https://nodejs.org/) (v18 or higher)
* [PostgreSQL](https://www.postgresql.org/download/)

### 2. Clone the Repository
```bash```
`git clone [https://github.com/papitolovesspag/secure-auth-portal.git](https://github.com/papitolovesspag/secure-auth-portal.git)`
`cd secure-auth-portal`
3. Install Dependencies
Bash
npm install
4. Database Configuration
You must create a local database before running the app. Open your terminal (or pgAdmin) and run:

SQL
psql -U postgres
CREATE DATABASE secrets;
\q
(Note: The application will automatically create the required Tables inside this database when it starts.)

5. Environment Variables
Create a file named .env in the root directory. You will need Google OAuth credentials from the Google Cloud Console.

Add the following configuration to .env:

Code snippet
# Database Config
PG_USER=postgres
PG_HOST=localhost
PG_DATABASE=secrets
PG_PASSWORD=your_postgres_password
PG_PORT=5432

# Session Security
SESSION_SECRET=type_anything_random_here_to_secure_cookies

# Google OAuth 2.0 (Required for Google Login)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
6. Run the Application
Bash
node index.js
The server will start on port 3000.

Open your browser and visit: http://localhost:3000

🗄️ Database Schema
The application automatically manages two tables:

users: Stores user credentials and encrypted secrets.

id: SERIAL PRIMARY KEY

email: VARCHAR UNIQUE

password: HASHED STRING

secret: TEXT

session: Managed automatically by connect-pg-simple for storing active cookies.

🤝 Contributing
This is a portfolio project. Feel free to fork and use it as a template for your own authentication systems.

© 2026 SecureAuth Systems.
