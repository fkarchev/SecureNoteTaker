-- db-init/01-schema.sql

-- SECURITY: Use a specific database
USE secure_notes;

-- SECURITY: Create tables with explicit types and constraints to ensure data integrity
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    -- SECURITY: Store passwords as long hashes (e.g., bcrypt generates 60-char hashes).
    -- NEVER store plaintext passwords.
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    -- content is text, which could contain XSS payloads. We rely on the frontend
    -- and backend validation to handle it safely, but DB stores it as raw text.
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- SECURITY: Enforce relational integrity. If a user is deleted, their notes are deleted.
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- SECURITY: The database user 'api_user' created by docker-compose environment variables
-- already has all privileges on the 'secure_notes' database, which is standard for a microservice DB.
-- However, we could further restrict it by only granting SELECT, INSERT, UPDATE, DELETE 
-- if we wanted to enforce strict least privilege (preventing the API from dropping tables).
-- For a simple app, standard CRUD access is acceptable.
