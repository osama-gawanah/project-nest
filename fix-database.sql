-- SQL script to add missing 'username' column to users table
-- Run this in your MySQL database

-- Check if column exists first, then add it
-- For MySQL, we need to check manually or use a stored procedure
-- Simple approach: try to add, ignore if exists

ALTER TABLE users 
ADD COLUMN username VARCHAR(255) NOT NULL AFTER email;

-- If you get an error that the column already exists, you can modify it instead:
-- ALTER TABLE users MODIFY COLUMN username VARCHAR(255) NOT NULL;

-- Note: If the table has existing data, you may need to provide a default value:
-- ALTER TABLE users ADD COLUMN username VARCHAR(255) NOT NULL DEFAULT '' AFTER email;

-- If you need to rename 'name' column to 'username':
-- ALTER TABLE users CHANGE COLUMN name username VARCHAR(255) NOT NULL;

