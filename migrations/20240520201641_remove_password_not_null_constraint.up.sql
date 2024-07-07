-- Add up migration script here

ALTER TABLE members
    ALTER COLUMN password_hash DROP NOT NULL;
