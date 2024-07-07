-- Add down migration script here

ALTER TABLE members
    ALTER COLUMN password_hash SET NOT NULL;
