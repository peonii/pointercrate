-- Add up migration script here

ALTER TABLE members
    ADD COLUMN google_account_id VARCHAR(255) NULL;