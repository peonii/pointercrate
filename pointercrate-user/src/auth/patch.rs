use crate::{
    auth::AuthenticatedUser,
    error::{Result, UserError},
    patch::PatchUser,
};
use log::info;
use pointercrate_core::util::{non_nullable, nullable};
use serde::Deserialize;
use sqlx::PgConnection;
use std::fmt::{Debug, Formatter};

#[derive(Deserialize)]
pub struct PatchMe {
    #[serde(default, deserialize_with = "non_nullable")]
    pub(super) password: Option<String>,

    #[serde(default, deserialize_with = "nullable")]
    pub(super) display_name: Option<Option<String>>,

    #[serde(default, deserialize_with = "nullable")]
    pub(super) youtube_channel: Option<Option<String>>,

    #[serde(default, deserialize_with = "nullable")]
    pub(super) email_address: Option<Option<String>>,
}

impl PatchMe {
    pub fn changes_password(&self) -> bool {
        self.password.is_some()
    }

    pub fn initiates_email_change(&self) -> bool {
        matches!(self.email_address, Some(Some(_)))
    }
}

// manual debug impl to ensure that the password field is never printed anywhere
impl Debug for PatchMe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatchMe")
            .field("display_name", &self.display_name)
            .field("youtube_channel", &self.youtube_channel)
            .finish()
    }
}

impl AuthenticatedUser {
    pub async fn apply_patch(mut self, patch: PatchMe, connection: &mut PgConnection) -> Result<Self> {
        if let Some(password) = patch.password {
            self.set_password(password, connection).await?;
        }

        if let Some(email) = patch.email_address {
            match email {
                Some(email) => self.initiate_email_change(email).await?,
                None => self.reset_email(connection).await?,
            }
        }

        self.user = self
            .user
            .apply_patch(
                PatchUser {
                    display_name: patch.display_name,
                    youtube_channel: patch.youtube_channel,
                    permissions: None,
                },
                connection,
            )
            .await?;

        Ok(self)
    }

    /// Initiates a change of email address
    ///
    /// generates a change-email token and mails it to the given email address in the form of a
    /// verification link.
    ///
    /// does not make any changes to the database, email is only changed when verification link is
    /// clicked.
    pub async fn initiate_email_change(&self, email: String) -> Result<()> {
        // TODO: actually mail out the token

        println!(
            "https://pointercrate.com/api/v1/auth/verify_email?token={}",
            self.generate_change_email_token(email)
        );

        Ok(())
    }

    pub async fn set_email_address(&mut self, email: String, connection: &mut PgConnection) -> Result<()> {
        sqlx::query!(
            "UPDATE members SET email_address = ($1::text)::email WHERE member_id = $2",
            email,
            self.user.id,
        )
        .execute(connection)
        .await?;

        self.email_address = Some(email);

        Ok(())
    }

    pub async fn reset_email(&mut self, connection: &mut PgConnection) -> Result<()> {
        sqlx::query!("UPDATE members SET email_address = NULL WHERE member_id = $1", self.user.id)
            .execute(connection)
            .await?;

        self.email_address = None;

        Ok(())
    }

    pub async fn set_password(&mut self, password: String, connection: &mut PgConnection) -> Result<()> {
        if self.google_account_id.is_some() {
            return Err(UserError::NotApplicable);
        }

        Self::validate_password(&password)?;

        info!("Setting new password for user {}", self.inner());

        // it is safe to unwrap here because the only errors that can happen are
        // 'BcryptError::CostNotAllowed' (won't happen because DEFAULT_COST is obviously allowed)
        // or errors that happen during internally parsing the hash the library itself just
        // generated. Obviously, an error there is a bug in the library, so we definitely wanna panic since
        // we're dealing with passwords
        self.password_hash = Some(bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap());

        sqlx::query!(
            "UPDATE members SET password_hash = $1 WHERE member_id = $2",
            self.password_hash,
            self.user.id
        )
        .execute(connection)
        .await?;

        Ok(())
    }
}
