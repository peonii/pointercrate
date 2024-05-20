use std::collections::HashSet;

use crate::{
    auth::{AccessClaims, AuthenticatedUser},
    error::{Result, UserError},
    User,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use log::{debug, info};
use pointercrate_core::error::CoreError;
use serde::Deserialize;
use sqlx::{Error, PgConnection};

#[derive(Deserialize)]
struct GoogleTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub scope: String,
    pub id_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    #[serde(rename = "sub")]
    pub id: String,
    pub email: String,
    pub name: String,
}

impl AuthenticatedUser {
    pub async fn basic_auth(username: &str, password: &str, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        info!("We are expected to perform basic authentication");
        debug!("Trying to authorize user {}", username);

        Self::by_name(username, connection).await?.verify_password(password)
    }

    pub async fn token_auth(access_token: &str, csrf_token: Option<&str>, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        info!("We are expected to perform token authentication");

        // Well this is reassuring. Also we directly deconstruct it and only save the ID
        // so we don't accidentally use unsafe values later on
        let mut no_validation = Validation::default();
        no_validation.insecure_disable_signature_validation();
        no_validation.validate_exp = false;
        no_validation.required_spec_claims = HashSet::new();

        let AccessClaims { id, .. } = jsonwebtoken::decode(access_token, &DecodingKey::from_secret(b""), &no_validation)
            .map_err(|_| CoreError::Unauthorized)?
            .claims;

        debug!("The token identified the user with id {}, validating...", id);

        // Note that at this point we haven't validated the access token OR the csrf token yet.
        // However, the key they are signed with encompasses the password salt for the user they supposedly
        // identify, so we need to retrieve that.
        let user = Self::by_id(id, connection).await?.validate_access_token(access_token)?;

        if let Some(csrf_token) = csrf_token {
            user.validate_csrf_token(csrf_token)?
        }

        Ok(user)
    }

    pub async fn oauth2_callback(code: &str, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        info!("We are expected to perform Google OAuth2 authentication");

        let client = reqwest::Client::new();

        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                (
                    "client_id",
                    std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set").as_str(),
                ),
                (
                    "client_secret",
                    std::env::var("GOOGLE_CLIENT_SECRET")
                        .expect("GOOGLE_CLIENT_SECRET not set")
                        .as_str(),
                ),
                (
                    "redirect_uri",
                    std::env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI not set").as_str(),
                ),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| CoreError::Unauthorized)?;

        // info!("Successfully fetched access token");
        // info!("Body: {:?}", response);

        // let text = response.text().await.map_err(|_| CoreError::Unauthorized)?;
        // info!("Text: {:?}", text);

        let response: GoogleTokenResponse = response.json().await.map_err(|_| CoreError::Unauthorized)?;

        info!("Successfully parsed access token {}", response.access_token);

        let key = DecodingKey::from_secret(&[]);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let user_info_token = jsonwebtoken::decode::<GoogleUserInfo>(&response.id_token, &key, &validation);

        if let Err(err) = user_info_token {
            info!("Failed to decode user info token: {:?}", err);
            return Err(UserError::Core(CoreError::Unauthorized));
        }

        let user_info = user_info_token.unwrap().claims;

        match User::by_google_account(&user_info.id, connection).await {
            Ok(user) => Ok(AuthenticatedUser {
                user,
                password_hash: None,
                google_account_id: Some(user_info.id),
                email_address: Some(user_info.email),
            }),
            Err(UserError::UserNotFoundGoogleAccount { .. }) => {
                let random_temporary_name = base64::encode(&user_info.name);

                let id = sqlx::query!(
                    "INSERT INTO members (email_address, name, display_name, google_account_id) VALUES (($1::text)::email, $2, $3, $4) RETURNING member_id",
                    user_info.email,
                    random_temporary_name,
                    user_info.name,
                    user_info.id
                )
                .fetch_one(connection)
                .await?
                .member_id;

                Ok(AuthenticatedUser {
                    user: User {
                        id,
                        name: random_temporary_name,
                        permissions: 0,
                        display_name: Some(user_info.name),
                        youtube_channel: None,
                    },
                    password_hash: None,
                    google_account_id: Some(user_info.id),
                    email_address: Some(user_info.email),
                })
            },
            Err(err) => Err(err),
        }
    }

    async fn by_id(id: i32, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        let row = sqlx::query!(
            r#"SELECT member_id, members.name, permissions::integer, display_name, youtube_channel::text, email_address::text, password_hash, google_account_id FROM members WHERE member_id = $1"#,
            id
        )
        .fetch_one(connection)
        .await;

        match row {
            Err(Error::RowNotFound) => Err(CoreError::Unauthorized.into()),
            Err(err) => Err(err.into()),
            Ok(row) => Ok(AuthenticatedUser {
                user: construct_from_row!(row),
                password_hash: row.password_hash,
                email_address: row.email_address,
                google_account_id: None,
            }),
        }
    }

    async fn by_google_account(id: &str, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        let row = sqlx::query!(
            r#"SELECT member_id, members.name, permissions::integer, display_name, youtube_channel::text, email_address::text, google_account_id FROM members WHERE google_account_id = $1"#,
            id
        )
        .fetch_one(connection)
        .await;

        match row {
            Err(Error::RowNotFound) => Err(CoreError::Unauthorized.into()),
            Err(err) => Err(err.into()),
            Ok(row) => Ok(AuthenticatedUser {
                user: construct_from_row!(row),
                password_hash: None,
                email_address: row.email_address,
                google_account_id: row.google_account_id,
            }),
        }
    }

    async fn by_name(name: &str, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        let row = sqlx::query!(
            r#"SELECT member_id, members.name, permissions::integer, display_name, youtube_channel::text, email_address::text, password_hash, google_account_id FROM members WHERE members.name = $1"#,
            name.to_string()
        )
        .fetch_one(connection)
        .await;

        match row {
            Err(Error::RowNotFound) => Err(CoreError::Unauthorized.into()),
            Err(err) => Err(err.into()),
            Ok(row) => Ok(AuthenticatedUser {
                user: construct_from_row!(row),
                password_hash: row.password_hash,
                email_address: row.email_address,
                google_account_id: None,
            }),
        }
    }
}
