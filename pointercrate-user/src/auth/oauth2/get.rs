use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use log::info;
use pointercrate_core::config;
use pointercrate_core::error::CoreError;
use serde::Deserialize;
use sqlx::{Error, PgConnection};

use crate::auth::AuthenticatedUser;
use crate::error::UserError;
use crate::{Result, User};

#[derive(Deserialize)]
struct GoogleTokenResponse {
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
    pub async fn oauth2_callback(code: &str, existing_id: Option<i32>, connection: &mut PgConnection) -> Result<AuthenticatedUser> {
        info!("We are expected to perform Google OAuth2 authentication");

        let client = reqwest::Client::new();

        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", &config::google_client_id()),
                ("client_secret", &config::google_client_secret()),
                ("redirect_uri", &config::google_redirect_uri()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| CoreError::Unauthorized)?;

        let response: GoogleTokenResponse = response.json().await.map_err(|_| CoreError::Unauthorized)?;

        // We can safely disable all validation here, as Google recommends to not
        // validate a fresh token, as it is guaranteed to be valid.
        //
        // https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
        let key = DecodingKey::from_secret(&[]);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let user_info = jsonwebtoken::decode::<GoogleUserInfo>(&response.id_token, &key, &validation)
            .map_err(|_| CoreError::Unauthorized)?
            .claims;

        match User::by_google_account(&user_info.id, connection).await {
            Ok(user) => Ok(AuthenticatedUser::oauth2(user, user_info.email, user_info.id)),
            Err(UserError::UserNotFoundGoogleAccount { .. }) => {
                if let Some(id) = existing_id {
                    let user = Self::by_id(id, connection).await?;

                    if !user.is_legacy() {
                        return Err(CoreError::Unauthorized.into());
                    }

                    let updated_user = sqlx::query!(
                    "UPDATE members SET google_account_id = $1, email_address = ($2::text)::email WHERE member_id = $3 RETURNING member_id",
                    user_info.id,
                    user_info.email,
                    id
                )
                    .fetch_one(connection)
                    .await?;

                    if updated_user.member_id != id {
                        return Err(Error::RowNotFound.into());
                    }

                    Ok(Self::oauth2(User { id, ..user.into_user() }, user_info.id, user_info.email))
                } else {
                    // This will never conflict with an existing user
                    // According to Google, the account ID is always unique
                    // https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
                    let name = format!("{}#{}", user_info.name, user_info.id);

                    let id = sqlx::query!(
                        "INSERT INTO
                        members (email_address, name, display_name, google_account_id)
                    VALUES
                        (($1::text)::email, $2, $3, $4) RETURNING member_id
                    ",
                        user_info.email,
                        name,
                        user_info.name,
                        user_info.id
                    )
                    .fetch_one(connection)
                    .await?
                    .member_id;

                    Ok(Self::oauth2(
                        User {
                            id,
                            name,
                            permissions: 0,
                            display_name: Some(user_info.name),
                            youtube_channel: None,
                        },
                        user_info.id,
                        user_info.email,
                    ))
                }
            },
            Err(err) => Err(err),
        }
    }
}
