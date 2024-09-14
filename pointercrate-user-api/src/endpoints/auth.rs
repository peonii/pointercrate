use crate::{
    auth::{BasicAuth, TokenAuth},
    ratelimits::UserRatelimits,
};
use pointercrate_core::{error::CoreError, etag::Taggable, pool::PointercratePool};
use pointercrate_core_api::{
    error::Result,
    etag::{Precondition, Tagged},
    response::Response2,
};
use pointercrate_user::{auth::AuthenticatedUser, auth::PatchMe, error::UserError, User};
use rocket::{
    http::{Cookie, CookieJar, SameSite, Status},
    serde::json::{serde_json, Json},
    State,
};
use std::net::IpAddr;

#[cfg(feature = "oauth2")]
#[rocket::get("/authorize?<legacy>")]
pub async fn authorize(
    ip: IpAddr, ratelimits: &State<UserRatelimits>, legacy: Option<&str>, cookies: &CookieJar<'_>,
) -> Result<Response2<()>> {
    ratelimits.login_attempts(ip)?;

    if legacy.is_some() {
        let legacy_cookie = Cookie::build(("legacy", "true"))
            .http_only(true)
            .same_site(SameSite::Strict)
            .path("/");

        cookies.add(legacy_cookie);
    }

    let redirect_uri = "https://accounts.google.com/o/oauth2/v2/auth".to_string()
        + format!("?client_id={}", std::env::var("GOOGLE_CLIENT_ID").unwrap()).as_str()
        + "&response_type=code"
        + "&prompt=consent"
        + "&scope=email%20profile"
        + "&redirect_uri=http%3A%2F%2Flocalhost%3A1971%2Fapi%2Fv1%2Fauth%2Fcallback";

    Ok(Response2::new(())
        .with_header("Location", redirect_uri)
        .status(Status::TemporaryRedirect))
}

#[cfg(feature = "oauth2")]
#[rocket::get("/callback?<code>")]
pub async fn callback(
    auth: std::result::Result<TokenAuth, UserError>, pool: &State<PointercratePool>, ip: IpAddr, ratelimits: &State<UserRatelimits>,
    code: &str, cookies: &CookieJar<'_>,
) -> Result<Response2<()>> {
    ratelimits.login_attempts(ip)?;
    let mut connection = pool.transaction().await.map_err(UserError::from)?;

    let mut existing_id: Option<i32> = None;

    if cookies.get("legacy").is_some() {
        if auth.is_err() {
            return Err(UserError::Core(CoreError::Unauthorized).into());
        }

        let user = auth?.user;

        if user.google_account_id.is_some() {
            return Err(UserError::AlreadyLinked.into());
        }

        existing_id = Some(user.inner().id);

        cookies.remove("legacy");
    }

    let user = AuthenticatedUser::oauth2_callback(code, existing_id, &mut *connection).await?;

    connection.commit().await.map_err(UserError::from)?;

    let mut cookie = Cookie::build(("access_token", user.generate_access_token()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/");

    if !cfg!(debug_assertions) {
        cookie = cookie.secure(true)
    }

    cookies.add(cookie);

    Ok(Response2::new(()).with_header("Location", "/").status(Status::TemporaryRedirect))
}

#[cfg(feature = "legacy_accounts")]
#[rocket::post("/register", data = "<body>")]
pub async fn register(
    ip: IpAddr, body: Json<Registration>, ratelimits: &State<UserRatelimits>, pool: &State<PointercratePool>,
) -> Result<Response2<Tagged<User>>> {
    #[cfg(feature = "legacy_accounts")]
    use {
        pointercrate_core::pool::PointercratePool,
        pointercrate_user::auth::legacy::{LegacyAuthenticatedUser, Registration},
    };

    LegacyAuthenticatedUser::validate_password(&body.password)?;
    User::validate_name(&body.name)?;

    Ok(Response2::tagged(user.into_user())
        .with_header("Location", "api/v1/auth/me")
        .status(Status::Created))
}

#[rocket::post("/")]
pub async fn login(
    auth: std::result::Result<BasicAuth, UserError>, ip: IpAddr, ratelimits: &State<UserRatelimits>,
) -> Result<Response2<Json<serde_json::Value>>> {
    ratelimits.login_attempts(ip)?;
    let auth = auth?;

    Ok(Response2::json(serde_json::json! {
        {
            "data": auth.user.user(),
            "token": auth.user.generate_access_token()
        }
    })
    .with_header("etag", auth.user.user().etag_string()))
}

#[rocket::post("/invalidate")]
pub async fn invalidate(mut auth: BasicAuth) -> Result<Status> {
    match auth.user {
        AuthenticatedUser::Legacy(legacy) => legacy.invalidate_all_tokens(auth.secret, &mut auth.connection).await?,
        AuthenticatedUser::OAuth2(oauth) => todo!(), // I have no clue what we'll do here
    }

    auth.connection.commit().await.map_err(UserError::from)?;

    Ok(Status::NoContent)
}

#[rocket::get("/me")]
pub fn get_me(auth: TokenAuth) -> Tagged<User> {
    Tagged(auth.user.into_user())
}

#[rocket::patch("/me", data = "<patch>")]
pub async fn patch_me(mut auth: BasicAuth, patch: Json<PatchMe>, pred: Precondition) -> Result<std::result::Result<Tagged<User>, Status>> {
    pred.require_etag_match(auth.user.user())?;

    let changes_password = patch.changes_password();

    let updated_user = auth.user.apply_patch(patch.0, &mut auth.connection).await?;

    auth.connection.commit().await.map_err(UserError::from)?;

    if changes_password {
        Ok(Err(Status::NotModified))
    } else {
        Ok(Ok(Tagged(updated_user)))
    }
}

#[rocket::delete("/me")]
pub async fn delete_me(mut auth: BasicAuth, pred: Precondition) -> Result<Status> {
    pred.require_etag_match(auth.user.user())?;

    auth.user.delete(&mut auth.connection).await?;
    auth.connection.commit().await.map_err(UserError::from)?;

    Ok(Status::NoContent)
}
