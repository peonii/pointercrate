use crate::User;

use super::AuthenticatedUser;

pub struct OAuth2AuthenticatedUser {
    user: User,
    email_address: String,
    pub google_account_id: String,
}

pub mod get;

impl OAuth2AuthenticatedUser {
    pub fn into_user(self) -> User {
        self.user
    }

    pub fn user(&self) -> &User {
        &self.user
    }

    pub fn email_address(&self) -> &str {
        &self.email_address
    }

    pub fn is_google_linked(&self) -> bool {
        true
    }
}

impl AuthenticatedUser {
    pub fn oauth2(user: User, email_address: String, google_account_id: String) -> Self {
        AuthenticatedUser::OAuth2(OAuth2AuthenticatedUser {
            user,
            email_address,
            google_account_id,
        })
    }
}
