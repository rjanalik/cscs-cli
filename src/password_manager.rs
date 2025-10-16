use serde::{Serialize, Serializer};
use std::fmt::{self, Debug, Formatter};

pub struct Credentials {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

impl Debug for Credentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"******")
            .field("totp", &"******")
            .finish()
    }
}

pub trait PasswordManager: Debug {
    fn get_credentials(&self, pass_service: String, username: String) -> anyhow::Result<Credentials>;
    fn to_str(&self) -> &str;
}

impl Serialize for dyn PasswordManager {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_str())
    }
}
