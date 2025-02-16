use oauth2::{basic::BasicClient, CsrfToken};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    #[serde(flatten)]
    pub success: Option<AuthSuccessParams>,
    #[serde(flatten)]
    pub error: Option<AuthErrorParams>,
}

#[derive(Debug, Deserialize)]
pub struct AuthErrorParams {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthSuccessParams {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub state_token: CsrfToken,
    pub client: BasicClient,
    pub tx: broadcast::Sender<Option<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserInfo {
    pub email: String,
    pub name: String,
    pub sub: String,
}
