use crate::models::{AppState, CallbackParams};
use anyhow::Result;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use tokio::{
    runtime::Runtime,
    sync::{broadcast, oneshot},
};
use url::Url;

const CLIENT_ID_ENV_KEY: &str = "GOOGLE_OAUTH_CLIENT_ID";
const CLIENT_SECRET_ENV_KEY: &str = "GOOGLE_OAUTH_CLIENT_SECRET";
const BASE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
const HOST_URL: &str = "localhost:3000";
const REDIRECT_ROUTE: &str = "/auth/google_callback";

pub fn get_oauth_token() -> Result<String> {
    dotenv().ok();
    let client_id = std::env::var(CLIENT_ID_ENV_KEY)?;
    let client_secret = std::env::var(CLIENT_SECRET_ENV_KEY)?;
    let redirect_url = format!("http://{}{}", HOST_URL, REDIRECT_ROUTE); // http://localhost:3000/auth/google_callback (this url is set in google cloude console)
    let scopes = vec!["openid", "email", "profile"];
    let client = build_auth_client(&client_id, &client_secret, &redirect_url)?;
    let (auth_url, csrf_token) = get_auth_url(&client, scopes);
    // println!("CSRF token : {:?}", csrf_token.secret());
    println!("Open this URL in your browser: {}", auth_url);
    webbrowser::open(&auth_url.as_str()).expect("Failed to open browser");
    run_local_server(csrf_token, client)
}

fn build_auth_client(
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<BasicClient> {
    let client = BasicClient::new(
        ClientId::new(client_id.to_owned()),
        Some(ClientSecret::new(client_secret.to_owned())),
        AuthUrl::new(BASE_AUTH_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_owned())?);

    Ok(client)
}

fn get_auth_url(basic_client: &BasicClient, scopes: Vec<&str>) -> (Url, CsrfToken) {
    let scopes: Vec<Scope> = scopes
        .into_iter()
        .map(|s| Scope::new(s.to_owned()))
        .collect();
    let (auth_url, csrf_token) = basic_client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes)
        .add_extra_param("access_type", "offline")
        .url();
    (auth_url, csrf_token)
}

fn run_local_server(csrf_token: CsrfToken, client: BasicClient) -> Result<String> {
    let (tx, mut rx) = broadcast::channel::<Option<String>>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (token_tx, token_rx) = oneshot::channel();

    let app = Router::new()
        .route(REDIRECT_ROUTE, get(handle_google_callback))
        .with_state(AppState {
            state_token: csrf_token,
            client,
            tx: tx.clone(),
        });

    Runtime::new().unwrap().block_on(async {
        let listener = tokio::net::TcpListener::bind(HOST_URL).await.unwrap();
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });

        std::thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                tokio::select! {
                    token_msg = rx.recv() => {
                        match token_msg {
                            Ok(token) => {
                                let _ = token_tx.send(token);
                            }
                            Err(_) => {
                                let _ = token_tx.send(None);
                            }
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(120)) => {
                        eprintln!("Timeout: user did not authorize within 120s.");
                        let _ = token_tx.send(None);
                    }
                }
                let _ = shutdown_tx.send(());
            });
        });
        let _ = server.await?;
        let token = token_rx.await?;
        match token {
            Some(t) => Ok(t),
            None => Err(anyhow::anyhow!("No token received (timed out or error)")),
        }
    })
}

async fn handle_google_callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let tx = state.tx.clone();
    if let Some(params) = params.error {
        tx.send(None).unwrap();
        return Response::new(params.error.to_owned()).into_response();
    }
    if params.success.is_none() {
        tx.send(None).unwrap();
        return Response::new("Unknwon".to_owned()).into_response();
    }
    let params = params.success.unwrap();
    if state.state_token.secret().to_owned() != params.state {
        tx.send(None).unwrap();
        return Response::new("Bad state".to_owned()).into_response();
    }
    match state
        .client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(async_http_client)
        .await
    {
        Ok(token) => {
            tx.send(Some(token.access_token().secret().to_string()))
                .unwrap();
            token
        }
        Err(error) => return Response::new(error.to_string()).into_response(),
    };

    // println!("token data: {:?}", token);
    // let info = get_profile(&token.access_token().secret()).await.unwrap();
    // println!("token: {:?}", token.access_token().secret());
    // println!("info: {:?}", info);
    return Response::new("Login success".into());
}

// async fn get_profile(access_token: &str) -> Result<UserInfo> {
//     let client = reqwest::Client::new();
//     let response = client
//         .get("https://openidconnect.googleapis.com/v1/userinfo")
//         .bearer_auth(access_token.to_owned())
//         .send()
//         .await?;
//     let user_info = response.json::<UserInfo>().await?;
//     println!("user info: {:?}", user_info);
//     Ok(user_info)
// }
