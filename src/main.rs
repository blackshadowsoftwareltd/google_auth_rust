use anyhow::Result;
use google_auth_rust::auth::get_oauth_token;

use dotenv::dotenv;
const CLIENT_ID_ENV_KEY: &str = "GOOGLE_OAUTH_CLIENT_ID";
const CLIENT_SECRET_ENV_KEY: &str = "GOOGLE_OAUTH_CLIENT_SECRET";

fn main() -> Result<()> {
    dotenv().ok();
    let client_id = std::env::var(CLIENT_ID_ENV_KEY)?;
    let client_secret = std::env::var(CLIENT_SECRET_ENV_KEY)?;
    const HOST_URL: &str = "localhost:3000";
    const REDIRECT_ROUTE: &str = "/auth/google_callback";

    let redirect_url = format!("http://{}{}", HOST_URL, REDIRECT_ROUTE); // http://localhost:3000/auth/google_callback (this url is set in google cloude console)
    let token = get_oauth_token(&client_id, &client_secret, &redirect_url)?;
    println!("YOUR TOKEN: {:?}", token);
    Ok(())
}
