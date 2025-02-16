use anyhow::Result;
use google_auth_rust::auth::get_oauth_token;

fn main() -> Result<()> {
    let token = get_oauth_token();
    println!("YOUR TOKEN: {:?}", token);
    Ok(())
}
