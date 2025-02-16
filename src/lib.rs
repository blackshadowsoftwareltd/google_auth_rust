// use oauth2::{basic::BasicClient, TokenResponse};
// use oauth2::{
//     AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
//     Scope, TokenUrl,
// };
// use std::io::{BufRead, BufReader, Write};
// use std::net::TcpListener;
// use url::Url;

// pub fn google_auth_rust(client_id: String, client_secret: String) {
//     let google_client_id = ClientId::new(client_id);
//     let google_client_secret = ClientSecret::new(client_secret);

//     let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
//         .expect("Invalid authorization endpoint URL");
//     let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
//         .expect("Invalid token endpoint URL");

//     // Set up the config for the Google OAuth2 process.
//     let client = BasicClient::new(google_client_id)
//         .set_client_secret(google_client_secret)
//         .set_auth_uri(auth_url)
//         .set_token_uri(token_url)
//         // This example will be running its own server at localhost:8080.
//         // See below for the server implementation.
//         .set_redirect_uri(
//             RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect URL"),
//         );

//     // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
//     // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
//     let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

//     // Generate the authorization URL to which we'll redirect the user.
//     let (authorize_url, csrf_state) = client
//         .authorize_url(CsrfToken::new_random)
//         // This example is requesting access to the user's profile.
//         .add_scope(Scope::new(
//             "https://www.googleapis.com/auth/userinfo.profile".to_string(),
//         ))
//         .set_pkce_challenge(pkce_code_challenge)
//         .url();

//     println!("Open this URL in your browser:\n{authorize_url}\n");

//     let (code, state) = {
//         // A very naive implementation of the redirect server.
//         let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

//         // The server will terminate itself after collecting the first code.
//         let Some(mut stream) = listener.incoming().flatten().next() else {
//             panic!("listener terminated without accepting a connection");
//         };

//         let mut reader = BufReader::new(&stream);

//         let mut request_line = String::new();
//         reader.read_line(&mut request_line).unwrap();

//         let redirect_url = request_line.split_whitespace().nth(1).unwrap();
//         let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

//         let code = url
//             .query_pairs()
//             .find(|(key, _)| key == "code")
//             .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
//             .unwrap();

//         let state = url
//             .query_pairs()
//             .find(|(key, _)| key == "state")
//             .map(|(_, state)| CsrfToken::new(state.into_owned()))
//             .unwrap();

//         let message = "Go back to your terminal :)";
//         let response = format!(
//             "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
//             message.len(),
//             message
//         );
//         stream.write_all(response.as_bytes()).unwrap();

//         (code, state)
//     };

//     println!("Google returned the following code:\n{}\n", code.secret());
//     println!(
//         "Google returned the following state:\n{} (expected `{}`)\n",
//         state.secret(),
//         csrf_state.secret()
//     );

//     // Define a custom HTTP client function
//     // let custom_http_client = |request: oauth2::http::Request<Vec<u8>>| {
//     //     let client = reqwest::blocking::Client::new();
//     //     let response = client
//     //         .execute(
//     //             reqwest::blocking::Request::try_from(request).expect("Failed to convert request"),
//     //         )
//     //         .expect("Failed to execute request");

//     //     let status = response.status();
//     //     let headers = response.headers().clone();
//     //     let body = response
//     //         .bytes()
//     //         .expect("Failed to read response body")
//     //         .to_vec();

//     //     oauth2::http::Response::builder()
//     //         .status(status)
//     //         .headers(headers)
//     //         .body(body)
//     //         .expect("Failed to build response")
//     // };

//     // // Exchange the code with a token.
//     // let token_response = client
//     //     .exchange_code(code)
//     //     .set_pkce_verifier(pkce_code_verifier)
//     //     .request(custom_http_client) // Use the custom HTTP client function
//     //     .expect("Failed to exchange code for token");

//     // println!("Google returned the following token:\n{token_response:?}\n");
// }
