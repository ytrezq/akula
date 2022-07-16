use akula::akula_tracing::{self, Component};
use axum::{
    body::{boxed, Full},
    handler::Handler,
    http::{header, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, Router},
};
use clap::Parser;
use rust_embed::RustEmbed;
use std::{marker::PhantomData, net::SocketAddr};
use tracing::*;
use tracing_subscriber::prelude::*;

#[derive(Parser)]
#[clap(
    name = "Otterscan",
    about = "Local, fast and privacy-friendly block explorer."
)]
pub struct Opt {
    #[clap(long, default_value = "127.0.0.1:3000")]
    pub listen_address: SocketAddr,

    #[clap(long, default_value = "http://localhost:8545")]
    pub rpc_url: String,
}

#[tokio::main]
async fn main() {
    let opt: Opt = Opt::parse();
    akula_tracing::build_subscriber(Component::Otterscan).init();

    // Define our app routes, including a fallback option for anything not matched.
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/index.html", get(index_handler))
        .route(
            "/config.json",
            get({
                let rpc_url = opt.rpc_url;
                move || async move {
                    serde_json::json!({
                        "erigonURL": rpc_url,
                        "assetsURLPrefix": "http://localhost:3000",
                    })
                    .to_string()
                }
            }),
        )
        .route("/block/*file", get(index_handler))
        .route("/address/*file", get(index_handler))
        .route("/static/*file", static_handler::<Asset>.into_service())
        .route("/chains/*file", static_handler::<Chains>.into_service())
        .route("/manifest.json", static_handler::<Asset>.into_service())
        .route("/favicon.ico", static_handler::<Asset>.into_service())
        .fallback(get(not_found));

    // Start listening on the given address.
    info!("Otterscan running at http://{}", opt.listen_address);
    axum::Server::bind(&opt.listen_address)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// We use static route matchers ("/" and "/index.html") to serve our home
// page.
async fn index_handler() -> impl IntoResponse {
    static_handler::<Asset>("/index.html".parse::<Uri>().unwrap()).await
}

// We use a wildcard matcher ("/static/*file") to match against everything
// within our defined assets directory. This is the directory on our Asset
// struct below, where folder = "examples/public/".
async fn static_handler<A: RustEmbed>(uri: Uri) -> impl IntoResponse {
    StaticFile::<A, _>::new(uri.path().trim_start_matches('/').to_string())
}

// Finally, we use a fallback route for anything that didn't match.
async fn not_found() -> Html<&'static str> {
    Html("<h1>404</h1><p>Not Found</p>")
}

#[derive(RustEmbed)]
#[folder = "src/otterscan/build"]
struct Asset;

#[derive(RustEmbed)]
#[folder = "src/otterscan/chains/_data"]
struct Chains;

pub struct StaticFile<A, T> {
    path: T,
    _marker: PhantomData<A>,
}

impl<A, T> StaticFile<A, T> {
    pub fn new(path: T) -> Self {
        Self {
            path,
            _marker: PhantomData,
        }
    }
}

impl<A, T> IntoResponse for StaticFile<A, T>
where
    A: RustEmbed,
    T: Into<String>,
{
    fn into_response(self) -> Response {
        let path = self.path.into();

        match A::get(path.as_str()) {
            Some(content) => {
                let body = boxed(Full::from(content.data));
                let mime = mime_guess::from_path(path).first_or_octet_stream();
                Response::builder()
                    .header(header::CONTENT_TYPE, mime.as_ref())
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .body(body)
                    .unwrap()
            }
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(boxed(Full::from("404")))
                .unwrap(),
        }
    }
}
