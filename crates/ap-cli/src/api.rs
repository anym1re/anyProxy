use std::path::{Path, PathBuf};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};

/// What the panel said, and what it meant.
#[derive(Debug, Clone)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Body, as it arrived.
    pub body: String,
}

impl Reply {
    /// Whether the panel did what was asked.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as JSON, or null when it is not.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// The machine-readable reason a request was refused.
    ///
    /// The panel's own wording is never printed: it is written in whichever
    /// language the panel runs in, and the person reading it chose another.
    /// What travels is the code, which the catalogue turns into a sentence.
    pub fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned()
    }
}

/// Talks to one panel.
#[derive(Debug, Clone)]
pub struct Api {
    base: String,
    token: Option<String>,
}

impl Api {
    /// Points at a panel, with a token if one has been kept.
    pub fn new(base: impl Into<String>, token: Option<String>) -> Self {
        Self {
            base: into_base(base.into()),
            token,
        }
    }

    /// Reads something.
    pub async fn get(&self, path: &str) -> Result<Reply, String> {
        self.send(Method::GET, path, None).await
    }

    /// Asks for something to be done.
    pub async fn post(&self, path: &str, body: serde_json::Value) -> Result<Reply, String> {
        self.send(Method::POST, path, Some(body.to_string())).await
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
    ) -> Result<Reply, String> {
        let address = self.address()?;
        let stream = tokio::net::TcpStream::connect(&address)
            .await
            .map_err(|error| format!("{address}: {error}"))?;
        let io = hyper_util::rt::TokioIo::new(stream);

        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| error.to_string())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", address.clone());
        if let Some(token) = &self.token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|error| error.to_string())?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|error| error.to_string())?
            .to_bytes();

        Ok(Reply {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }

    /// The host and port to open a socket to.
    pub(crate) fn address(&self) -> Result<String, String> {
        let rest = self
            .base
            .strip_prefix("http://")
            .ok_or_else(|| format!("{} is not an http address", self.base))?;
        Ok(rest.trim_end_matches('/').to_owned())
    }
}

/// Normalises what an operator typed into a base address.
fn into_base(given: String) -> String {
    let trimmed = given.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_owned()
    } else {
        format!("http://{trimmed}")
    }
}

/// Where the token is kept between commands.
pub fn token_path() -> PathBuf {
    if let Ok(given) = std::env::var("ANYPROXY_TOKEN_FILE") {
        return PathBuf::from(given);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home)
        .join(".config")
        .join("anyproxy")
        .join("token")
}

/// Reads the token, refusing one anyone else could have read.
///
/// A token is a live session. A file the group or the world can read is a
/// session handed to whoever is on the machine, so it is refused rather than
/// used with a warning.
pub fn read_token(path: &Path) -> Result<Option<String>, String> {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(format!("{} is readable beyond its owner", path.display()));
                }
            }
            #[cfg(not(unix))]
            let _ = &metadata;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }

    let token =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let token = token.trim().to_owned();
    Ok((!token.is_empty()).then_some(token))
}

/// Writes the token, readable by its owner and nobody else.
pub fn write_token(path: &Path, token: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let staged = path.with_file_name(format!(
        ".{}.new",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "token".to_owned())
    ));

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&staged)
            .map_err(|error| format!("{}: {error}", staged.display()))?;
        file.write_all(token.as_bytes())
            .map_err(|error| format!("{}: {error}", staged.display()))?;
        drop(file);
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o400))
            .map_err(|error| format!("{}: {error}", staged.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&staged, token).map_err(|error| format!("{}: {error}", staged.display()))?;

    std::fs::rename(&staged, path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Forgets the token.
pub fn forget_token(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("anyproxy-cli-token");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}-{}", uuid::Uuid::now_v7().simple()))
    }

    #[test]
    fn an_address_without_a_scheme_gets_one() {
        for given in [
            "127.0.0.1:8080",
            "http://127.0.0.1:8080",
            "  127.0.0.1:8080  ",
        ] {
            assert_eq!(
                Api::new(given, None).address().unwrap(),
                "127.0.0.1:8080",
                "{given}"
            );
        }
        assert_eq!(
            Api::new("http://panel.example.com/", None)
                .address()
                .unwrap(),
            "panel.example.com"
        );
    }

    #[test]
    fn a_token_survives_a_round_trip() {
        let path = a_path("round-trip");
        write_token(&path, "opaque").unwrap();
        assert_eq!(read_token(&path).unwrap().as_deref(), Some("opaque"));
    }

    #[test]
    fn no_token_reads_as_no_token() {
        assert_eq!(read_token(&a_path("absent")).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_token_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let path = a_path("exposed");
        write_token(&path, "opaque").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        let outcome = read_token(&path);
        assert!(outcome.is_err(), "a world-readable token was used");
    }

    #[cfg(unix)]
    #[test]
    fn a_token_is_written_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;

        let path = a_path("mode");
        write_token(&path, "opaque").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400);
    }

    #[cfg(unix)]
    #[test]
    fn a_token_can_be_written_over_one_that_is_already_there() {
        let path = a_path("rewrite");
        write_token(&path, "first").unwrap();
        write_token(&path, "second").unwrap();
        assert_eq!(read_token(&path).unwrap().as_deref(), Some("second"));
    }

    #[test]
    fn forgetting_a_token_that_is_not_there_is_not_a_failure() {
        assert!(forget_token(&a_path("never-was")).is_ok());
    }

    #[test]
    fn a_refusal_carries_its_code_and_not_the_panels_wording() {
        let reply = Reply {
            status: 404,
            body: r#"{"error":{"code":"not_found","message":"не найдено"}}"#.to_owned(),
        };
        assert_eq!(reply.code(), "not_found");
        assert!(!reply.ok());
    }

    #[test]
    fn a_body_that_is_not_an_error_gives_an_unknown_code() {
        let reply = Reply {
            status: 502,
            body: "<html>gateway</html>".to_owned(),
        };
        assert_eq!(reply.code(), "unknown");
    }
}
