use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::InboundError;

/// The only version this speaks.
const VERSION: u8 = 5;

/// Username and password, RFC 1929.
const AUTH_LOGIN: u8 = 2;

/// Nothing this listener will agree to.
const AUTH_NONE_ACCEPTABLE: u8 = 0xFF;

/// What the client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Where it wants to go, as it named it.
    pub host: String,
    /// The port it wants.
    pub port: u16,
}

/// Reads the greeting and settles on username and password.
///
/// No other method is offered, including none at all. A listener that would
/// accept an unauthenticated client is an open proxy, and an open proxy is in
/// every scanner's list within a day.
pub async fn negotiate<S>(stream: &mut S) -> Result<(), InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(InboundError::Protocol("socks5"));
    }

    let mut offered = vec![0u8; head[1] as usize];
    stream.read_exact(&mut offered).await?;
    if !offered.contains(&AUTH_LOGIN) {
        stream.write_all(&[VERSION, AUTH_NONE_ACCEPTABLE]).await?;
        return Err(InboundError::Protocol("socks5"));
    }

    stream.write_all(&[VERSION, AUTH_LOGIN]).await?;
    Ok(())
}

/// Reads the name and password the client offers.
pub async fn credentials<S>(stream: &mut S) -> Result<(String, String), InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != 1 {
        return Err(InboundError::Protocol("socks5 auth"));
    }

    let mut length = [0u8; 1];
    stream.read_exact(&mut length).await?;
    let mut user = vec![0u8; length[0] as usize];
    stream.read_exact(&mut user).await?;

    stream.read_exact(&mut length).await?;
    let mut pass = vec![0u8; length[0] as usize];
    stream.read_exact(&mut pass).await?;

    Ok((
        String::from_utf8_lossy(&user).into_owned(),
        String::from_utf8_lossy(&pass).into_owned(),
    ))
}

/// Tells the client whether its credentials were accepted.
///
/// A refusal is spoken in the protocol rather than by hanging up: a client
/// that is told no can say so to the person using it, and a connection that
/// simply drops looks like a network fault they will spend an evening on.
pub async fn answer_credentials<S>(stream: &mut S, admitted: bool) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[1, if admitted { 0 } else { 1 }]).await?;
    Ok(())
}

/// Reads where the client wants to go.
pub async fn request<S>(stream: &mut S) -> Result<Request, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(InboundError::Protocol("socks5"));
    }
    // Only CONNECT. Binding and associating a port on this node would make it
    // reachable in ways the node's own configuration never described.
    if head[1] != 1 {
        answer_request(stream, 7).await?;
        return Err(InboundError::Protocol("socks5 command"));
    }

    let host = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0u8; length[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            answer_request(stream, 8).await?;
            return Err(InboundError::Protocol("socks5 address"));
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Request {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Tells the client how its request went.
///
/// The bound address is reported as zero. A client has no use for it on a
/// CONNECT, and the node's own addresses are not something to hand out.
pub async fn answer_request<S>(stream: &mut S, code: u8) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pipe() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(4096)
    }

    #[tokio::test]
    async fn a_client_offering_a_password_is_told_to_use_one() {
        let (mut client, mut server) = pipe().await;
        let served = tokio::spawn(async move { negotiate(&mut server).await });

        client.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();

        assert_eq!(answer, [5, AUTH_LOGIN]);
        assert!(served.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn a_client_offering_only_no_authentication_is_turned_away() {
        let (mut client, mut server) = pipe().await;
        let served = tokio::spawn(async move { negotiate(&mut server).await });

        // Method zero is "no authentication required".
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();

        assert_eq!(answer, [5, AUTH_NONE_ACCEPTABLE]);
        assert!(served.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn something_that_is_not_socks_is_refused() {
        let (mut client, mut server) = pipe().await;
        let served = tokio::spawn(async move { negotiate(&mut server).await });
        client.write_all(b"GE").await.unwrap();
        drop(client);
        assert!(served.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_name_and_password_come_back_as_given() {
        let (mut client, mut server) = pipe().await;
        let served = tokio::spawn(async move { credentials(&mut server).await });

        client.write_all(&[1, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"opens!").await.unwrap();

        let (user, pass) = served.await.unwrap().unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "opens!");
    }

    #[tokio::test]
    async fn a_refusal_is_spoken_rather_than_hung_up() {
        let (mut client, mut server) = pipe().await;
        answer_credentials(&mut server, false).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [1, 1]);
    }

    #[tokio::test]
    async fn a_request_names_where_it_wants_to_go() {
        for (bytes, expected) in [
            (
                vec![5u8, 1, 0, 1, 203, 0, 113, 7, 0x01, 0xBB],
                Request {
                    host: "203.0.113.7".to_owned(),
                    port: 443,
                },
            ),
            (
                {
                    let mut request = vec![5u8, 1, 0, 3, 5];
                    request.extend_from_slice(b"ya.ru");
                    request.extend_from_slice(&[0x01, 0xBB]);
                    request
                },
                Request {
                    host: "ya.ru".to_owned(),
                    port: 443,
                },
            ),
        ] {
            let (mut client, mut server) = pipe().await;
            let served = tokio::spawn(async move { request(&mut server).await });
            client.write_all(&bytes).await.unwrap();
            assert_eq!(served.await.unwrap().unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn a_command_other_than_connect_is_refused_in_the_protocol() {
        let (mut client, mut server) = pipe().await;
        let served = tokio::spawn(async move { request(&mut server).await });

        // Two is BIND: it would have this node listen on a port nobody
        // configured it to listen on.
        client
            .write_all(&[5, 2, 0, 1, 203, 0, 113, 7, 0x01, 0xBB])
            .await
            .unwrap();
        let mut answer = [0u8; 10];
        client.read_exact(&mut answer).await.unwrap();

        assert_eq!(answer[0], 5);
        assert_eq!(
            answer[1], 7,
            "the client was not told the command is refused"
        );
        assert!(served.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn the_answer_does_not_carry_an_address_of_ours() {
        let (mut client, mut server) = pipe().await;
        answer_request(&mut server, 0).await.unwrap();
        let mut answer = [0u8; 10];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer[4..10], &[0, 0, 0, 0, 0, 0]);
    }
}
