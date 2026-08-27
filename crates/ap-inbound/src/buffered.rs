//! A stream that can be read a head at a time without over-reading.
//!
//! A request head ends at a blank line and the body begins immediately after
//! it, so a reader that takes more than the head has to give the remainder
//! back. Reading one byte at a time avoids that and costs a system call per
//! byte; a head carrying a few kilobytes of cookies is thousands of them.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::InboundError;

/// How much is taken from the stream at a time while looking for the end of a
/// head.
const CHUNK: usize = 8 * 1024;

/// A stream with whatever was read past the last head still in hand.
pub struct Buffered<S> {
    inner: S,
    held: Vec<u8>,
    at: usize,
}

impl<S> Buffered<S> {
    /// Wraps a stream, holding nothing yet.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            held: Vec::new(),
            at: 0,
        }
    }

    /// What has been read from the stream but not yet handed on.
    fn waiting(&self) -> &[u8] {
        &self.held[self.at..]
    }
}

impl<S: AsyncRead + Unpin> Buffered<S> {
    /// Reads up to and including the blank line that ends a head.
    ///
    /// Anything read past it stays here and is handed on by the ordinary
    /// reads that follow, so the body of the message is never lost.
    pub async fn head(&mut self, ceiling: usize) -> Result<Vec<u8>, InboundError> {
        loop {
            if let Some(end) = find_blank_line(self.waiting()) {
                let head = self.waiting()[..end].to_vec();
                self.at += end;
                return Ok(head);
            }
            if self.waiting().len() >= ceiling {
                return Err(InboundError::TooLarge);
            }

            // What has already been handed on is dropped, so a long
            // conversation does not grow this without bound.
            if self.at > 0 {
                self.held.drain(..self.at);
                self.at = 0;
            }
            let was = self.held.len();
            self.held.resize(was + CHUNK, 0);
            let read = self.inner.read(&mut self.held[was..]).await?;
            self.held.truncate(was + read);
            if read == 0 {
                return Err(InboundError::Protocol("http"));
            }
        }
    }
}

/// Where a head ends, counted from the start of what is held.
fn find_blank_line(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|four| four == b"\r\n\r\n")
        .map(|at| at + 4)
}

impl<S: AsyncRead + Unpin> AsyncRead for Buffered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        into: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let held = self.held.len() - self.at;
        if held > 0 {
            let take = held.min(into.remaining());
            let at = self.at;
            let piece = self.held[at..at + take].to_vec();
            into.put_slice(&piece);
            self.at += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, into)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Buffered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn holding(bytes: &'static [u8]) -> Buffered<tokio::io::DuplexStream> {
        let (mut writing, reading) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = writing.write_all(bytes).await;
        });
        Buffered::new(reading)
    }

    #[tokio::test]
    async fn a_head_ends_at_the_blank_line() {
        let mut stream = holding(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody here").await;
        let head = stream.head(8 * 1024).await.unwrap();
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[tokio::test]
    async fn what_followed_the_head_is_still_there_to_read() {
        // The body begins where the head stops. A reader that swallowed it
        // would pass on a request with nothing in it.
        let mut stream = holding(b"POST /api HTTP/1.1\r\nContent-Length: 9\r\n\r\nnine here").await;
        let _ = stream.head(8 * 1024).await.unwrap();

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"nine here");
    }

    #[tokio::test]
    async fn two_heads_come_out_of_one_stream_in_order() {
        let mut stream = holding(b"GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            stream.head(8 * 1024).await.unwrap(),
            b"GET /one HTTP/1.1\r\n\r\n"
        );
        assert_eq!(
            stream.head(8 * 1024).await.unwrap(),
            b"GET /two HTTP/1.1\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn a_head_past_the_ceiling_is_refused_as_such() {
        let mut stream =
            holding(b"GET / HTTP/1.1\r\nCookie: aaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n").await;
        assert!(matches!(stream.head(32).await, Err(InboundError::TooLarge)));
    }

    #[tokio::test]
    async fn a_stream_that_ends_before_a_head_does_is_refused() {
        let mut stream = holding(b"GET / HTTP/1.1\r\nHost: x\r\n").await;
        assert!(stream.head(8 * 1024).await.is_err());
    }
}
