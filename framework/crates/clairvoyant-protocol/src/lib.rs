use async_trait::async_trait;
use clairvoyant_core::{
    decode_frame, encode_frame, ClairvoyantEnvelope, ClairvoyantErrorBody, ClairvoyantRequest,
    ClairvoyantResponse, FrameError, MAX_FRAME_BYTES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("server returned error {status}: {message}")]
    Server {
        status: u16,
        message: String,
        retry_after_ms: Option<u64>,
    },
    #[error("connection closed before response")]
    Closed,
}

impl From<ClairvoyantErrorBody> for ProtocolError {
    fn from(error: ClairvoyantErrorBody) -> Self {
        Self::Server {
            status: error.status,
            message: error.message,
            retry_after_ms: error.retry_after_ms,
        }
    }
}

pub async fn read_value<R, T>(reader: &mut R) -> Result<Option<T>, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0_u8; 4];
    let first_byte_count = reader.read(&mut len_buf[..1]).await?;
    if first_byte_count == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut len_buf[1..]).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len).into());
    }
    let mut frame = vec![0_u8; 4 + len];
    frame[..4].copy_from_slice(&len_buf);
    reader.read_exact(&mut frame[4..]).await?;
    Ok(Some(decode_frame(&frame)?))
}

pub async fn write_value<W, T>(writer: &mut W, value: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(value)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[async_trait]
pub trait ClairvoyantClient {
    async fn request(
        &mut self,
        request: ClairvoyantRequest,
    ) -> Result<ClairvoyantResponse, ProtocolError>;
}

pub struct ByteClient<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> ByteClient<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

#[async_trait]
impl<R, W> ClairvoyantClient for ByteClient<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn request(
        &mut self,
        request: ClairvoyantRequest,
    ) -> Result<ClairvoyantResponse, ProtocolError> {
        write_value(&mut self.writer, &request).await?;
        match read_value::<_, ClairvoyantEnvelope>(&mut self.reader).await? {
            Some(ClairvoyantEnvelope::Ok { response }) => Ok(*response),
            Some(ClairvoyantEnvelope::Err { error }) => Err(error.into()),
            None => Err(ProtocolError::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clairvoyant_core::{ClairvoyantEnvelope, Settings};

    #[tokio::test]
    async fn duplex_round_trips_value() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let write = tokio::spawn(async move {
            write_value(&mut a, &ClairvoyantRequest::GetSettings)
                .await
                .expect("write");
        });
        let read: ClairvoyantRequest = read_value(&mut b).await.expect("read").expect("some");
        write.await.expect("join");
        assert!(matches!(read, ClairvoyantRequest::GetSettings));
    }

    #[tokio::test]
    async fn read_value_returns_none_on_clean_eof() {
        let mut empty = tokio::io::empty();
        let value: Option<ClairvoyantRequest> = read_value(&mut empty).await.expect("clean eof");
        assert!(value.is_none());
    }

    #[tokio::test]
    async fn read_value_rejects_truncated_length_prefix() {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        writer
            .write_all(&[0, 0])
            .await
            .expect("write partial length");
        drop(writer);

        let error = read_value::<_, ClairvoyantRequest>(&mut reader)
            .await
            .expect_err("truncated length prefix should fail");
        assert!(matches!(error, ProtocolError::Io(_)));
    }

    #[tokio::test]
    async fn read_value_rejects_oversized_frame_before_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        writer
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .expect("write oversized length");
        drop(writer);

        let error = read_value::<_, ClairvoyantRequest>(&mut reader)
            .await
            .expect_err("oversized frame should fail without reading payload");
        assert!(matches!(
            error,
            ProtocolError::Frame(FrameError::TooLarge(size)) if size == MAX_FRAME_BYTES + 1
        ));
    }

    #[tokio::test]
    async fn byte_client_exchanges_request_response_frames() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client_reader, client_writer) = tokio::io::split(client_io);
        let (mut server_reader, mut server_writer) = tokio::io::split(server_io);
        let server = tokio::spawn(async move {
            let request: ClairvoyantRequest = read_value(&mut server_reader)
                .await
                .expect("server read")
                .expect("request");
            assert!(matches!(request, ClairvoyantRequest::GetSettings));
            write_value(
                &mut server_writer,
                &ClairvoyantEnvelope::Ok {
                    response: Box::new(ClairvoyantResponse::Settings(Settings {
                        intent_timeout: 10,
                        reason_timeout: 11,
                    })),
                },
            )
            .await
            .expect("server write");
        });
        let mut client = ByteClient::new(client_reader, client_writer);
        let response = client
            .request(ClairvoyantRequest::GetSettings)
            .await
            .expect("client response");
        server.await.expect("server task");
        match response {
            ClairvoyantResponse::Settings(settings) => {
                assert_eq!(settings.intent_timeout, 10);
                assert_eq!(settings.reason_timeout, 11);
            }
            other => panic!("unexpected response {other:?}"),
        }
    }

    #[tokio::test]
    async fn byte_client_maps_error_envelope_to_server_error() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client_reader, client_writer) = tokio::io::split(client_io);
        let (mut server_reader, mut server_writer) = tokio::io::split(server_io);
        let server = tokio::spawn(async move {
            let request: ClairvoyantRequest = read_value(&mut server_reader)
                .await
                .expect("server read")
                .expect("request");
            assert!(matches!(request, ClairvoyantRequest::GetSettings));
            write_value(
                &mut server_writer,
                &ClairvoyantEnvelope::Err {
                    error: ClairvoyantErrorBody {
                        status: 503,
                        message: "busy".to_string(),
                        retry_after_ms: Some(250),
                    },
                },
            )
            .await
            .expect("server write");
        });
        let mut client = ByteClient::new(client_reader, client_writer);
        let error = client
            .request(ClairvoyantRequest::GetSettings)
            .await
            .expect_err("error envelope should fail request");
        assert!(matches!(
            error,
            ProtocolError::Server {
                status: 503,
                retry_after_ms: Some(250),
                ..
            }
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn byte_client_rejects_unknown_response_fields() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client_reader, client_writer) = tokio::io::split(client_io);
        let (mut server_reader, mut server_writer) = tokio::io::split(server_io);
        let server = tokio::spawn(async move {
            let request: ClairvoyantRequest = read_value(&mut server_reader)
                .await
                .expect("server read")
                .expect("request");
            assert!(matches!(request, ClairvoyantRequest::GetSettings));
            let invalid = br#"{"result":"ok","response":{"kind":"settings","value":{"intent_timeout":10,"reason_timeout":11},"extra":true}}"#;
            server_writer
                .write_all(&(invalid.len() as u32).to_be_bytes())
                .await
                .expect("write len");
            server_writer.write_all(invalid).await.expect("write body");
            server_writer.flush().await.expect("flush");
        });
        let mut client = ByteClient::new(client_reader, client_writer);
        let error = client
            .request(ClairvoyantRequest::GetSettings)
            .await
            .expect_err("unknown response field should fail");
        assert!(matches!(error, ProtocolError::Frame(_)));
        server.await.expect("server task");
    }
}
