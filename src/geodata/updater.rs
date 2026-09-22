//! Bounded GeoData downloads forced through one raw proxy dispatcher.
//!
//! This module deliberately does not know about routing or DIRECT. The caller
//! must pass the raw dispatcher for the selected default proxy. Every hop,
//! including redirects, opens a domain destination through that dispatcher.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::BytesMut;
use rustls::{ClientConfig, RootCertStore, client::Resumption, pki_types::ServerName};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::{
    dispatch::{BoxStream, DispatchError, Dispatcher},
    session::{Destination, InboundKind, StreamSession},
};

pub(crate) const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(90);

const MAX_REDIRECTS: usize = 5;
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_REQUEST_ETAG_BYTES: usize = 1024;
const MAX_RESPONSE_HEAD_BYTES: usize = 32 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_INFORMATIONAL_RESPONSES: usize = 4;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TRAILER_BYTES: usize = 8 * 1024;
const MAX_TRAILER_HEADERS: usize = 32;
const IO_BUFFER_BYTES: usize = 16 * 1024;

pub(crate) struct GeoDataDownloadRequest {
    pub dispatcher: Arc<dyn Dispatcher>,
    pub url: String,
    pub etag: Option<String>,
    /// A new temporary file. The downloader refuses to replace an existing
    /// path; publishing the completed file is the manager's responsibility.
    pub temporary_path: PathBuf,
    pub size_limit: u64,
    pub timeout: Duration,
    pub cancellation: CancellationToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GeoDataDownloadOutcome {
    NotModified,
    Downloaded {
        etag: Option<String>,
        sha256: [u8; 32],
        size: u64,
        final_url: String,
    },
}

#[derive(Debug, Error)]
pub(crate) enum GeoDataDownloadError {
    #[error("invalid GeoData URL: {0}")]
    InvalidUrl(String),
    #[error("GeoData download URL must use HTTPS")]
    HttpsRequired,
    #[error("GeoData download URL must contain a domain host")]
    DomainRequired,
    #[error("GeoData download URL must not contain credentials")]
    CredentialsNotAllowed,
    #[error("GeoData download ETag is not a bounded HTTP header value")]
    InvalidEtag,
    #[error("GeoData proxy dispatch failed: {0}")]
    Dispatch(#[source] DispatchError),
    #[error("GeoData TLS setup failed: {0}")]
    TlsSetup(String),
    #[error("GeoData TLS handshake failed: {0}")]
    TlsHandshake(String),
    #[error("GeoData HTTP protocol error: {0}")]
    Protocol(String),
    #[error("GeoData server returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("GeoData download followed more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    #[error("GeoData response body is at least {actual} bytes; limit is {maximum} bytes")]
    BodyTooLarge { actual: u64, maximum: u64 },
    #[error("GeoData download timed out after {0:?}")]
    TimedOut(Duration),
    #[error("GeoData download was cancelled")]
    Cancelled,
    #[error("failed to {operation} GeoData temporary file {path}: {source}")]
    File {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("GeoData network I/O failed: {0}")]
    NetworkIo(#[source] io::Error),
}

/// Downloads one GeoData asset exclusively through `request.dispatcher`.
///
/// The successful `Downloaded` result leaves a fully flushed temporary file at
/// `request.temporary_path`. All other outcomes remove the temporary file.
pub(crate) async fn download_geodata_via_proxy(
    request: GeoDataDownloadRequest,
) -> Result<GeoDataDownloadOutcome, GeoDataDownloadError> {
    let connector = WebPkiHttpsConnector::new()?;
    download_with_connector(request, &connector).await
}

#[async_trait]
trait HttpsConnector: Send + Sync {
    async fn connect(
        &self,
        server_name: &str,
        stream: BoxStream,
    ) -> Result<BoxStream, GeoDataDownloadError>;
}

struct WebPkiHttpsConnector {
    connector: TlsConnector,
}

impl WebPkiHttpsConnector {
    fn new() -> Result<Self, GeoDataDownloadError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| GeoDataDownloadError::TlsSetup(error.to_string()))?
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = Resumption::disabled();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

#[async_trait]
impl HttpsConnector for WebPkiHttpsConnector {
    async fn connect(
        &self,
        server_name: &str,
        stream: BoxStream,
    ) -> Result<BoxStream, GeoDataDownloadError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|error| GeoDataDownloadError::TlsSetup(error.to_string()))?;
        self.connector
            .connect(server_name, stream)
            .await
            .map(|stream| Box::new(stream) as BoxStream)
            .map_err(|error| GeoDataDownloadError::TlsHandshake(error.to_string()))
    }
}

async fn download_with_connector(
    request: GeoDataDownloadRequest,
    connector: &dyn HttpsConnector,
) -> Result<GeoDataDownloadOutcome, GeoDataDownloadError> {
    let initial_url = parse_https_url(&request.url)?;
    validate_etag(request.etag.as_deref())?;

    let temporary_path = request.temporary_path.clone();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|source| GeoDataDownloadError::File {
            operation: "create",
            path: temporary_path.clone(),
            source,
        })?;

    let cancellation = request.cancellation.clone();
    let timeout = request.timeout;
    let result = {
        let operation = download_inner(request, connector, initial_url, file);
        tokio::pin!(operation);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(GeoDataDownloadError::Cancelled),
            timed = tokio::time::timeout(timeout, &mut operation) => {
                match timed {
                    Ok(result) => result,
                    Err(_) => Err(GeoDataDownloadError::TimedOut(timeout)),
                }
            }
        }
    };

    if !matches!(result, Ok(GeoDataDownloadOutcome::Downloaded { .. })) {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

async fn download_inner(
    request: GeoDataDownloadRequest,
    connector: &dyn HttpsConnector,
    mut current_url: Url,
    file: File,
) -> Result<GeoDataDownloadOutcome, GeoDataDownloadError> {
    let mut file = Some(file);

    for redirects_followed in 0..=MAX_REDIRECTS {
        let endpoint = HttpsEndpoint::from_url(&current_url)?;
        let session = StreamSession {
            inbound: InboundKind::InternalGeoData,
            source: SocketAddr::from(([0, 0, 0, 0], 0)),
            destination: Destination::domain(endpoint.host.clone(), endpoint.port)
                .map_err(|error| GeoDataDownloadError::InvalidUrl(error.to_string()))?,
            sniffed_domain: None,
        };
        let stream = request
            .dispatcher
            .connect_tcp(session)
            .await
            .map_err(GeoDataDownloadError::Dispatch)?;
        let stream = connector.connect(&endpoint.host, stream).await?;
        let mut response = HttpReader::new(stream);

        response
            .stream
            .write_all(&build_request(&endpoint, request.etag.as_deref()))
            .await
            .map_err(GeoDataDownloadError::NetworkIo)?;
        response
            .stream
            .flush()
            .await
            .map_err(GeoDataDownloadError::NetworkIo)?;

        let head = response.read_final_head().await?;
        if is_redirect(head.status) {
            if redirects_followed == MAX_REDIRECTS {
                return Err(GeoDataDownloadError::TooManyRedirects);
            }
            let location = head.location.ok_or_else(|| {
                GeoDataDownloadError::Protocol(
                    "redirect response does not contain Location".to_owned(),
                )
            })?;
            current_url = resolve_redirect(&current_url, &location)?;
            continue;
        }

        match head.status {
            304 if request.etag.is_some() => return Ok(GeoDataDownloadOutcome::NotModified),
            304 => {
                return Err(GeoDataDownloadError::Protocol(
                    "received 304 without sending If-None-Match".to_owned(),
                ));
            }
            200 => {}
            status => return Err(GeoDataDownloadError::HttpStatus(status)),
        }

        validate_content_encoding(head.content_encoding.as_deref())?;
        let framing = body_framing(&head, request.size_limit)?;
        let target = file
            .take()
            .expect("temporary file must be consumed by one final response");
        let mut sink = BodySink::new(target, request.size_limit);
        match framing {
            BodyFraming::ContentLength(length) => {
                response.copy_exact_body(length, &mut sink).await?;
            }
            BodyFraming::Chunked => {
                response.copy_chunked_body(&mut sink).await?;
            }
            BodyFraming::UntilEof => {
                response.copy_body_until_eof(&mut sink).await?;
            }
        }
        let (sha256, size) = sink.finish(&request.temporary_path)?;
        return Ok(GeoDataDownloadOutcome::Downloaded {
            etag: head.etag,
            sha256,
            size,
            final_url: current_url.to_string(),
        });
    }

    Err(GeoDataDownloadError::TooManyRedirects)
}

#[derive(Debug)]
struct HttpsEndpoint {
    host: String,
    port: u16,
    authority: String,
    origin_form: String,
}

impl HttpsEndpoint {
    fn from_url(url: &Url) -> Result<Self, GeoDataDownloadError> {
        let host = match url.host() {
            Some(Host::Domain(host)) => host.to_owned(),
            _ => return Err(GeoDataDownloadError::DomainRequired),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| GeoDataDownloadError::InvalidUrl("missing HTTPS port".to_owned()))?;
        let authority = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut origin_form = if url.path().is_empty() {
            "/".to_owned()
        } else {
            url.path().to_owned()
        };
        if let Some(query) = url.query() {
            origin_form.push('?');
            origin_form.push_str(query);
        }
        Ok(Self {
            host,
            port,
            authority,
            origin_form,
        })
    }
}

fn parse_https_url(raw: &str) -> Result<Url, GeoDataDownloadError> {
    if raw.len() > MAX_URL_BYTES {
        return Err(GeoDataDownloadError::InvalidUrl(format!(
            "URL exceeds {MAX_URL_BYTES} bytes"
        )));
    }
    let mut url =
        Url::parse(raw).map_err(|error| GeoDataDownloadError::InvalidUrl(error.to_string()))?;
    if url.scheme() != "https" {
        return Err(GeoDataDownloadError::HttpsRequired);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(GeoDataDownloadError::CredentialsNotAllowed);
    }
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return Err(GeoDataDownloadError::DomainRequired);
    }
    url.set_fragment(None);
    Ok(url)
}

fn resolve_redirect(base: &Url, location: &str) -> Result<Url, GeoDataDownloadError> {
    if location.len() > MAX_URL_BYTES || !is_header_value(location.as_bytes()) {
        return Err(GeoDataDownloadError::InvalidUrl(
            "redirect Location is not a bounded HTTP header value".to_owned(),
        ));
    }
    let joined = base
        .join(location)
        .map_err(|error| GeoDataDownloadError::InvalidUrl(error.to_string()))?;
    parse_https_url(joined.as_str())
}

fn validate_etag(etag: Option<&str>) -> Result<(), GeoDataDownloadError> {
    if let Some(etag) = etag
        && (etag.len() > MAX_REQUEST_ETAG_BYTES || !is_header_value(etag.as_bytes()))
    {
        return Err(GeoDataDownloadError::InvalidEtag);
    }
    Ok(())
}

fn build_request(endpoint: &HttpsEndpoint, etag: Option<&str>) -> Vec<u8> {
    let conditional = etag.map_or_else(String::new, |etag| format!("If-None-Match: {etag}\r\n"));
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nUser-Agent: VCore/0.1\r\nConnection: close\r\n{}\r\n",
        endpoint.origin_form, endpoint.authority, conditional
    )
    .into_bytes()
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[derive(Debug)]
struct ResponseHead {
    status: u16,
    content_length: Option<u64>,
    transfer_encoding: Option<String>,
    content_encoding: Option<String>,
    etag: Option<String>,
    location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    ContentLength(u64),
    Chunked,
    UntilEof,
}

fn body_framing(head: &ResponseHead, size_limit: u64) -> Result<BodyFraming, GeoDataDownloadError> {
    if head.transfer_encoding.is_some() && head.content_length.is_some() {
        return Err(GeoDataDownloadError::Protocol(
            "response contains both Transfer-Encoding and Content-Length".to_owned(),
        ));
    }
    if let Some(encoding) = &head.transfer_encoding {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(GeoDataDownloadError::Protocol(format!(
                "unsupported Transfer-Encoding `{encoding}`"
            )));
        }
        return Ok(BodyFraming::Chunked);
    }
    if let Some(length) = head.content_length {
        if length > size_limit {
            return Err(GeoDataDownloadError::BodyTooLarge {
                actual: length,
                maximum: size_limit,
            });
        }
        return Ok(BodyFraming::ContentLength(length));
    }
    Ok(BodyFraming::UntilEof)
}

fn validate_content_encoding(encoding: Option<&str>) -> Result<(), GeoDataDownloadError> {
    if let Some(encoding) = encoding
        && !encoding
            .split(',')
            .all(|value| value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(GeoDataDownloadError::Protocol(format!(
            "unsupported Content-Encoding `{encoding}`"
        )));
    }
    Ok(())
}

struct HttpReader {
    stream: BoxStream,
    buffered: BytesMut,
}

impl HttpReader {
    fn new(stream: BoxStream) -> Self {
        Self {
            stream,
            buffered: BytesMut::with_capacity(4 * 1024),
        }
    }

    async fn read_final_head(&mut self) -> Result<ResponseHead, GeoDataDownloadError> {
        for informational_count in 0..=MAX_INFORMATIONAL_RESPONSES {
            let block = self.read_head_block().await?;
            let head = parse_response_head(&block)?;
            if !(100..200).contains(&head.status) {
                return Ok(head);
            }
            if head.status == 101 {
                return Err(GeoDataDownloadError::Protocol(
                    "HTTP protocol switching is not supported".to_owned(),
                ));
            }
            if informational_count == MAX_INFORMATIONAL_RESPONSES {
                return Err(GeoDataDownloadError::Protocol(
                    "too many informational responses".to_owned(),
                ));
            }
        }
        unreachable!("informational response loop always returns");
    }

    async fn read_head_block(&mut self) -> Result<Vec<u8>, GeoDataDownloadError> {
        loop {
            if let Some(end) = find_bytes(&self.buffered, b"\r\n\r\n") {
                if end + 4 > MAX_RESPONSE_HEAD_BYTES {
                    return Err(GeoDataDownloadError::Protocol(format!(
                        "response head exceeds {MAX_RESPONSE_HEAD_BYTES} bytes"
                    )));
                }
                let mut block = self.buffered.split_to(end + 4).to_vec();
                block.truncate(end);
                return Ok(block);
            }
            if self.buffered.len() >= MAX_RESPONSE_HEAD_BYTES {
                return Err(GeoDataDownloadError::Protocol(format!(
                    "response head exceeds {MAX_RESPONSE_HEAD_BYTES} bytes"
                )));
            }
            let mut scratch = [0_u8; 4 * 1024];
            let read = self
                .stream
                .read(&mut scratch)
                .await
                .map_err(GeoDataDownloadError::NetworkIo)?;
            if read == 0 {
                return Err(GeoDataDownloadError::Protocol(
                    "response ended before its HTTP head".to_owned(),
                ));
            }
            self.buffered.extend_from_slice(&scratch[..read]);
        }
    }

    async fn copy_exact_body(
        &mut self,
        mut remaining: u64,
        sink: &mut BodySink,
    ) -> Result<(), GeoDataDownloadError> {
        let mut scratch = [0_u8; IO_BUFFER_BYTES];
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(IO_BUFFER_BYTES as u64))
                .expect("bounded read size fits usize");
            let read = self.read_some(&mut scratch[..wanted]).await?;
            if read == 0 {
                return Err(GeoDataDownloadError::Protocol(format!(
                    "response body ended with {remaining} bytes missing"
                )));
            }
            sink.write(&scratch[..read])?;
            remaining -= read as u64;
        }
        Ok(())
    }

    async fn copy_body_until_eof(
        &mut self,
        sink: &mut BodySink,
    ) -> Result<(), GeoDataDownloadError> {
        let mut scratch = [0_u8; IO_BUFFER_BYTES];
        loop {
            let read = self.read_some(&mut scratch).await?;
            if read == 0 {
                return Ok(());
            }
            sink.write(&scratch[..read])?;
        }
    }

    async fn copy_chunked_body(&mut self, sink: &mut BodySink) -> Result<(), GeoDataDownloadError> {
        loop {
            let line = self.read_line(MAX_CHUNK_LINE_BYTES).await?;
            if !is_header_value(&line) {
                return Err(GeoDataDownloadError::Protocol(
                    "chunk-size line contains invalid bytes".to_owned(),
                ));
            }
            let size_text = line
                .split(|byte| *byte == b';')
                .next()
                .expect("split always returns one value");
            let size_text = trim_ascii_whitespace(size_text);
            if size_text.is_empty() || size_text.len() > 16 {
                return Err(GeoDataDownloadError::Protocol(
                    "invalid chunk size".to_owned(),
                ));
            }
            let size_text = std::str::from_utf8(size_text).map_err(|_| {
                GeoDataDownloadError::Protocol("chunk size is not ASCII".to_owned())
            })?;
            let size = u64::from_str_radix(size_text, 16).map_err(|_| {
                GeoDataDownloadError::Protocol("invalid hexadecimal chunk size".to_owned())
            })?;
            if size == 0 {
                self.read_trailers().await?;
                return Ok(());
            }
            self.copy_exact_body(size, sink).await?;
            let terminator = self.read_exact_small(2).await?;
            if terminator != b"\r\n" {
                return Err(GeoDataDownloadError::Protocol(
                    "chunk data is not followed by CRLF".to_owned(),
                ));
            }
        }
    }

    async fn read_trailers(&mut self) -> Result<(), GeoDataDownloadError> {
        let mut total = 0_usize;
        for count in 0..=MAX_TRAILER_HEADERS {
            let line = self.read_line(MAX_TRAILER_BYTES).await?;
            total = total.checked_add(line.len() + 2).ok_or_else(|| {
                GeoDataDownloadError::Protocol("trailer size overflow".to_owned())
            })?;
            if total > MAX_TRAILER_BYTES {
                return Err(GeoDataDownloadError::Protocol(format!(
                    "trailers exceed {MAX_TRAILER_BYTES} bytes"
                )));
            }
            if line.is_empty() {
                return Ok(());
            }
            if count == MAX_TRAILER_HEADERS {
                return Err(GeoDataDownloadError::Protocol(format!(
                    "trailers contain more than {MAX_TRAILER_HEADERS} fields"
                )));
            }
            validate_trailer_line(&line)?;
        }
        unreachable!("trailer loop always returns");
    }

    async fn read_line(&mut self, maximum: usize) -> Result<Vec<u8>, GeoDataDownloadError> {
        loop {
            if let Some(end) = find_bytes(&self.buffered, b"\r\n") {
                if end > maximum {
                    return Err(GeoDataDownloadError::Protocol(format!(
                        "HTTP line exceeds {maximum} bytes"
                    )));
                }
                let mut line = self.buffered.split_to(end + 2).to_vec();
                line.truncate(end);
                return Ok(line);
            }
            if self.buffered.len() > maximum {
                return Err(GeoDataDownloadError::Protocol(format!(
                    "HTTP line exceeds {maximum} bytes"
                )));
            }
            let mut scratch = [0_u8; 4 * 1024];
            let read = self
                .stream
                .read(&mut scratch)
                .await
                .map_err(GeoDataDownloadError::NetworkIo)?;
            if read == 0 {
                return Err(GeoDataDownloadError::Protocol(
                    "response ended in the middle of an HTTP line".to_owned(),
                ));
            }
            self.buffered.extend_from_slice(&scratch[..read]);
        }
    }

    async fn read_exact_small(&mut self, length: usize) -> Result<Vec<u8>, GeoDataDownloadError> {
        let mut output = vec![0_u8; length];
        let mut written = 0;
        while written < length {
            if self.buffered.is_empty() {
                let mut scratch = [0_u8; 4 * 1024];
                let read = self
                    .stream
                    .read(&mut scratch)
                    .await
                    .map_err(GeoDataDownloadError::NetworkIo)?;
                if read == 0 {
                    return Err(GeoDataDownloadError::Protocol(
                        "response body ended unexpectedly".to_owned(),
                    ));
                }
                self.buffered.extend_from_slice(&scratch[..read]);
            }
            let take = (length - written).min(self.buffered.len());
            let bytes = self.buffered.split_to(take);
            output[written..written + take].copy_from_slice(&bytes);
            written += take;
        }
        Ok(output)
    }

    async fn read_some(&mut self, output: &mut [u8]) -> Result<usize, GeoDataDownloadError> {
        if !self.buffered.is_empty() {
            let take = output.len().min(self.buffered.len());
            let bytes = self.buffered.split_to(take);
            output[..take].copy_from_slice(&bytes);
            return Ok(take);
        }
        self.stream
            .read(output)
            .await
            .map_err(GeoDataDownloadError::NetworkIo)
    }
}

fn parse_response_head(block: &[u8]) -> Result<ResponseHead, GeoDataDownloadError> {
    if !block.is_ascii() {
        return Err(GeoDataDownloadError::Protocol(
            "response head contains non-ASCII bytes".to_owned(),
        ));
    }
    let text = std::str::from_utf8(block)
        .map_err(|_| GeoDataDownloadError::Protocol("invalid response head".to_owned()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| GeoDataDownloadError::Protocol("missing HTTP status line".to_owned()))?;
    let mut status_parts = status_line.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(GeoDataDownloadError::Protocol(
            "server did not respond with HTTP/1.1".to_owned(),
        ));
    }
    let status_text = status_parts
        .next()
        .ok_or_else(|| GeoDataDownloadError::Protocol("missing HTTP status".to_owned()))?;
    if status_text.len() != 3 || !status_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GeoDataDownloadError::Protocol(
            "invalid HTTP status".to_owned(),
        ));
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| GeoDataDownloadError::Protocol("invalid HTTP status".to_owned()))?;

    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut content_encoding = None;
    let mut etag = None;
    let mut location = None;
    let mut header_count = 0_usize;

    for line in lines {
        header_count += 1;
        if header_count > MAX_RESPONSE_HEADERS {
            return Err(GeoDataDownloadError::Protocol(format!(
                "response contains more than {MAX_RESPONSE_HEADERS} headers"
            )));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(GeoDataDownloadError::Protocol(
                "obsolete folded headers are not supported".to_owned(),
            ));
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            GeoDataDownloadError::Protocol("malformed HTTP response header".to_owned())
        })?;
        if !is_header_name(name.as_bytes()) {
            return Err(GeoDataDownloadError::Protocol(
                "invalid HTTP response header name".to_owned(),
            ));
        }
        let value = value.trim_matches([' ', '\t']);
        if !is_header_value(value.as_bytes()) {
            return Err(GeoDataDownloadError::Protocol(
                "invalid HTTP response header value".to_owned(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            set_once(&mut content_length, "Content-Length")?;
            content_length = Some(value.parse::<u64>().map_err(|_| {
                GeoDataDownloadError::Protocol("invalid Content-Length".to_owned())
            })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            set_string_once(&mut transfer_encoding, value, "Transfer-Encoding")?;
        } else if name.eq_ignore_ascii_case("content-encoding") {
            set_string_once(&mut content_encoding, value, "Content-Encoding")?;
        } else if name.eq_ignore_ascii_case("etag") {
            set_string_once(&mut etag, value, "ETag")?;
        } else if name.eq_ignore_ascii_case("location") {
            set_string_once(&mut location, value, "Location")?;
        }
    }

    Ok(ResponseHead {
        status,
        content_length,
        transfer_encoding,
        content_encoding,
        etag,
        location,
    })
}

fn set_once<T>(
    slot: &mut Option<T>,
    header_name: &'static str,
) -> Result<(), GeoDataDownloadError> {
    if slot.is_some() {
        return Err(GeoDataDownloadError::Protocol(format!(
            "duplicate {header_name} header"
        )));
    }
    Ok(())
}

fn set_string_once(
    slot: &mut Option<String>,
    value: &str,
    header_name: &'static str,
) -> Result<(), GeoDataDownloadError> {
    set_once(slot, header_name)?;
    *slot = Some(value.to_owned());
    Ok(())
}

fn validate_trailer_line(line: &[u8]) -> Result<(), GeoDataDownloadError> {
    if !line.is_ascii()
        || line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        return Err(GeoDataDownloadError::Protocol(
            "invalid HTTP trailer".to_owned(),
        ));
    }
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(GeoDataDownloadError::Protocol(
            "malformed HTTP trailer".to_owned(),
        ));
    };
    let name = &line[..colon];
    let value = trim_ascii_whitespace(&line[colon + 1..]);
    if !is_header_name(name) || !is_header_value(value) {
        return Err(GeoDataDownloadError::Protocol(
            "invalid HTTP trailer".to_owned(),
        ));
    }
    if name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"content-encoding")
        || name.eq_ignore_ascii_case(b"location")
    {
        return Err(GeoDataDownloadError::Protocol(
            "forbidden framing field in HTTP trailer".to_owned(),
        ));
    }
    Ok(())
}

fn is_header_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_header_value(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct BodySink {
    file: File,
    hasher: Sha256,
    size: u64,
    maximum: u64,
}

impl BodySink {
    fn new(file: File, maximum: u64) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            size: 0,
            maximum,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), GeoDataDownloadError> {
        let added = u64::try_from(bytes.len()).expect("buffer length fits u64");
        let next = self
            .size
            .checked_add(added)
            .ok_or(GeoDataDownloadError::BodyTooLarge {
                actual: u64::MAX,
                maximum: self.maximum,
            })?;
        if next > self.maximum {
            return Err(GeoDataDownloadError::BodyTooLarge {
                actual: next,
                maximum: self.maximum,
            });
        }
        self.file
            .write_all(bytes)
            .map_err(GeoDataDownloadError::NetworkIo)?;
        self.hasher.update(bytes);
        self.size = next;
        Ok(())
    }

    fn finish(mut self, path: &std::path::Path) -> Result<([u8; 32], u64), GeoDataDownloadError> {
        self.file
            .flush()
            .and_then(|()| self.file.sync_all())
            .map_err(|source| GeoDataDownloadError::File {
                operation: "flush",
                path: path.to_path_buf(),
                source,
            })?;
        let sha256 = self.hasher.finalize().into();
        Ok((sha256, self.size))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{
        dispatch::{DatagramTransport, DispatchError},
        session::{DatagramSession, Destination},
    };

    struct PlainHttpsConnector;

    #[async_trait]
    impl HttpsConnector for PlainHttpsConnector {
        async fn connect(
            &self,
            _server_name: &str,
            stream: BoxStream,
        ) -> Result<BoxStream, GeoDataDownloadError> {
            Ok(stream)
        }
    }

    struct ScriptedDispatcher {
        responses: Mutex<VecDeque<Vec<u8>>>,
        sessions: Mutex<Vec<StreamSession>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    struct HangingDispatcher;

    #[async_trait]
    impl Dispatcher for HangingDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            std::future::pending().await
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }

    impl ScriptedDispatcher {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                sessions: Mutex::new(Vec::new()),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sessions(&self) -> Vec<StreamSession> {
            self.sessions.lock().expect("sessions lock").clone()
        }

        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    #[async_trait]
    impl Dispatcher for ScriptedDispatcher {
        async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
            self.sessions.lock().expect("sessions lock").push(session);
            let response = self
                .responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .ok_or_else(|| DispatchError::Other("no scripted response".to_owned()))?;
            let requests = Arc::clone(&self.requests);
            let (client, mut server) = tokio::io::duplex(128 * 1024);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut scratch = [0_u8; 1024];
                loop {
                    let read = server.read(&mut scratch).await.expect("read request");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&scratch[..read]);
                    if find_bytes(&request, b"\r\n\r\n").is_some() {
                        break;
                    }
                }
                requests.lock().expect("requests lock").push(request);
                server.write_all(&response).await.expect("write response");
                server.shutdown().await.expect("shutdown response");
            });
            Ok(Box::new(client))
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }

    fn request(
        dispatcher: Arc<dyn Dispatcher>,
        url: &str,
        temporary_path: PathBuf,
        size_limit: u64,
    ) -> GeoDataDownloadRequest {
        GeoDataDownloadRequest {
            dispatcher,
            url: url.to_owned(),
            etag: Some("\"old\"".to_owned()),
            temporary_path,
            size_limit,
            timeout: Duration::from_secs(2),
            cancellation: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn follows_https_redirect_and_streams_chunked_body_through_raw_proxy() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("geosite.dat.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example.test/final.dat?version=2\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: identity\r\nETag: \"new\"\r\n\r\n4\r\ngeo-\r\n4\r\ndata\r\n0\r\nX-Checksum: present\r\n\r\n".to_vec(),
        ]));
        let outcome = download_with_connector(
            request(
                dispatcher.clone(),
                "https://rules.example.test/geosite.dat",
                temporary_path.clone(),
                1024,
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("download succeeds");

        let expected_sha256: [u8; 32] = Sha256::digest(b"geo-data").into();
        assert_eq!(
            outcome,
            GeoDataDownloadOutcome::Downloaded {
                etag: Some("\"new\"".to_owned()),
                sha256: expected_sha256,
                size: 8,
                final_url: "https://cdn.example.test/final.dat?version=2".to_owned(),
            }
        );
        assert_eq!(
            fs::read(&temporary_path).expect("temporary data"),
            b"geo-data"
        );

        let sessions = dispatcher.sessions();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|session| {
            session.inbound == InboundKind::InternalGeoData
                && session.source == SocketAddr::from(([0, 0, 0, 0], 0))
                && session.sniffed_domain.is_none()
        }));
        assert_eq!(
            sessions[0].destination,
            Destination::Domain {
                host: "rules.example.test".to_owned(),
                port: 443,
            }
        );
        assert_eq!(
            sessions[1].destination,
            Destination::Domain {
                host: "cdn.example.test".to_owned(),
                port: 443,
            }
        );

        let requests = dispatcher.requests();
        assert_eq!(requests.len(), 2);
        let first = std::str::from_utf8(&requests[0]).expect("request is ASCII");
        assert!(first.starts_with("GET /geosite.dat HTTP/1.1\r\n"));
        assert!(first.contains("\r\nHost: rules.example.test\r\n"));
        assert!(first.contains("\r\nAccept-Encoding: identity\r\n"));
        assert!(first.contains("\r\nIf-None-Match: \"old\"\r\n"));
    }

    #[tokio::test]
    async fn not_modified_removes_the_unused_temporary_file() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("geoip.dat.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 304 Not Modified\r\nETag: \"old\"\r\n\r\n".to_vec(),
        ]));
        let outcome = download_with_connector(
            request(
                dispatcher,
                "https://rules.example.test/geoip.dat",
                temporary_path.clone(),
                1024,
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("conditional request succeeds");

        assert_eq!(outcome, GeoDataDownloadOutcome::NotModified);
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn supports_content_length_and_eof_delimited_bodies() {
        let directory = tempdir().expect("tempdir");
        let content_length_path = directory.path().join("content-length.new");
        let content_length_dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345ignored".to_vec(),
        ]));
        let content_length = download_with_connector(
            request(
                content_length_dispatcher,
                "https://rules.example.test/content-length",
                content_length_path.clone(),
                5,
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("content-length body");
        assert!(matches!(
            content_length,
            GeoDataDownloadOutcome::Downloaded { size: 5, .. }
        ));
        assert_eq!(
            fs::read(content_length_path).expect("length file"),
            b"12345"
        );

        let eof_path = directory.path().join("eof.new");
        let eof_dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\neof-body".to_vec(),
        ]));
        let eof = download_with_connector(
            request(
                eof_dispatcher,
                "https://rules.example.test/eof",
                eof_path.clone(),
                32,
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect("EOF body");
        assert!(matches!(
            eof,
            GeoDataDownloadOutcome::Downloaded { size: 8, .. }
        ));
        assert_eq!(fs::read(eof_path).expect("EOF file"), b"eof-body");
    }

    #[tokio::test]
    async fn rejects_oversized_body_and_removes_partial_file() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("oversized.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n0\r\n\r\n"
                .to_vec(),
        ]));
        let error = download_with_connector(
            request(
                dispatcher,
                "https://rules.example.test/geoip.dat",
                temporary_path.clone(),
                4,
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect_err("body must be rejected");

        assert!(matches!(
            error,
            GeoDataDownloadError::BodyTooLarge {
                actual: 8,
                maximum: 4
            }
        ));
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn rejects_redirect_to_http_without_dispatching_the_second_hop() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("redirect.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 302 Found\r\nLocation: http://unsafe.example.test/file\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ]));
        let error = download_with_connector(
            request(
                dispatcher.clone(),
                "https://rules.example.test/geoip.dat",
                temporary_path.clone(),
                1024,
            ),
            &PlainHttpsConnector,
        )
        .await
        .expect_err("HTTP redirect must be rejected");

        assert!(matches!(error, GeoDataDownloadError::HttpsRequired));
        assert_eq!(dispatcher.sessions().len(), 1);
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn cancellation_wins_before_proxy_dispatch() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("cancelled.new");
        let dispatcher = Arc::new(ScriptedDispatcher::new([
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ]));
        let request = request(
            dispatcher.clone(),
            "https://rules.example.test/geoip.dat",
            temporary_path.clone(),
            1024,
        );
        request.cancellation.cancel();
        let error = download_with_connector(request, &PlainHttpsConnector)
            .await
            .expect_err("cancelled request");

        assert!(matches!(error, GeoDataDownloadError::Cancelled));
        assert!(dispatcher.sessions().is_empty());
        assert!(!temporary_path.exists());
    }

    #[tokio::test]
    async fn timeout_covers_proxy_connection_and_removes_temporary_file() {
        let directory = tempdir().expect("tempdir");
        let temporary_path = directory.path().join("timeout.new");
        let mut request = request(
            Arc::new(HangingDispatcher),
            "https://rules.example.test/geoip.dat",
            temporary_path.clone(),
            1024,
        );
        request.timeout = Duration::from_millis(10);
        let error = download_with_connector(request, &PlainHttpsConnector)
            .await
            .expect_err("request must time out");

        assert!(matches!(
            error,
            GeoDataDownloadError::TimedOut(duration)
                if duration == Duration::from_millis(10)
        ));
        assert!(!temporary_path.exists());
    }

    #[test]
    fn parser_rejects_ambiguous_or_unbounded_framing() {
        let both = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked",
        )
        .expect("head parses");
        assert!(matches!(
            body_framing(&both, 10),
            Err(GeoDataDownloadError::Protocol(_))
        ));

        let length =
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 11").expect("head parses");
        assert!(matches!(
            body_framing(&length, 10),
            Err(GeoDataDownloadError::BodyTooLarge {
                actual: 11,
                maximum: 10
            })
        ));
    }

    #[test]
    fn url_and_etag_validation_preserve_domain_only_https_contract() {
        assert!(matches!(
            parse_https_url("http://example.test/file"),
            Err(GeoDataDownloadError::HttpsRequired)
        ));
        assert!(matches!(
            parse_https_url("https://127.0.0.1/file"),
            Err(GeoDataDownloadError::DomainRequired)
        ));
        assert!(matches!(
            parse_https_url("https://user@example.test/file"),
            Err(GeoDataDownloadError::CredentialsNotAllowed)
        ));
        assert!(matches!(
            validate_etag(Some("\"ok\"\r\nX-Evil: yes")),
            Err(GeoDataDownloadError::InvalidEtag)
        ));
    }
}
