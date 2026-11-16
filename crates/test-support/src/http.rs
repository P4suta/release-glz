//! A loopback HTTP server that answers from a script or a handler and records every request.
//!
//! The server blocks on each accept and read instead of polling a clock, so a slow machine delays a test without failing it.
//! Each connection carries one request and one answer, and every answer closes its connection.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use super::fail;

/// Bytes read from a connection in one call.
const READ_CHUNK_BYTES: usize = 8192;

/// The blank line that ends a request's head.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// One request as the server received it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method, such as `GET`.
    pub method: String,
    /// The path and query that the request line names.
    pub target: String,
    /// Each header in arrival order, with its name in lowercase.
    pub headers: Vec<(String, String)>,
    /// The body that `Content-Length` delimits.
    pub body: Vec<u8>,
    /// The head and the body as they arrived.
    raw: Vec<u8>,
}

impl Request {
    /// The target without its query.
    #[must_use]
    pub fn path(&self) -> &str {
        self.target
            .split_once('?')
            .map_or(self.target.as_str(), |(path, _)| path)
    }

    /// The value of the first header called `name`, whatever its case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The head and the body as they arrived, with each invalid UTF-8 sequence replaced.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }
}

/// An answer that the server sends with `Connection: close`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Whether `Content-Length` delimits the body, rather than the end of the connection.
    sized: bool,
}

impl Response {
    /// A response with `status`, no headers of its own, and an empty body.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            sized: true,
        }
    }

    /// The same response with the header `name: value` added.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The same response with `body`.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The same response without `Content-Length`, so that its body ends where the server closes the connection.
    #[must_use]
    pub const fn until_close(mut self) -> Self {
        self.sized = false;
        self
    }

    /// The status line, the headers, and the body as the server writes them.
    fn bytes(&self) -> Vec<u8> {
        let headers: String = self
            .headers
            .iter()
            .flat_map(|(name, value)| [name.as_str(), ": ", value.as_str(), "\r\n"])
            .collect();
        let length = if self.sized {
            format!("Content-Length: {}\r\n", self.body.len())
        } else {
            String::new()
        };
        // RFC 9112 lets a status line end without a reason phrase, which clients ignore.
        let mut bytes = format!(
            "HTTP/1.1 {} \r\n{headers}{length}Connection: close\r\n\r\n",
            self.status
        )
        .into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// What the server does with a request once it has recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Send the response.
    Respond(Response),
    /// Close the connection without an answer, as a server that fails during the exchange does.
    Close,
}

impl From<Response> for Reply {
    fn from(response: Response) -> Self {
        Self::Respond(response)
    }
}

/// A loopback HTTP server that serves one connection at a time and records each request.
///
/// It stops when [`FakeServer::finish`] runs or when it is dropped, and either way it joins its thread and closes its port.
/// Stopping fails the test when a scripted reply went unsent, a request arrived after the script ran out, or the server met a fault, and the message lists the recorded requests.
pub struct FakeServer {
    address: SocketAddr,
    shared: Arc<Shared>,
    /// Holds the port until the thread has stopped, so that the connection that wakes the thread reaches no other server.
    listener: Option<TcpListener>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for FakeServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeServer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl FakeServer {
    /// Bind `127.0.0.1:0` and serve until stopped.
    ///
    /// The script starts empty, so until [`FakeServer::script`] or [`FakeServer::route`] says otherwise, each request gets a 500 response and fails the test.
    ///
    /// # Panics
    ///
    /// When the port can't be bound or the serving thread can't start.
    #[must_use]
    pub fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|error| {
            fail(format_args!(
                "the fake server couldn't bind a loopback port: {error}"
            ))
        });
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| fail(format_args!("the fake server has no address: {error}")));
        let serving = listener.try_clone().unwrap_or_else(|error| {
            fail(format_args!(
                "the fake server at {address} couldn't share its listener: {error}"
            ))
        });
        let shared = Arc::new(Shared {
            state: Mutex::new(State::new()),
            waker_named: Condvar::new(),
        });
        let served = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name(format!("fake server {address}"))
            .spawn(move || serve(&serving, &served))
            .unwrap_or_else(|error| {
                fail(format_args!(
                    "the fake server at {address} couldn't start its thread: {error}"
                ))
            });
        Self {
            address,
            shared,
            listener: Some(listener),
            thread: Some(thread),
        }
    }

    /// Queue `replies` to answer the next requests in order, one each.
    ///
    /// # Panics
    ///
    /// When the server routes its requests through a handler or hangs up.
    pub fn script<I>(&self, replies: I)
    where
        I: IntoIterator,
        I::Item: Into<Reply>,
    {
        let replies: Vec<Reply> = replies.into_iter().map(Into::into).collect();
        let mut state = self.shared.lock();
        let Responder::Script(script) = &mut state.responder else {
            drop(state);
            fail(format_args!(
                "the fake server at {} has no script to extend",
                self.address
            ))
        };
        script.extend(replies);
        drop(state);
    }

    /// Answer each request with the reply that `handler` returns for it.
    ///
    /// A panic in `handler` answers its request with a 500 response and fails the test when the server stops.
    ///
    /// # Panics
    ///
    /// When the server already holds a script or has accepted a connection.
    pub fn route(&self, handler: impl FnMut(&Request) -> Reply + Send + 'static) {
        self.replace_unused_script(Responder::Route(Box::new(handler)));
    }

    /// Close each connection as soon as it arrives, before reading anything, as a peer that fails a TLS handshake does.
    ///
    /// # Panics
    ///
    /// When the server already holds a script or has accepted a connection.
    pub fn hang_up(&self) {
        self.replace_unused_script(Responder::HangUp);
    }

    fn replace_unused_script(&self, responder: Responder) {
        let mut state = self.shared.lock();
        let unused = matches!(&state.responder, Responder::Script(script) if script.is_empty())
            && state.connections == 0;
        if !unused {
            fail(format_args!(
                "the fake server at {} already holds a script or has served a connection",
                self.address
            ));
        }
        state.responder = responder;
    }

    /// The address that the server listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The `http://` origin of the server, without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The requests recorded so far, in arrival order.
    ///
    /// The server records each request before it answers or closes, so a client that has seen its answer finds its request here.
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        self.shared.lock().requests.clone()
    }

    /// The connections accepted so far, whether or not they carried a request.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.shared.lock().connections
    }

    /// Stop once the server has accepted every connection that reached it before this call, and return the recorded requests.
    ///
    /// # Panics
    ///
    /// When a scripted reply went unsent, a request arrived after the script ran out, or the server met a fault.
    /// The message lists the recorded requests.
    pub fn finish(&mut self) -> Vec<Request> {
        if let Err(message) = self.stop() {
            fail(format_args!("{message}"));
        }
        self.requests()
    }

    /// Stop and join the thread, and describe what fails the test, if anything.
    fn stop(&mut self) -> Result<(), String> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        self.shared.begin_stopping();
        // The listener queues connections in arrival order, so the thread accepts every earlier one before this one.
        let waker = TcpStream::connect(self.address).map_err(|error| {
            format!(
                "the fake server at {} couldn't be woken to stop: {error}",
                self.address
            )
        })?;
        let waker_address = waker.local_addr().map_err(|error| {
            format!(
                "the connection that stops the fake server at {} has no address: {error}",
                self.address
            )
        })?;
        self.shared.name_waker(waker_address);
        let joined = thread.join();
        drop(waker);
        drop(self.listener.take());
        joined.map_err(|payload| {
            format!(
                "the fake server at {} panicked: {}",
                self.address,
                panic_message(&*payload)
            )
        })?;
        self.shared.verdict(self.address)
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        if let Err(message) = self.stop()
            && !std::thread::panicking()
        {
            fail(format_args!("{message}"));
        }
    }
}

/// The source of each reply.
enum Responder {
    /// Replies in order, one for each request.
    Script(VecDeque<Reply>),
    /// A function of the request.
    Route(Box<dyn FnMut(&Request) -> Reply + Send>),
    /// No reply, because each connection closes as soon as it arrives.
    HangUp,
}

/// What the serving thread and the test share.
struct State {
    responder: Responder,
    requests: Vec<Request>,
    /// Connections accepted, apart from the one that stops the server.
    connections: usize,
    /// Requests that arrived after the script ran out.
    beyond_script: usize,
    /// Faults that fail the test once the server stops.
    problems: Vec<String>,
    /// A handle on the connection being served, which stopping shuts down so that a read blocked on it returns.
    in_flight: Option<TcpStream>,
    stopping: bool,
    /// The local address of the connection that stopping opens to wake the thread.
    waker: Option<SocketAddr>,
}

impl State {
    const fn new() -> Self {
        Self {
            responder: Responder::Script(VecDeque::new()),
            requests: Vec::new(),
            connections: 0,
            beyond_script: 0,
            problems: Vec::new(),
            in_flight: None,
            stopping: false,
            waker: None,
        }
    }

    /// Decide what happens to the connection from `peer`, whose `tracking` handle lets stopping end it.
    fn admit(&mut self, peer: SocketAddr, tracking: std::io::Result<TcpStream>) -> Admission {
        if self.waker == Some(peer) {
            return Admission::Stop;
        }
        self.connections = self.connections.saturating_add(1);
        if self.stopping || matches!(self.responder, Responder::HangUp) {
            return Admission::HangUp;
        }
        match tracking {
            Ok(handle) => {
                self.in_flight = Some(handle);
                Admission::Serve
            }
            Err(error) => {
                self.problems
                    .push(format!("a connection couldn't be tracked: {error}"));
                Admission::HangUp
            }
        }
    }

    /// Record `request` and choose its reply.
    fn answer(&mut self, request: Request) -> Reply {
        let reply = match &mut self.responder {
            Responder::Script(script) => script.pop_front().unwrap_or_else(|| {
                self.beyond_script = self.beyond_script.saturating_add(1);
                Reply::Respond(Response::new(500).body(format!(
                    "the fake server has no scripted reply for request {}: {} {}",
                    self.requests.len().saturating_add(1),
                    request.method,
                    request.target
                )))
            }),
            Responder::Route(handler) => {
                match catch_unwind(AssertUnwindSafe(|| handler(&request))) {
                    Ok(reply) => reply,
                    Err(payload) => {
                        let problem = format!(
                            "the handler panicked on {} {}: {}",
                            request.method,
                            request.target,
                            panic_message(&*payload)
                        );
                        self.problems.push(problem.clone());
                        Reply::Respond(Response::new(500).body(problem))
                    }
                }
            }
            Responder::HangUp => Reply::Close,
        };
        self.requests.push(request);
        reply
    }

    fn begin_stopping(&mut self) {
        self.stopping = true;
        if let Some(in_flight) = self.in_flight.take() {
            // A connection whose client has already left refuses the shutdown, and a read blocked on it has returned anyway.
            in_flight.shutdown(Shutdown::Both).unwrap_or_else(drop);
        }
    }

    /// Everything that fails the test, with the recorded requests, or nothing.
    fn verdict(&self, address: SocketAddr) -> Result<(), String> {
        let mut findings = self.problems.clone();
        if let Responder::Script(script) = &self.responder
            && !script.is_empty()
        {
            findings.push(format!("scripted replies never sent: {}", script.len()));
        }
        if self.beyond_script > 0 {
            findings.push(format!(
                "requests beyond the script, each answered with 500: {}",
                self.beyond_script
            ));
        }
        if findings.is_empty() {
            return Ok(());
        }
        let listing = (1_usize..)
            .zip(&self.requests)
            .map(|(number, request)| format!("\n  {number}. {} {}", request.method, request.target))
            .collect::<Vec<_>>()
            .concat();
        Err(format!(
            "the fake server at {address} failed the test\n{}\nrecorded requests:{}",
            findings.join("\n"),
            if listing.is_empty() {
                " none"
            } else {
                &listing
            }
        ))
    }
}

struct Shared {
    state: Mutex<State>,
    /// Signalled once stopping has named its waking connection.
    waker_named: Condvar,
}

/// What happens to an accepted connection.
enum Admission {
    /// Read its request and answer it.
    Serve,
    /// Close it unread.
    HangUp,
    /// It is the connection that stops the server.
    Stop,
}

impl Shared {
    /// The state, which a panic in a handler leaves intact because the handler runs under `catch_unwind`.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Decide what happens to the connection from `peer`.
    ///
    /// Once stopping has begun, the decision waits until stopping names its waking connection, which it does right after connecting.
    fn admit(&self, stream: &TcpStream, peer: SocketAddr) -> Admission {
        let tracking = stream.try_clone();
        let mut state = self.lock();
        if state.stopping {
            state = self
                .waker_named
                .wait_while(state, |current| current.waker.is_none())
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.admit(peer, tracking)
    }

    fn answer(&self, request: Request) -> Reply {
        self.lock().answer(request)
    }

    fn record_problem(&self, problem: String) {
        self.lock().problems.push(problem);
    }

    fn begin_stopping(&self) {
        self.lock().begin_stopping();
    }

    fn name_waker(&self, address: SocketAddr) {
        self.lock().waker = Some(address);
        self.waker_named.notify_all();
    }

    fn verdict(&self, address: SocketAddr) -> Result<(), String> {
        self.lock().verdict(address)
    }
}

/// Accept connections one at a time until the waking connection arrives.
fn serve(listener: &TcpListener, shared: &Shared) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(error) => {
                shared.record_problem(format!("the server stopped accepting connections: {error}"));
                return;
            }
        };
        match shared.admit(&stream, peer) {
            Admission::Serve => serve_connection(shared, stream),
            Admission::HangUp => drop(stream),
            Admission::Stop => return,
        }
    }
}

fn serve_connection(shared: &Shared, mut stream: TcpStream) {
    let reply = match receive(&mut stream) {
        Ok(Some(request)) => shared.answer(request),
        Ok(None) => Reply::Close,
        Err(problem) => {
            shared.record_problem(problem.clone());
            Reply::Respond(Response::new(500).body(problem))
        }
    };
    if let Reply::Respond(response) = reply {
        // A client may leave before it has read the whole answer, as one that refuses an oversized body does, and the test asserts on what the client saw.
        stream.write_all(&response.bytes()).unwrap_or_else(drop);
    }
    // The connection closes once both handles are gone.
    shared.lock().in_flight = None;
    drop(stream);
}

/// The request that the connection carries, or `None` when it ends before the head and the body have arrived.
fn receive(stream: &mut TcpStream) -> Result<Option<Request>, String> {
    let mut raw = Vec::new();
    let head_length = loop {
        if let Some(start) = raw
            .windows(HEAD_END.len())
            .position(|window| window == HEAD_END)
        {
            break start.saturating_add(HEAD_END.len());
        }
        if !read_more(stream, &mut raw)? {
            return Ok(None);
        }
    };
    let head = parse_head(raw.get(..head_length).unwrap_or_default())?;
    let total = head_length
        .checked_add(head.body_length)
        .ok_or_else(|| format!("a request names an impossible length: {}", head.body_length))?;
    while raw.len() < total {
        if !read_more(stream, &mut raw)? {
            return Ok(None);
        }
    }
    raw.truncate(total);
    let body = raw.get(head_length..).unwrap_or_default().to_vec();
    Ok(Some(Request {
        method: head.method,
        target: head.target,
        headers: head.headers,
        body,
        raw,
    }))
}

/// Append what the next read brings, and report whether the connection is still open.
fn read_more(stream: &mut impl Read, raw: &mut Vec<u8>) -> Result<bool, String> {
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(count) => {
                raw.extend_from_slice(chunk.get(..count).unwrap_or_default());
                return Ok(true);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::NotConnected
                        | ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(format!("a request couldn't be read: {error}")),
        }
    }
}

/// A request's line and headers.
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body_length: usize,
}

fn parse_head(head: &[u8]) -> Result<Head, String> {
    let text = std::str::from_utf8(head)
        .map_err(|error| format!("a request head isn't UTF-8: {error}"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(format!(
            "a request line isn't `METHOD TARGET HTTP/1.1`: {request_line:?}"
        ));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(format!("a request isn't HTTP/1: {request_line:?}"));
    }
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("a header line has no colon: {line:?}"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let named = |wanted: &str| {
        headers
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.as_str())
    };
    if named("transfer-encoding").is_some() {
        return Err(format!(
            "{method} {target} has a Transfer-Encoding body, which the fake server can't read"
        ));
    }
    let body_length = named("content-length").map_or(Ok(0), |value| {
        value.parse().map_err(|error| {
            format!("{method} {target} has a Content-Length of {value:?}: {error}")
        })
    })?;
    Ok(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        body_length,
    })
}

/// The message that a panic carried.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_else(|| "a panic without a message".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{FakeServer, Reply, Response, read_more};
    use std::io::{self, ErrorKind, Read, Write};
    use std::net::TcpStream;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Fails its first read with `error`, then serves `data`.
    struct FailsFirst {
        error: Option<ErrorKind>,
        data: &'static [u8],
    }

    impl Read for FailsFirst {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(error) = self.error.take() {
                return Err(error.into());
            }
            self.data.read(buffer)
        }
    }

    #[test]
    fn a_read_that_a_signal_interrupts_is_retried() {
        let mut reader = FailsFirst {
            error: Some(ErrorKind::Interrupted),
            data: b"request",
        };
        let mut raw = Vec::new();

        assert_eq!(read_more(&mut reader, &mut raw), Ok(true));
        assert_eq!(raw, b"request");
    }

    #[test]
    fn a_reset_ends_the_connection_and_any_other_read_error_fails_the_test() {
        let mut raw = Vec::new();
        let mut reset = FailsFirst {
            error: Some(ErrorKind::ConnectionReset),
            data: b"request",
        };
        let mut denied = FailsFirst {
            error: Some(ErrorKind::PermissionDenied),
            data: b"request",
        };

        assert_eq!(read_more(&mut reset, &mut raw), Ok(false));
        let failure = read_more(&mut denied, &mut raw).unwrap_err();
        assert!(failure.contains("couldn't be read"), "{failure}");
        assert_eq!(raw, b"");
    }

    /// Send `request` on a new connection and return everything the server sends before it closes the connection.
    fn exchange(server: &FakeServer, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(server.address()).unwrap();
        stream.write_all(request).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        String::from_utf8(answer).unwrap()
    }

    /// The message that `finish` fails with.
    fn finish_failure(server: &mut FakeServer) -> String {
        let payload = catch_unwind(AssertUnwindSafe(|| server.finish())).unwrap_err();
        payload.downcast_ref::<String>().cloned().unwrap()
    }

    #[test]
    fn scripted_replies_answer_requests_in_order_and_record_them() {
        let mut server = FakeServer::start();
        server.script([
            Response::new(201)
                .header("Location", "/items/1")
                .body("created"),
            Response::new(404),
        ]);

        let created = exchange(
            &server,
            b"POST /items?kind=a HTTP/1.1\r\nAuthorization: Bearer x\r\nContent-Length: 4\r\n\r\nbody",
        );
        let missing = exchange(&server, b"GET /items/2 HTTP/1.1\r\nHost: fake\r\n\r\n");

        assert_eq!(
            created,
            "HTTP/1.1 201 \r\nLocation: /items/1\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncreated"
        );
        assert_eq!(
            missing,
            "HTTP/1.1 404 \r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        let post = &requests[0];
        assert_eq!(
            (post.method.as_str(), post.target.as_str(), post.path()),
            ("POST", "/items?kind=a", "/items")
        );
        assert_eq!(post.header("AUTHORIZATION"), Some("Bearer x"));
        assert_eq!(post.body, b"body");
        assert_eq!(
            post.text(),
            "POST /items?kind=a HTTP/1.1\r\nAuthorization: Bearer x\r\nContent-Length: 4\r\n\r\nbody"
        );
        assert_eq!(requests[1].target, "/items/2");
        assert_eq!(requests[1].body, b"");
    }

    #[test]
    fn a_request_beyond_the_script_gets_a_500_and_fails_the_finish_with_its_name() {
        let mut server = FakeServer::start();
        server.script([Response::new(204)]);

        exchange(&server, b"GET /expected HTTP/1.1\r\n\r\n");
        let extra = exchange(&server, b"DELETE /extra HTTP/1.1\r\n\r\n");

        assert!(extra.starts_with("HTTP/1.1 500 "), "{extra}");
        assert!(extra.contains("DELETE /extra"), "{extra}");
        let message = finish_failure(&mut server);
        assert!(
            message.contains("requests beyond the script, each answered with 500: 1"),
            "{message}"
        );
        assert!(
            message.contains("1. GET /expected\n  2. DELETE /extra"),
            "{message}"
        );
        assert_eq!(server.requests().len(), 2);
    }

    #[test]
    fn a_scripted_reply_that_no_request_took_fails_the_finish() {
        let mut server = FakeServer::start();
        server.script([Response::new(200), Response::new(200)]);

        exchange(&server, b"GET /only HTTP/1.1\r\n\r\n");

        let message = finish_failure(&mut server);
        assert!(
            message.contains("scripted replies never sent: 1"),
            "{message}"
        );
        assert!(message.contains("1. GET /only"), "{message}");
    }

    #[test]
    fn a_close_records_the_request_before_it_ends_the_connection_unanswered() {
        let mut server = FakeServer::start();
        server.script([Reply::Close]);

        let answer = exchange(
            &server,
            b"POST /publish HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
        );

        assert_eq!(answer, "");
        assert_eq!(server.requests()[0].body, b"abc");
        server.finish();
    }

    #[test]
    fn a_response_until_close_carries_no_length_and_ends_with_the_connection() {
        let mut server = FakeServer::start();
        server.script([Response::new(200).body("streamed").until_close()]);

        let answer = exchange(&server, b"GET /stream HTTP/1.1\r\n\r\n");

        assert_eq!(answer, "HTTP/1.1 200 \r\nConnection: close\r\n\r\nstreamed");
        server.finish();
    }

    #[test]
    fn a_handler_answers_each_request_and_its_panic_becomes_a_500_that_fails_the_finish() {
        let mut server = FakeServer::start();
        server.route(|request| {
            assert_ne!(request.path(), "/broken", "no route for {}", request.target);
            Response::new(200).body(request.target.clone()).into()
        });

        let echoed = exchange(&server, b"GET /echo?x=1 HTTP/1.1\r\n\r\n");
        let broken = exchange(&server, b"GET /broken HTTP/1.1\r\n\r\n");

        assert!(echoed.ends_with("\r\n\r\n/echo?x=1"), "{echoed}");
        assert!(broken.starts_with("HTTP/1.1 500 "), "{broken}");
        let message = finish_failure(&mut server);
        assert!(
            message.contains("the handler panicked on GET /broken"),
            "{message}"
        );
        assert!(message.contains("no route for /broken"), "{message}");
    }

    #[test]
    fn a_server_that_hangs_up_closes_each_connection_unread_and_counts_it() {
        let mut server = FakeServer::start();
        server.hang_up();

        let mut stream = TcpStream::connect(server.address()).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();

        assert_eq!(answer, b"");
        assert_eq!(server.finish(), []);
        assert_eq!(server.connections(), 1);
    }

    #[test]
    fn a_request_whose_body_arrives_after_its_head_is_recorded_whole() {
        let mut server = FakeServer::start();
        server.script([Response::new(204)]);

        let mut stream = TcpStream::connect(server.address()).unwrap();
        stream
            .write_all(b"POST /fixture HTTP/1.1\r\nContent-Length: 2\r\n\r\n")
            .unwrap();
        stream.write_all(b"{}").unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();

        assert_eq!(
            server.finish()[0].text(),
            "POST /fixture HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"
        );
    }

    #[test]
    fn finishing_counts_a_connection_that_carried_no_request() {
        let mut server = FakeServer::start();

        drop(TcpStream::connect(server.address()).unwrap());

        assert_eq!(server.finish(), []);
        assert_eq!(server.connections(), 1);
    }

    #[test]
    fn stopping_ends_a_connection_whose_request_never_completes() {
        let mut server = FakeServer::start();
        let mut stream = TcpStream::connect(server.address()).unwrap();
        stream.write_all(b"GET /stalled HTTP/1.1\r\n").unwrap();

        assert_eq!(server.finish(), []);

        // The server ends the connection whether or not it had accepted it, and a close with unread bytes resets it.
        let mut answer = Vec::new();
        match stream.read_to_end(&mut answer) {
            Ok(_) => assert_eq!(answer, b""),
            Err(error) => assert_eq!(error.kind(), ErrorKind::ConnectionReset),
        }
    }
}
