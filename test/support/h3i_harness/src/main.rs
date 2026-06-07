// Conformance test harness for the raiha HTTP/3 server, built on h3i.
//
// Usage: h3i_harness <case> <host:port>
//
// Connects to the given server, runs the actions of the named test case,
// and prints the resulting ConnectionSummary as a single JSON line to
// stdout. Exits 0 when a summary was produced (even if the peer reported
// an error -- judging conformance is the Ruby test's job), 1 on client
// errors or invalid arguments.

const H3_NO_ERROR: u64 = 0x100;

fn main() {
    let mut args = std::env::args().skip(1);
    let (case, host_port) = match (args.next(), args.next()) {
        (Some(case), Some(host_port)) => (case, host_port),
        _ => {
            eprintln!("usage: h3i_harness <case> <host:port>");
            std::process::exit(1);
        },
    };

    let actions = match build_case(&case) {
        Some(actions) => actions,
        None => {
            eprintln!("unknown test case: {case}");
            std::process::exit(1);
        },
    };

    let config = h3i::config::Config::new()
        .with_host_port(host_port.clone())
        .with_connect_to(host_port)
        .verify_peer(false)
        .with_idle_timeout(5000)
        .build()
        .expect("failed to build h3i config");

    match h3i::client::sync_client::connect(config, actions, None) {
        Ok(summary) => {
            println!(
                "{}",
                serde_json::to_string(&summary).expect("failed to serialize summary")
            );
        },
        Err(error) => {
            eprintln!("h3i client error: {error:?}");
            std::process::exit(1);
        },
    }
}

fn build_case(case: &str) -> Option<Vec<h3i::actions::h3::Action>> {
    match case {
        // A plain GET request. The server is expected to respond with a
        // 200 HEADERS frame.
        "get_200" => Some(vec![
            h3i::actions::h3::send_headers_frame(0, true, request_headers()),
            wait_for_headers(0),
            connection_close(),
        ]),
        _ => None,
    }
}

fn request_headers() -> Vec<h3i::quiche::h3::Header> {
    vec![
        h3i::quiche::h3::Header::new(b":method", b"GET"),
        h3i::quiche::h3::Header::new(b":scheme", b"https"),
        h3i::quiche::h3::Header::new(b":authority", b"127.0.0.1"),
        h3i::quiche::h3::Header::new(b":path", b"/test"),
    ]
}

fn wait_for_headers(stream_id: u64) -> h3i::actions::h3::Action {
    h3i::actions::h3::Action::Wait {
        wait_type: h3i::actions::h3::WaitType::StreamEvent(h3i::actions::h3::StreamEvent {
            stream_id,
            event_type: h3i::actions::h3::StreamEventType::Headers,
        }),
    }
}

fn connection_close() -> h3i::actions::h3::Action {
    h3i::actions::h3::Action::ConnectionClose {
        error: h3i::quiche::ConnectionError {
            is_app: true,
            error_code: H3_NO_ERROR,
            reason: vec![],
        },
    }
}
