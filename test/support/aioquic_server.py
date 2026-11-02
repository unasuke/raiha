import argparse
import asyncio
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived


class ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received_data = {}

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print("HANDSHAKE_COMPLETE", flush=True)
            resumed = str(event.session_resumed).lower()
            early = str(event.early_data_accepted).lower()
            print(f"CONNECTION resumed={resumed} early={early}", flush=True)
        elif isinstance(event, StreamDataReceived):
            # The echo goes once the stream has ended, whatever number of
            # pieces its data came in.
            data = self.received_data.get(event.stream_id, b"") + event.data
            self.received_data[event.stream_id] = data
            if not event.end_stream:
                return
            print(f"STREAM_DATA:{data.hex()}", flush=True)
            self._quic.send_stream_data(
                event.stream_id, b"ECHO:" + data, end_stream=True
            )
            self.transmit()


async def main(certfile, keyfile, port, alpn):
    config = QuicConfiguration(is_client=False, alpn_protocols=alpn)
    config.load_cert_chain(certfile, keyfile)
    # The tickets it gives, by their bytes, so that a client may resume one
    # and send 0-RTT.
    tickets = {}

    server = await serve(
        "127.0.0.1",
        port,
        configuration=config,
        create_protocol=ServerProtocol,
        session_ticket_fetcher=lambda ticket: tickets.pop(ticket, None),
        session_ticket_handler=lambda ticket: tickets.__setitem__(ticket.ticket, ticket),
    )
    print(f"READY:{port}", flush=True)
    await asyncio.sleep(10)
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--certfile", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--alpn", action="append")
    args = parser.parse_args()
    asyncio.run(main(args.certfile, args.keyfile, args.port, args.alpn))
