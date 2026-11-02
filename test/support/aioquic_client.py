import argparse
import asyncio
import ssl
import sys

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake_complete = asyncio.Event()
        self.stream_data_received = asyncio.Event()
        self.received_data = {}
        self.resumed = False
        self.early = False

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print("HANDSHAKE_COMPLETE", flush=True)
            self.resumed = event.session_resumed
            self.early = event.early_data_accepted
            self.handshake_complete.set()
        elif isinstance(event, StreamDataReceived):
            self.received_data.setdefault(event.stream_id, b"")
            self.received_data[event.stream_id] += event.data
            if event.end_stream:
                print(
                    f"STREAM_DATA:{self.received_data[event.stream_id].hex()}",
                    flush=True,
                )
                self.stream_data_received.set()


async def main(host, port, data_hex, alpn):
    config = QuicConfiguration(is_client=True, alpn_protocols=alpn)
    config.verify_mode = ssl.CERT_NONE

    async with connect(
        host, port, configuration=config, create_protocol=ClientProtocol
    ) as protocol:
        await asyncio.wait_for(protocol.handshake_complete.wait(), timeout=5)
        # With no data, the handshake alone: the connection closes here.
        if data_hex is None:
            return

        stream_id = protocol._quic.get_next_available_stream_id()
        protocol._quic.send_stream_data(
            stream_id, bytes.fromhex(data_hex), end_stream=True
        )
        protocol.transmit()

        try:
            await asyncio.wait_for(protocol.stream_data_received.wait(), timeout=5)
        except asyncio.TimeoutError:
            print("TIMEOUT_WAITING_FOR_RESPONSE", flush=True)


# Connects twice, sending `data_hex` on a stream each time, the second
# time with the ticket the first was given and the data in 0-RTT; prints,
# for each connection, whether it resumed and 0-RTT was taken, with what
# came back.
async def resume(host, port, data_hex, alpn):
    tickets = []
    for attempt in range(2):
        config = QuicConfiguration(is_client=True, alpn_protocols=alpn)
        config.verify_mode = ssl.CERT_NONE
        if tickets:
            config.session_ticket = tickets[-1]
        async with connect(
            host,
            port,
            configuration=config,
            create_protocol=ClientProtocol,
            session_ticket_handler=tickets.append,
            wait_connected=not tickets,
        ) as protocol:
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol._quic.send_stream_data(
                stream_id, bytes.fromhex(data_hex), end_stream=True
            )
            protocol.transmit()
            await asyncio.wait_for(protocol.stream_data_received.wait(), timeout=5)
            await asyncio.wait_for(protocol.handshake_complete.wait(), timeout=5)
            resumed = str(protocol.resumed).lower()
            early = str(protocol.early).lower()
            data = protocol.received_data[stream_id].hex()
            print(f"CONNECTION resumed={resumed} early={early} data={data}", flush=True)
            # The tickets come after the handshake.
            await asyncio.sleep(0.2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data")
    parser.add_argument("--alpn", action="append")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.resume:
        asyncio.run(resume(args.host, args.port, args.data, args.alpn))
    else:
        asyncio.run(main(args.host, args.port, args.data, args.alpn))
