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

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print("HANDSHAKE_COMPLETE", flush=True)
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


async def main(host, port, data_hex):
    config = QuicConfiguration(is_client=True)
    config.verify_mode = ssl.CERT_NONE

    async with connect(
        host, port, configuration=config, create_protocol=ClientProtocol
    ) as protocol:
        await asyncio.wait_for(protocol.handshake_complete.wait(), timeout=5)

        stream_id = protocol._quic.get_next_available_stream_id()
        protocol._quic.send_stream_data(
            stream_id, bytes.fromhex(data_hex), end_stream=True
        )
        protocol.transmit()

        try:
            await asyncio.wait_for(protocol.stream_data_received.wait(), timeout=5)
        except asyncio.TimeoutError:
            print("TIMEOUT_WAITING_FOR_RESPONSE", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data", required=True)
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port, args.data))
