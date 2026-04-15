import argparse
import asyncio
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived


class ServerProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print("HANDSHAKE_COMPLETE", flush=True)
        elif isinstance(event, StreamDataReceived):
            print(f"STREAM_DATA:{event.data.hex()}", flush=True)
            self._quic.send_stream_data(
                event.stream_id, b"ECHO:" + event.data, end_stream=True
            )
            self.transmit()


async def main(certfile, keyfile, port):
    config = QuicConfiguration(is_client=False)
    config.load_cert_chain(certfile, keyfile)

    server = await serve(
        "127.0.0.1",
        port,
        configuration=config,
        create_protocol=ServerProtocol,
    )
    print(f"READY:{port}", flush=True)
    await asyncio.sleep(10)
    server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--certfile", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.certfile, args.keyfile, args.port))
