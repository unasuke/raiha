"""Decodes a file of the QPACK Offline Interop with ls-qpack (pylsqpack).

Usage: pylsqpack_decode.py FILE MAX_TABLE_CAPACITY BLOCKED_STREAMS

The file is a sequence of blocks: a stream ID (8 octets), a length (4
octets) and that many octets; stream 0 is the encoder stream. Prints one
JSON object: each stream ID with the header list its section decoded to,
names and values in hex, or {"error": "..."} when ls-qpack refuses one.
"""

import json
import struct
import sys

import pylsqpack


def main():
    path, capacity, blocked = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    data = open(path, "rb").read()
    decoder = pylsqpack.Decoder(capacity, blocked)
    lists = {}
    offset = 0
    try:
        while offset < len(data):
            stream_id, length = struct.unpack_from(">QI", data, offset)
            octets = data[offset + 12 : offset + 12 + length]
            offset += 12 + length
            if stream_id == 0:
                decoder.feed_encoder(octets)
            else:
                _, headers = decoder.feed_header(stream_id, octets)
                lists[str(stream_id)] = [[name.hex(), value.hex()] for name, value in headers]
    except Exception as error:  # what ls-qpack refuses, reported to the test
        print(json.dumps({"error": "%s: %s" % (type(error).__name__, error)}))
        return
    print(json.dumps(lists))


if __name__ == "__main__":
    main()
