#!/usr/bin/env python3
"""Exercise -M through the UDP listener and validate the resulting capture.

Run after building: python3 scripts/test-pcap-datagrams.py ./src/sflowtool
"""
import os
import select
import socket
import struct
import subprocess
import sys
import time


def read_exact(stream, size):
    result = bytearray()
    deadline = time.monotonic() + 5
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise AssertionError("timed out reading sflowtool capture")
        data = os.read(stream.fileno(), size - len(result))
        if not data:
            raise AssertionError("sflowtool closed its output unexpectedly")
        result.extend(data)
    return bytes(result)


def datagram(ipv6, samples):
    agent = struct.pack("!I", 2) + socket.inet_pton(socket.AF_INET6, "::1") if ipv6 else struct.pack("!II", 1, 0x7f000001)
    header = struct.pack("!I", 5) + agent + struct.pack("!IIII", 0, 1, 1000, samples)
    # A valid flow sample with no records: sequence, source, rate, pool,
    # drops, input, output and record count.
    flow = struct.pack("!IIIIIIII", 1, 1, 1, 1, 0, 0, 0, 0)
    return header + (struct.pack("!II", 1, len(flow)) + flow) * samples


def main(binary):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind(("127.0.0.1", 0))
        port = sender.getsockname()[1]
    proc = subprocess.Popen([binary, "-4", "-b", "127.0.0.1", "-p", str(port), "-M"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        header = read_exact(proc.stdout, 24)
        order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[header[:4]]
        assert struct.unpack(order + "I", header[20:24])[0] == 1, "capture must use Ethernet framing"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for ipv6, samples in ((False, 0), (False, 1), (True, 1), (False, 2)):
                payload = datagram(ipv6, samples)
                sender.sendto(payload, ("127.0.0.1", port))
                ts_sec, ts_usec, caplen, original_len = struct.unpack(order + "IIII", read_exact(proc.stdout, 16))
                packet = read_exact(proc.stdout, caplen)
                assert ts_sec > 0 and ts_usec < 1000000
                assert caplen == original_len == 14 + 20 + 8 + len(payload)
                assert packet[12:14] == b"\x08\x00"
                ip = packet[14:34]
                assert ip[0] == 0x45 and ip[9] == 17
                assert struct.unpack("!H", ip[2:4])[0] == len(packet) - 14
                sport, dport, udp_len, checksum = struct.unpack("!HHHH", packet[34:42])
                assert sport == dport == 6343 and checksum == 0
                assert udp_len == len(packet) - 34, (udp_len, len(packet) - 34)
                # A consumer obeying the UDP length must see the entire sFlow datagram.
                assert packet[42:34 + udp_len] == payload
        print("PASS: four UDP datagrams retained completely in -M capture")
    finally:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "./src/sflowtool")
