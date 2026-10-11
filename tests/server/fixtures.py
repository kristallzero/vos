# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 VoS contributors.

"""Local HTTP and UDP DNS endpoints; installer test needs no public network."""
import http.server
import socket
import struct
import threading

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"vos-http-ok")

threading.Thread(target=http.server.HTTPServer(("127.0.0.1", 18080), HTTP).serve_forever, daemon=True).start()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 15353))
while True:
    query, addr = udp.recvfrom(65535)
    end = 12
    while query[end]:
        end += query[end] + 1
    end += 5
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
    udp.sendto(header + query[12:end] + answer, addr)
