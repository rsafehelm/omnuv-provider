#!/usr/bin/env python3
"""The packets the opening's hermetic test sends and waits for.

    udp.py echo PORT [LOG]            answer every UDP datagram on PORT with
                                      "echo <payload>", until killed; each
                                      sender's address appended to LOG
    udp.py tcp PORT                   accept TCP on PORT, until killed
    udp.py hear PORT SECONDS          print "heard <src ip>:<src port> <payload>"
                                      for each datagram in SECONDS, then exit
    udp.py ask HOST PORT [SPORT]      send one datagram and print the answer's
                                      source and payload, or "silence" after 2 s
    udp.py connect HOST PORT          "connected" or "refused" / "silence"

stdout is the result and nothing else; the test greps it.
"""
import socket
import sys
import time


def main():
    mode = sys.argv[1]
    if mode == "echo":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", int(sys.argv[2])))
        log = open(sys.argv[3], "a", buffering=1) if len(sys.argv) > 3 else None
        while True:
            data, src = s.recvfrom(2048)
            if log:
                log.write(f"{src[0]}:{src[1]}\n")
            s.sendto(b"echo " + data, src)
    if mode == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", int(sys.argv[2])))
        s.listen(8)
        while True:
            c, _ = s.accept()
            c.close()
    if mode == "hear":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", int(sys.argv[2])))
        end = time.monotonic() + float(sys.argv[3])
        while (left := end - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                data, src = s.recvfrom(2048)
            except socket.timeout:
                break
            print(f"heard {src[0]}:{src[1]} {data.decode(errors='replace')}", flush=True)
        return
    if mode == "ask":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if len(sys.argv) > 4:
            s.bind(("0.0.0.0", int(sys.argv[4])))
        s.settimeout(2)
        s.sendto(b"probe", (sys.argv[2], int(sys.argv[3])))
        try:
            data, src = s.recvfrom(2048)
            print(f"answer {src[0]}:{src[1]} {data.decode(errors='replace')}")
        except (socket.timeout, ConnectionRefusedError):
            print("silence")
        return
    if mode == "connect":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((sys.argv[2], int(sys.argv[3])))
            print("connected")
        except ConnectionRefusedError:
            print("refused")
        except (socket.timeout, OSError):
            print("silence")
        return
    sys.exit(f"udp.py: unknown mode {mode}")


if __name__ == "__main__":
    main()
