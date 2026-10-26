import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
start = time.time()
try:
    s.connect(('127.0.0.1', 6653))
    print("Connected in", time.time() - start)
    s.sendall(b'\x01\x00\x00\x08\x00\x00\x00\x01') # OF 1.0 HELLO
    data = s.recv(1024)
    print("Received:", data)
except Exception as e:
    print("Error:", e)
finally:
    s.close()
