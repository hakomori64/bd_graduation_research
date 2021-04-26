import socket

def recvAll(sock):
  full_msg = b''
  while True:
    msg = sock.recv(4096)
    if len(msg) <= 0:
      break
    full_msg += msg
  
  return full_msg

