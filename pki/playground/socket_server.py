import socket
import struct

host = '127.0.0.1'
port = 8765
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main():
  sock.bind((host, port))
  sock.listen()

  while True:
    print("waiting client...")

    connection, address = sock.accept()
    print('client info:', str(address))

    recvline = ''
    sendline = ''
    num = 0

    try:
      recvline = recvAll(connection)
      print(recvline)
      print()

      connection.send("Hello".encode('utf-8'))

      recvline = recvAll(connection)
      print(recvline)
      print()
    finally:
      connection.close()

  socket.close()

def recvAll(sock):
  full_msg = b''
  while True:
    msg = sock.recv(4096)
    full_msg += msg
    if len(msg) <= 4096:
      break
  
  return full_msg

if __name__ == '__main__':
  main()