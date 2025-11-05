import socket, ssl, threading

HOST = "127.0.0.1"
PORT = 12345

clients = []  # keep track of connected clients

def handle_client(conn, addr):
    print(f"[+] {addr} connected.")
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            # broadcast encrypted message to all other clients
            for client in clients:
                if client != conn:
                    client.sendall(data)
        except:
            break
    conn.close()
    clients.remove(conn)
    print(f"[-] {addr} disconnected.")

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[*] Server listening on {HOST}:{PORT} with TLS...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                clients.append(conn)
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
