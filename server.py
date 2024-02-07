from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread
from tcp_by_size import send_with_size, recv_by_size
from sys import argv

IP: str = "0.0.0.0"
PORT: int = 1234


class Server:
    def __init__(self, ip: str, port: int) -> None:
        """Initialize the Server object."""
        self.threads: list[Thread] = []
        self.srv_sock: socket = socket(AF_INET, SOCK_STREAM)
        self.srv_sock.bind((ip, port))
        self.srv_sock.listen(20)
        self.srv_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    @staticmethod
    def handle_client(cli_sock, id, addr) -> None:
        request = recv_by_size(cli_sock)
        if not request:
            print(
                f"Error receiving data from client: {id, addr}, closing connection..."
            )
            cli_sock.close()
            return
        opcode = request.split("|")[1]
        match opcode:
            case "REGS":
                Server.handle_register(cli_sock, request)
            case "LOGN":
                Server.handle_login(cli_sock, request)
            case "FRGP":
                Server.handle_forgot_password(cli_sock, request)
            case _:
                print(
                    f"The request from client: {id, addr} is not valid, closing connection..."
                )
                cli_sock.close()
                return

    @staticmethod
    def handle_register(cli_sock, request):
        pass

    @staticmethod
    def handle_login(cli_sock, request):
        pass

    @staticmethod
    def handle_forgot_password(cli_sock, request):
        pass

    def run(self) -> None:
        """Run the server application.

        Returns:
            None
        """
        i = 1
        try:
            print("\nMain thread: starting to accept...")
            while True:
                cli_sock, addr = self.srv_sock.accept()
                t: Thread = Thread(
                    target=Server.handle_client, args=(cli_sock, str(i), addr)
                )
                t.start()
                i += 1
                self.threads.append(t)
                if i > 100000000:
                    print("\nMain thread: going down for maintenance")
                    break
        except KeyboardInterrupt:
            print("\nMain thread: received keyboard interrupt. Shutting down...")
        except socket.error as se:
            print(f"\nMain thread: encountered socket error: {se}")
        except Exception as e:
            print(f"\nMain thread: encountered an unexpected error: {e}")
        finally:
            print("Main thread: waiting for all clients to die")
            for t in self.threads:
                try:
                    t.join()
                except Exception as e:
                    print(f"Error joining thread: {e}")
            self.srv_sock.close()


if __name__ == "__main__":
    if len(argv) == 3:
        ip = argv[1]
        port = int(argv[2])
        s = Server(ip, port)
        s.run()
    else:
        # print("Usage: python server.py <ip> <port>")
        s = Server(IP, PORT)
        s.run()
