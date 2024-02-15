from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread, Lock
from tcp_by_size import send_with_size, recv_by_size
from sys import argv
from database_handler import DataBaseHandler
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from random import randrange
from re import match

IP: str = "0.0.0.0"
PORT: int = 1234


class Server:
    HOST_EMAIL = "dalalcyber@gmail.com"
    HOST_PASSWORD = "cdyu khpz hyhc poqn"

    def __init__(self, ip: str, port: int) -> None:
        """Initialize the Server object."""
        self.threads: list[Thread] = []
        self.srv_sock: socket = socket(AF_INET, SOCK_STREAM)
        self.srv_sock.bind((ip, port))
        self.srv_sock.listen(20)
        self.srv_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.lock = Lock()

    @staticmethod
    def handle_client(cli_sock, id, addr, lock) -> None:
        result = None
        is_code_match = False
        db_handler = DataBaseHandler()
        while True:
            request = recv_by_size(cli_sock)
            if not request:
                print(
                    f"Error while receiving data from client: {id, addr}, closing connection..."
                )
                cli_sock.close()
                break
            opcode = request.split("|")[1]
            match opcode:
                case "REGS":
                    Server.handle_register(cli_sock, request, db_handler, id, addr, lock)
                case "LOGN":
                    Server.handle_login(cli_sock, request, db_handler, id, addr, lock)
                case "FRGP":
                    result = Server.handle_forgot_password(
                        cli_sock, request, id, addr, db_handler, lock
                    )  # (code, username)
                case "CODE":
                    if result:
                        is_code_match = Server.handle_password_code(
                            cli_sock, request, result[0]
                        )
                    else:
                        send_with_size(
                            cli_sock, f"|EROR|2|".encode()
                        )  # trying to submit code before getting the code
                case "PWUP":
                    if is_code_match:
                        (is_code_match, result) = Server.handle_update_password(
                            cli_sock, request, result, id, addr, db_handler, lock
                        )
                    else:
                        send_with_size(
                            cli_sock, f"|EROR|6|".encode()
                        )  # trying to update password before passing verification
                case _:
                    print(
                        f"The request from client: {id, addr} is not valid, closing connection..."
                    )
                    send_with_size(
                        cli_sock, f"|EROR|8|".encode()
                    )  # request is not valid

    @staticmethod
    def handle_register(cli_sock, request, db_handler, id, addr, lock):
        try:
            request = request.split("|")
            username = request[2]
            email = request[3]
            password = request[4]
            if not username:
                print(
                    f"The username ({username}) received by client: {id, addr} is not a valid username"
                )
                send_with_size(cli_sock, f"|EROR|9|".encode())  # username is not valid
            elif not bool(
                match(r"[^@]+@[^@]+\.[^@]+", email)
            ):  # check if the email received is valid
                print(
                    f"The email ({email}) received by client: {id, addr} is not a valid email address"
                )
                send_with_size(
                    cli_sock, f"|EROR|4|".encode()
                )  # email is not a valid email address
            elif not password:
                print(
                    f"The password ({password}) received by client: {id, addr} is not valid"
                )
                send_with_size(cli_sock, f"|EROR|3|".encode())  # password is not valid
            elif Server.database_action(lock, db_handler.is_username_exist, username):
                print(
                    f"The username ({username}) received by client: {id, addr} is already in use"
                )
                send_with_size(
                    cli_sock, f"|EROR|10|".encode()
                )  # username already in use
            elif Server.database_action(lock, db_handler.is_email_exist, email):
                print(
                    f"The email ({email}) received by client: {id, addr} is already in use"
                )
                send_with_size(cli_sock, f"|EROR|11|".encode())  # email already in use
            else:
                Server.database_action(lock, db_handler.save_user, username, email, password)
                print(f"The user {username} has successfully registered")
                send_with_size(cli_sock, f"|REGK|".encode())
        except Exception as e:
            print(
                f"Error while trying to register the new user of client: {id, addr}, {e}"
            )
            send_with_size(
                cli_sock, f"|EROR|1|".encode()
            )  # server had problems while dealing with the request

    @staticmethod
    def handle_login(cli_sock, request, db_handler, id, addr, lock):
        request = request.split("|")
        username = request[2]
        password = request[3]
        if not Server.database_action(lock, db_handler.is_username_exist, username):
            print(
                f"client: {id, addr} tried to login with a username that does not exist"
            )
            send_with_size(cli_sock, f"|EROR|12|".encode())  # username does not exist
        elif Server.database_action(lock, db_handler.is_password_ok, username, password):
            send_with_size(
                cli_sock, f"|LOGK|{username}|{Server.database_action(lock, db_handler.get_email, username)}|".encode()
            )
            print(f"The user ({username}) of client: {id, addr} has logged in")
        else:
            print(
                f"Client: {id, addr} sent an incorrect password ({password}) for user: {username}"
            )
            send_with_size(cli_sock, f"|EROR|13|".encode())  # incorrect password

    @staticmethod
    def handle_forgot_password(cli_sock, request, id, addr, db_handler, lock):
        try:
            receiver_email = request.split("|")[2]
            if not bool(
                match(r"[^@]+@[^@]+\.[^@]+", receiver_email)
            ):  # check if the email received is valid
                print(
                    f"The email ({receiver_email}) received by client: {id, addr} is not a valid email address"
                )
                send_with_size(
                    cli_sock, f"|EROR|4|".encode()
                )  # email received is not a valid email address
                return None
            username = Server.database_action(lock, db_handler.get_username, receiver_email)
            if username is None:
                print(
                    f"The email ({receiver_email}) received by client: {id, addr} does not appear in the user table"
                )
                send_with_size(
                    cli_sock, f"|EROR|7|".encode()
                )  # email received does not appear in the user table
                return None
            message = MIMEMultipart("alternative")
            message["Subject"] = "Code for a new password"
            message["From"] = Server.HOST_EMAIL
            message["To"] = receiver_email
            code = str(randrange(100000, 1000000))  # 6 digit code
            text = f"""\
            Your code for changing the password is: {code}
            """
            message.attach(MIMEText(text, "plain"))
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(Server.HOST_EMAIL, Server.HOST_PASSWORD)
                server.sendmail(Server.HOST_EMAIL, receiver_email, message.as_string())
            print(
                f"Email was sent successfully from {Server.HOST_EMAIL} to {receiver_email}"
            )
            send_with_size(cli_sock, f"|SNTC|".encode())
            return (code, username)
        except Exception as e:
            print(f"Error while sending the email to client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|1|".encode()
            )  # server had problems while dealing with the request
            return None

    @staticmethod
    def handle_password_code(cli_sock, request, code) -> bool:
        client_code: str = request.split("|")[2]
        if len(client_code) != 6 or not client_code.isnumeric():
            print(f"The code received from the client is not valid")
            send_with_size(cli_sock, f"|EROR|5|".encode())  # code is not valid
            return False
        if code == client_code:
            send_with_size(cli_sock, f"|CDEK|".encode())
            return True
        send_with_size(cli_sock, f"|CDEW|".encode())
        return False

    @staticmethod
    def handle_update_password(
        cli_sock, request, user_data, id, addr, db_handler, lock
    ) -> tuple[bool, (str, str)]:
        _, username = user_data
        password = request.split("|")[2]
        if password:
            try:
                Server.database_action(lock, db_handler.update_user_password, username, password)
                send_with_size(cli_sock, f"|PWUK|".encode())
            except Exception as e:
                print(
                    f"Error while updating the password of client: {id, addr}, user: {username}, to password: {password}"
                )
                print(f"Error: {e}")
                send_with_size(
                    cli_sock, f"|EROR|1|".encode()
                )  # server had problems while dealing with the request
            finally:
                return (False, (None, None))
        else:
            print(
                f"New password ({password}) received by client: {id, addr} is not valid"
            )
            print(f"Error: {e}")
            send_with_size(cli_sock, f"|EROR|3|".encode())  # password is not valid
            return (True, user_data)
    
    @staticmethod
    def database_action(lock: Lock, func: callable, *args, **kwargs):
        '''
        This function prevents race condition using locks.
        In reality, this function is useless because SQLite already supports locks (but I still added this for learning purposes).
        '''
        with lock:
            return func(*args, **kwargs)

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
                    target=Server.handle_client, args=(cli_sock, str(i), addr, self.lock)
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
