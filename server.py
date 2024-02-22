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
from error_codes import Errors


IP: str = "0.0.0.0"
PORT: int = 1234


class Server:
    HOST_EMAIL = "dalalcyber@gmail.com"
    HOST_PASSWORD = "cdyu khpz hyhc poqn"

    def __init__(self, ip: str, port: int) -> None:
        try:
            self.threads: list[Thread] = []
            self.srv_sock: socket = socket(AF_INET, SOCK_STREAM)
            self.srv_sock.bind((ip, port))
            self.srv_sock.listen(20)
            self.srv_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self.lock = Lock()
        except Exception as e:
            print(f"Error: {e}")

    @staticmethod
    def handle_client(cli_sock, id, addr, lock) -> None:
        try:
            result1 = None
            result2 = None
            is_code_match1 = False
            is_code_match2 = False
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
                        if is_code_match1:
                            Server.handle_register(
                                cli_sock, request, result1, db_handler, id, addr, lock
                            )
                            is_code_match1 = False
                        else:
                            send_with_size(
                                cli_sock,
                                f"|EROR|{Errors.REGISTER_BEFORE_PASSING_EMAIL_VERIFICATION}|".encode(),
                            )  # trying to register before passing email verification
                    case "REGC":
                        result1 = Server.send_code(
                            cli_sock, request, db_handler, id, addr, lock
                        )  # (code, email)
                    case "LOGN":
                        Server.handle_login(cli_sock, request, db_handler, id, addr, lock)
                    case "VERC":
                        result2 = Server.send_code(
                            cli_sock, request, id, addr, db_handler, lock
                        )  # (code, username)
                    case "CODE":
                        if result2:
                            is_code_match2 = Server.handle_code(
                                cli_sock, request, result2[0], id, addr
                            )
                        elif result1:
                            is_code_match1 = Server.handle_code(
                                cli_sock, request, result1[0], id, addr
                            )
                        else:
                            send_with_size(
                                cli_sock,
                                f"|EROR|{Errors.SUBMIT_CODE_BEFORE_GETTING_IT}|".encode(),
                            )  # trying to submit code before getting the code
                    case "PWUP":
                        if is_code_match2:
                            (is_code_match2, result2) = Server.handle_update_password(
                                cli_sock, request, result2, id, addr, db_handler, lock
                            )
                        else:
                            send_with_size(
                                cli_sock,
                                f"|EROR|{Errors.UPDATE_PASSWORD_BEFORE_PASSING_VERIFICATION}|".encode(),
                            )  # trying to update password before passing verification
                    case _:
                        print(
                            f"The request from client: {id, addr} is not valid, closing connection..."
                        )
                        send_with_size(
                            cli_sock, f"|EROR|{Errors.INVALID_REQUEST}|".encode()
                        )  # request is not valid
        except Exception as e:
            print(
                f"Error while trying to register the new user of client: {id, addr}, {e}"
            )
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
            )  # server had problems while dealing with the request

    @staticmethod
    def handle_register(cli_sock, request, user_data, db_handler, id, addr, lock):
        try:
            request = request.split("|")
            username = request[2]
            email = user_data[1]
            password = request[3]
            if not username:
                print(
                    f"The username ({username}) received by client: {id, addr} is not a valid username"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INVALID_USERNAME}|".encode()
                )  # username is not valid
            elif not bool(
                match(r"[^@]+@[^@]+\.[^@]+", email)
            ):  # check if the email received is valid
                print(
                    f"The email ({email}) received by client: {id, addr} is not a valid email address"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INVALID_EMAIL}|".encode()
                )  # email is not a valid email address
            elif not password:
                print(
                    f"The password ({password}) received by client: {id, addr} is not valid"
                )
                send_with_size(
                    cli_sock, f"|{Errors.INVALID_PASSWORD}|".encode()
                )  # password is not valid
            elif Server.database_action(lock, db_handler.is_username_exist, username):
                print(
                    f"The username ({username}) received by client: {id, addr} is already in use"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.USERNAME_IN_USE}|".encode()
                )  # username already in use
            elif Server.database_action(lock, db_handler.is_email_exist, email):
                print(
                    f"The email ({email}) received by client: {id, addr} is already in use"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.EMAIL_IN_USE}|".encode()
                )  # email already in use
            else:
                Server.database_action(
                    lock, db_handler.save_user, username, email, password
                )
                print(f"The user {username} has successfully registered")
                send_with_size(cli_sock, f"|REGK|".encode())
        except Exception as e:
            print(
                f"Error while trying to register the new user of client: {id, addr}, {e}"
            )
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
            )  # server had problems while dealing with the request

    @staticmethod
    def handle_login(cli_sock, request, db_handler, id, addr, lock):
        try:
            request = request.split("|")
            username = request[2]
            password = request[3]
            if not Server.database_action(lock, db_handler.is_username_exist, username):
                print(
                    f"client: {id, addr} tried to login with a username that does not exist"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.USERNAME_NOT_EXIST}|".encode()
                )  # username does not exist
            elif Server.database_action(
                lock, db_handler.is_password_ok, username, password
            ):
                send_with_size(
                    cli_sock,
                    f"|LOGK|{username}|{Server.database_action(lock, db_handler.get_email, username)}|".encode(),
                )
                print(f"The user ({username}) of client: {id, addr} has logged in")
            else:
                print(
                    f"Client: {id, addr} sent an incorrect password ({password}) for user: {username}"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INCORRECT_PASSWORD}|".encode()
                )  # incorrect password
        except Exception as e:
            print(f"Error while handling the login of client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
            )  # server had problems while dealing with the request

    @staticmethod
    def send_code(cli_sock, request, id, addr, db_handler, lock):
        try:
            opcode = request.split("|")[1]
            receiver_email = request.split("|")[2]
            if not bool(
                match(r"[^@]+@[^@]+\.[^@]+", receiver_email)
            ):  # check if the email received is valid
                print(
                    f"The email ({receiver_email}) received by client: {id, addr} is not a valid email address"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INVALID_EMAIL}|".encode()
                )  # email received is not a valid email address
                return None
            message = MIMEMultipart("alternative")
            message["From"] = Server.HOST_EMAIL
            message["To"] = receiver_email
            code = str(randrange(100000, 1000000))  # 6 digit code
            if opcode == "VERC":
                username = Server.database_action(
                    lock, db_handler.get_username, receiver_email
                )
                if username is None:
                    print(
                        f"The email ({receiver_email}) received by client: {id, addr} does not appear in the user table"
                    )
                    send_with_size(
                        cli_sock, f"|EROR|{Errors.EMAIL_NOT_EXIST}|".encode()
                    )  # email received does not appear in the user table
                    return None
                message["Subject"] = "Code for a new password"
                text = f"""\
                Your code for changing the password is: {code}
                """
            else:
                message["Subject"] = "Code for registration"
                text = f"""\
                Your code for registering a new user is: {code}
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
            return (code, username) if opcode == "VERC" else (code, receiver_email)
        except Exception as e:
            print(f"Error while sending the email to client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
            )  # server had problems while dealing with the request
            return None

    @staticmethod
    def handle_code(cli_sock, request, code, id, addr) -> bool:
        try:
            client_code: str = request.split("|")[2]
            if len(client_code) != 6 or not client_code.isnumeric():
                print(f"The code received from the client is not valid")
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INVALID_CODE}|".encode()
                )  # code is not valid
                return False
            if code == client_code:
                send_with_size(cli_sock, f"|CDEK|".encode())
                return True
            send_with_size(cli_sock, f"|CDEW|".encode())
            return False
        except Exception as e:
            print(f"Error while sending the email to client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
            )  # server had problems while dealing with the request
            return False

    @staticmethod
    def handle_update_password(
        cli_sock, request, user_data, id, addr, db_handler, lock
    ) -> tuple[bool, (str, str)]:
        _, username = user_data
        password = request.split("|")[2]
        if password:
            try:
                Server.database_action(
                    lock, db_handler.update_user_password, username, password
                )
                send_with_size(cli_sock, f"|PWUK|".encode())
            except Exception as e:
                print(
                    f"Error while updating the password of client: {id, addr}, user: {username}, to password: {password}"
                )
                print(f"Error: {e}")
                send_with_size(
                    cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
                )  # server had problems while dealing with the request
            finally:
                return (False, (None, None))
        else:
            print(
                f"New password ({password}) received by client: {id, addr} is not valid"
            )
            print(f"Error: {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.INVALID_PASSWORD}|".encode()
            )  # password is not valid
            return (True, user_data)

    @staticmethod
    def database_action(lock: Lock, func: callable, *args, **kwargs):
        """
        This function prevents race condition using locks.
        In reality, this function is useless because SQLite already supports locks (but I still added this for learning purposes).
        """
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
                    target=Server.handle_client,
                    args=(cli_sock, str(i), addr, self.lock),
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
