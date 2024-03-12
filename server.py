from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread, Lock
from tcp_by_size import send_with_size, recv_by_size
from sys import argv
from database_handler import DataBaseHandler, EmailCodeDBHandler
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from random import randrange
from re import match
from error_codes import Errors
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import random
import math

IP: str = "0.0.0.0"
PORT: int = 1234

class Server:
    """Class implementing a server application for user registration and login."""
    HOST_EMAIL = "dalalcyber@gmail.com"
    HOST_PASSWORD = "cdyu khpz hyhc poqn"

    def __init__(self, ip: str, port: int) -> None:
        """Initialize the server with provided IP and port."""
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
    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a
    
    @staticmethod
    def is_prime(num):
        if num <= 1:
            return False
        if num == 2 or num == 3:
            return True
        if num % 2 == 0:
            return False
        for i in range(3, int(math.sqrt(num)) + 1, 2):
            if num % i == 0:
                return False
        return True
    
    @staticmethod
    def generate_prime():
        while True:
            num = random.randint(100, 1000)
            if Server.is_prime(num):
                return num

    @staticmethod
    def generate_primitive_root(prime):
        while True:
            primitive_root = random.randint(2, prime - 1)
            if pow(primitive_root, (prime - 1) // 2, prime) != 1:
                return primitive_root
            
    @staticmethod
    def generate_private_key(prime):
        return random.randint(2, prime - 1)
    
    @staticmethod
    def generate_public_key(prime, primitive_root, private_key):
        return pow(primitive_root, private_key, prime)
    
    @staticmethod
    def generate_shared_secret(public_key, private_key, prime):
        shared_secret = pow(public_key, private_key, prime)
        shared_secret_str = str(shared_secret)
        padded_shared_secret = shared_secret_str.ljust(16, '0')
        return padded_shared_secret.encode()
    
    @staticmethod
    def handle_client(cli_sock, id, addr, lock) -> None:
        """Handle individual client connections."""
        try:
            result1 = None
            result2 = None
            is_code_match1 = False
            is_code_match2 = False
            secret_key = None
            db_handler = DataBaseHandler()
            email_db_handler = EmailCodeDBHandler()
            try:
                is_crypto_ok = False
                while not is_crypto_ok:
                    crypto_system = recv_by_size(cli_sock).split("|")[1]
                    if crypto_system in ("RSA", "Diffie-Hellman"):
                        send_with_size(cli_sock, "|CSOK|".encode())
                        is_crypto_ok = True
                        if crypto_system == "RSA":
                            data = recv_by_size(cli_sock)
                            opcode = data.split("|")[1]
                            match opcode:
                                case "GKEY":
                                    private_key = rsa.generate_private_key(
                                        public_exponent=65537,
                                        key_size=2048,
                                        backend=default_backend()
                                    )
                                    public_key = private_key.public_key()
                                    public_key_pem = public_key.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    )
                                    send_with_size(cli_sock, f"|PKEY|{public_key_pem.decode()}|")
                                    encrypted_secret_key = cli_sock.recv(2048)
                                    secret_key = private_key.decrypt(
                                        encrypted_secret_key,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )
                                    print(f"AES secret key: {secret_key} (after dectyption with the private key)")
                                    send_with_size(cli_sock, f"|KEYK|".encode(), secret_key)
                                case _:
                                    print(
                                        f"The request from client: {id, addr} is not valid, closing connection..."
                                    )
                                    send_with_size(
                                        cli_sock, f"|EROR|{Errors.INVALID_REQUEST}|".encode(), secret_key
                                    )  # request is not valid
                        elif crypto_system == "Diffie-Hellman":
                            prime = Server.generate_prime()
                            primitive_root = Server.generate_primitive_root(prime)
                            private_key = Server.generate_private_key(prime)
                            public_key = Server.generate_public_key(prime, primitive_root, private_key)
                            cli_sock.sendall(str(prime).encode())
                            cli_sock.sendall(str(primitive_root).encode())
                            cli_sock.sendall(str(public_key).encode())
                            client_public_key = int(cli_sock.recv(1024).decode())
                            secret_key = Server.generate_shared_secret(client_public_key, private_key, prime)
                            print("Shared secret generated:", secret_key)
                    else:
                        send_with_size(cli_sock, "|CSNK|".encode())
            except Exception as e:
                    print(e)
                    send_with_size(
                        cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode()
                    )  # server had problems while dealing with the request
                    cli_sock.close()
            while True:
                request = recv_by_size(cli_sock, key=secret_key)
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
                                f"|EROR|{Errors.REGISTER_BEFORE_PASSING_EMAIL_VERIFICATION}|".encode(), secret_key,
                            )  # trying to register before passing email verification
                    case "REGC":
                        result1 = Server.send_code(
                            cli_sock,
                            request,
                            db_handler,
                            id,
                            addr,
                            lock,
                            email_db_handler,
                            secret_key
                        )  # (code, email)
                    case "LOGN":
                        Server.handle_login(
                            cli_sock, request, db_handler, id, addr, lock, secret_key
                        )
                    case "VERC":
                        result2 = Server.send_code(
                            cli_sock,
                            request,
                            id,
                            addr,
                            db_handler,
                            lock,
                            email_db_handler,
                            secret_key
                        )  # (code, username)
                    case "CODE":
                        if result2:
                            is_code_match2 = Server.handle_code(
                                cli_sock,
                                request,
                                result2[0],
                                id,
                                addr,
                                email_db_handler,
                                lock,
                                secret_key
                            )
                        elif result1:
                            is_code_match1 = Server.handle_code(
                                cli_sock,
                                request,
                                result1[0],
                                id,
                                addr,
                                email_db_handler,
                                lock,
                                secret_key
                            )
                        else:
                            send_with_size(
                                cli_sock,
                                f"|EROR|{Errors.SUBMIT_CODE_BEFORE_GETTING_IT}|".encode(), secret_key,
                            )  # trying to submit code before getting the code
                    case "PWUP":
                        if is_code_match2:
                            (is_code_match2, result2) = Server.handle_update_password(
                                cli_sock, request, result2, id, addr, db_handler, lock, secret_key
                            )
                        else:
                            send_with_size(
                                cli_sock,
                                f"|EROR|{Errors.UPDATE_PASSWORD_BEFORE_PASSING_VERIFICATION}|".encode(), secret_key,
                            )  # trying to update password before passing verification
                    case _:
                        print(
                            f"The request from client: {id, addr} is not valid, closing connection..."
                        )
                        send_with_size(
                            cli_sock, f"|EROR|{Errors.INVALID_REQUEST}|".encode(), secret_key
                        )  # request is not valid
        except Exception as e:
            print(
                f"Error while handling client request: {id, addr}, {e}"
            )
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode(), secret_key
            )  # server had problems while dealing with the request

    @staticmethod
    def handle_register(cli_sock, request, user_data, db_handler, id, addr, lock, secret_key):
        """Handle user registration."""
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
                    cli_sock, f"|EROR|{Errors.INVALID_USERNAME}|".encode(), secret_key
                )  # username is not valid
            elif not bool(
                match(r"[^@]+@[^@]+\.[^@]+", email)
            ):  # check if the email received is valid
                print(
                    f"The email ({email}) received by client: {id, addr} is not a valid email address"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INVALID_EMAIL}|".encode(), secret_key
                )  # email is not a valid email address
            elif not password:
                print(
                    f"The password ({password}) received by client: {id, addr} is not valid"
                )
                send_with_size(
                    cli_sock, f"|{Errors.INVALID_PASSWORD}|".encode(), secret_key
                )  # password is not valid
            elif Server.database_action(lock, db_handler.is_username_exist, username):
                print(
                    f"The username ({username}) received by client: {id, addr} is already in use"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.USERNAME_IN_USE}|".encode(), secret_key
                )  # username already in use
            elif Server.database_action(lock, db_handler.is_email_exist, email):
                print(
                    f"The email ({email}) received by client: {id, addr} is already in use"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.EMAIL_IN_USE}|".encode(), secret_key
                )  # email already in use
            else:
                Server.database_action(
                    lock, db_handler.save_user, username, email, password
                )
                print(f"The user {username} has successfully registered")
                send_with_size(cli_sock, f"|REGK|".encode(), secret_key)
        except Exception as e:
            print(
                f"Error while trying to register the new user of client: {id, addr}, {e}"
            )
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode(), secret_key
            )  # server had problems while dealing with the request

    @staticmethod
    def handle_login(cli_sock, request, db_handler, id, addr, lock, secret_key):
        """Handle user login."""
        try:
            request = request.split("|")
            username = request[2]
            password = request[3]
            if not Server.database_action(lock, db_handler.is_username_exist, username):
                print(
                    f"client: {id, addr} tried to login with a username that does not exist"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.USERNAME_NOT_EXIST}|".encode(), secret_key
                )  # username does not exist
            elif Server.database_action(
                lock, db_handler.is_password_ok, username, password
            ):
                send_with_size(
                    cli_sock,
                    f"|LOGK|{username}|{Server.database_action(lock, db_handler.get_email, username)}|".encode(), secret_key,
                )
                print(f"The user ({username}) of client: {id, addr} has logged in")
            else:
                print(
                    f"Client: {id, addr} sent an incorrect password ({password}) for user: {username}"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INCORRECT_PASSWORD}|".encode(), secret_key
                )  # incorrect password
        except Exception as e:
            print(f"Error while handling the login of client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode(), secret_key
            )  # server had problems while dealing with the request

    @staticmethod
    def send_code(cli_sock, request, id, addr, db_handler, lock, email_db_handler, secret_key):
        """Send verification code to the provided email."""
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
                    cli_sock, f"|EROR|{Errors.INVALID_EMAIL}|".encode(), secret_key
                )  # email received is not a valid email address
                return None
            message = MIMEMultipart("alternative")
            message["From"] = Server.HOST_EMAIL
            message["To"] = receiver_email
            code = str(randrange(100000, 1000000))  # 6 digits code
            if opcode == "VERC":
                username = Server.database_action(
                    lock, db_handler.get_username, receiver_email
                )
                if username is None:
                    print(
                        f"The email ({receiver_email}) received by client: {id, addr} does not appear in the user table"
                    )
                    send_with_size(
                        cli_sock, f"|EROR|{Errors.EMAIL_NOT_EXIST}|".encode(), secret_key
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
            if Server.database_action(
                lock, email_db_handler.is_email_exist, receiver_email
            ):
                Server.database_action(
                    lock, email_db_handler.delete_email, receiver_email
                )
            Server.database_action(lock, email_db_handler.save_email, receiver_email)
            send_with_size(cli_sock, f"|SNTC|".encode(), secret_key)
            return (code, username) if opcode == "VERC" else (code, receiver_email)
        except Exception as e:
            print(f"Error while sending the email to client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode(), secret_key
            )  # server had problems while dealing with the request
            return None

    @staticmethod
    def handle_code(cli_sock, request, code, id, addr, email_db_handler, lock, secret_key) -> bool:
        """Handle verification code sent by the client."""
        try:
            email: str = request.split("|")[3]
            if not Server.database_action(lock, email_db_handler.is_email_exist, email):
                print(
                    f"The email ({email}) received by client: {id, addr} does not appear in the emails table"
                )
                send_with_size(
                    cli_sock, f"|EROR|{Errors.EMAIL_NOT_EXIST}|".encode(), secret_key
                )  # email received does not appear in the emails table
                return False
            if Server.database_action(lock, email_db_handler.is_timeout_passed, email):
                print(f"The code sent to client: {id, addr} has expired")
                send_with_size(
                    cli_sock, f"|EROR|{Errors.CODE_EXPIRED}|".encode(), secret_key
                )  # The code has expired
                Server.database_action(lock, email_db_handler.delete_email, email)
                return False
            client_code: str = request.split("|")[2]
            print(code, client_code)
            if len(client_code) != 6 or not client_code.isnumeric():
                print(f"The code received from the client is not valid")
                send_with_size(
                    cli_sock, f"|EROR|{Errors.INVALID_CODE}|".encode(), secret_key
                )  # code is not valid
                return False
            if code == client_code:
                send_with_size(cli_sock, f"|CDEK|".encode(), secret_key)
                Server.database_action(lock, email_db_handler.delete_email, email)
                return True
            send_with_size(cli_sock, f"|CDEW|".encode(), secret_key)
            return False
        except Exception as e:
            print(f"Error while verifying the code of client: {id, addr}, {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode(), secret_key
            )  # server had problems while dealing with the request
            return False

    @staticmethod
    def handle_update_password(
        cli_sock, request, user_data, id, addr, db_handler, lock, secret_key
    ) -> tuple[bool, (str, str)]:
        """Handle updating user password."""
        _, username = user_data
        password = request.split("|")[2]
        if password:
            try:
                Server.database_action(
                    lock, db_handler.update_user_password, username, password
                )
                send_with_size(cli_sock, f"|PWUK|".encode(), secret_key)
            except Exception as e:
                print(
                    f"Error while updating the password of client: {id, addr}, user: {username}, to password: {password}"
                )
                print(f"Error: {e}")
                send_with_size(
                    cli_sock, f"|EROR|{Errors.SERVER_ERROR}|".encode(), secret_key
                )  # server had problems while dealing with the request
            finally:
                return (False, (None, None))
        else:
            print(
                f"New password ({password}) received by client: {id, addr} is not valid"
            )
            print(f"Error: {e}")
            send_with_size(
                cli_sock, f"|EROR|{Errors.INVALID_PASSWORD}|".encode(), secret_key
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
        """Run the server application."""
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
