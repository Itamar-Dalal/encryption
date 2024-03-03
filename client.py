import tkinter as tk
from tkinter import font, messagebox
from socket import socket, AF_INET, SOCK_STREAM
from tcp_by_size import send_with_size, recv_by_size
from sys import argv, exit
from re import match
from error_codes import Errors


IP = "127.0.0.1"
PORT = 1234


def close_window(func):
    """
    A decorator function to handle closing windows.

    Args:
        func (function): The function to be wrapped.

    Returns:
        function: The wrapped function.
    """
    try:
        def wrapper(self, *args, **kwargs):
            if self.running_window:
                self.running_window.destroy()
            result = func(self, *args, **kwargs)
            return result

        return wrapper
    except Exception as e:
        print(f"Error: {e}")


class Client:
    """
    A class representing a client for a user login system.

    Attributes:
        width (int): The width of the GUI windows.
        height (int): The height of the GUI windows.
        ip (str): The IP address of the server.
        port (int): The port number of the server.
        cli_sock (socket): The client socket for communication.
        running_window (tk.Tk): The currently running window.
        username (str): The username of the user.
        password (str): The password of the user.
        verify_password (str): The verification of the password.
        email (str): The email address of the user.
        forgot_password_email (str): The email address for forgotten password recovery.
    """
    def __init__(self, ip, port, width=350, height=250):
        """
        Initializes the Client class.

        Args:
            ip (str): The IP address of the server.
            port (int): The port number of the server.
            width (int, optional): The width of the GUI windows. Defaults to 350.
            height (int, optional): The height of the GUI windows. Defaults to 250.
        """
        try:
            self.width = width
            self.height = height
            self.ip = ip
            self.port = port
            self.cli_sock = socket(AF_INET, SOCK_STREAM)
            self.running_window = None
            self.username = None
            self.password = None
            self.verify_password = None
            self.email = None
            self.forgot_password_email = None
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_home(self):
        """
        Initializes the home window.

        This function sets up the home window with options to either register or login.
        """
        try:
            self.home_window = tk.Tk()
            self.running_window = self.home_window
            self.home_window.attributes('-topmost',True)
            self.home_window.title("Home")
            self.home_window.geometry(f"{self.width}x{self.height}")
            self.home_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=16, weight="bold")
            header_label = tk.Label(
                self.home_window,
                text="User Login - Itamar Dalal",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            )
            header_label.pack(pady=20, padx=10, ipadx=10, ipady=5)
            self.button_style = {
                "bg": "#46516e",
                "fg": "white",
                "borderwidth": 0,
                "activebackground": "#2980B9",
                "activeforeground": "white",
            }
            register_button = tk.Button(
                self.home_window,
                text="Open Register Window",
                command=self.init_register,
                **self.button_style,
            )
            register_button.pack(pady=20, padx=10, ipadx=10, ipady=5)
            login_button = tk.Button(
                self.home_window,
                text="Open Login Window",
                command=self.init_login,
                **self.button_style,
            )
            login_button.pack(pady=20, padx=10, ipadx=10, ipady=5)
            self.home_window.mainloop()
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_register(self, err=None):
        """
        Initializes the register window.

        This function sets up the register window with fields for username, email, password, and verification of password.

        Args:
            err (str, optional): Error message to display, if any. Defaults to None.
        """
        try:
            if err:
                messagebox.showerror("Register Error", err)
            self.register_window = tk.Tk()
            self.running_window = self.register_window
            self.register_window.attributes('-topmost',True)
            self.register_window.title("Register")
            self.register_window.geometry(f"300x480")
            self.register_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            tk.Label(
                self.register_window,
                text="Register",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            labels = ["Username:", "Email Address:", "Password:", "Verify password:"]
            self.register_entries = [
                tk.Entry(
                    self.register_window,
                    bg="#46516e",
                    fg="#E0E6F0",
                    show="*" if label in ("Password:", "Verify password:") else None,
                )
                for label in labels
            ]
            for label, entry in zip(labels, self.register_entries):
                tk.Label(self.register_window, text=label, bg="#1E2533", fg="#E0E6F0").pack(
                    pady=5
                )
                entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
            register_button = tk.Button(
                self.register_window,
                text="Register",
                command=self.register,
                **self.button_style,
            )
            register_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            home_button = tk.Button(
                self.register_window,
                text="Return Home",
                command=self.init_home,
                **self.button_style,
            )
            home_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_login(self, err=None):
        """
        Initializes the login window.

        This function sets up the login window with fields for username and password.

        Args:
            err (str, optional): Error message to display, if any. Defaults to None.
        """
        try:
            if err:
                messagebox.showerror("Login Error", err)
            self.login_window = tk.Tk()
            self.running_window = self.login_window
            self.login_window.attributes('-topmost',True)
            self.login_window.title("Login")
            self.login_window.geometry(f"300x380")
            self.login_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            tk.Label(
                self.login_window,
                text="Login",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            labels = ["Username:", "Password:"]
            self.login_entries = [
                tk.Entry(
                    self.login_window,
                    bg="#46516e",
                    fg="#E0E6F0",
                    show="*" if label == "Password:" else None,
                )
                for label in labels
            ]
            for label, entry in zip(labels, self.login_entries):
                tk.Label(self.login_window, text=label, bg="#1E2533", fg="#E0E6F0").pack(
                    pady=5
                )
                entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
            login_button = tk.Button(
                self.login_window,
                text="Login",
                command=self.login_user,
                **self.button_style,
            )
            login_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            forgot_password_button = tk.Button(
                self.login_window,
                text="Forgot Password",
                command=self.init_forgot_password,
                **self.button_style,
            )
            forgot_password_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            home_button = tk.Button(
                self.login_window,
                text="Return Home",
                command=self.init_home,
                **self.button_style,
            )
            home_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_forgot_password(self, err=None):
        """
        Initializes the forgot password window.

        This function sets up the forgot password window with field for email address.

        Args:
            err (str, optional): Error message to display, if any. Defaults to None.
        """
        try:
            if err:
                messagebox.showerror("Forgot Password Error", err)
            self.forgot_password_window = tk.Tk()
            self.running_window = self.forgot_password_window
            self.forgot_password_window.attributes('-topmost',True)
            self.forgot_password_window.title("Forgot Password")
            self.forgot_password_window.geometry(f"300x280")
            self.forgot_password_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            tk.Label(
                self.forgot_password_window,
                text="Forgot Password",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            tk.Label(
                self.forgot_password_window,
                text="Email Address:",
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=5)
            self.email_entry = tk.Entry(
                self.forgot_password_window, bg="#46516e", fg="#E0E6F0"
            )
            self.email_entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
            send_email_button = tk.Button(
                self.forgot_password_window,
                text="Send Email",
                command=self.forgot_password,
                **self.button_style,
            )
            send_email_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            login_button = tk.Button(
                self.forgot_password_window,
                text="Return To Login",
                command=self.init_login,
                **self.button_style,
            )
            login_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_password_code(self, err=None):
        """
        Initializes the password code window.

        This function sets up the password code window with field for entering code.

        Args:
            err (str, optional): Error message to display, if any. Defaults to None.
        """
        try:
            if err:
                messagebox.showerror("Password Code Error", err)
            self.password_code_window = tk.Tk()
            self.running_window = self.password_code_window
            self.password_code_window.attributes('-topmost',True)
            self.password_code_window.title("Password Code")
            self.password_code_window.geometry(f"300x310")
            self.password_code_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            tk.Label(
                self.password_code_window,
                text="Code for password update",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            tk.Label(
                self.password_code_window,
                text="Code:",
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=5)
            self.password_code_entry = tk.Entry(
                self.password_code_window, bg="#46516e", fg="#E0E6F0"
            )
            self.password_code_entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
            submit_code_button = tk.Button(
                self.password_code_window,
                text="Submit",
                command=self.password_code,
                **self.button_style,
            )
            submit_code_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            send_again_button = tk.Button(
                self.password_code_window,
                text="Send Email Again",
                command=self.forgot_password,
                **self.button_style,
            )
            send_again_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            forgot_password_button = tk.Button(
                self.password_code_window,
                text="Return To Forgot Password",
                command=self.init_forgot_password,
                **self.button_style,
            )
            forgot_password_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_register_code(self, err=None):
        """
        Initializes the register code window.

        This function sets up the register code window with field for entering code.

        Args:
            err (str, optional): Error message to display, if any. Defaults to None.
        """
        try:
            if err:
                messagebox.showerror("Register Code Error", err)
            self.register_code_window = tk.Tk()
            self.running_window = self.register_code_window
            self.register_code_window.attributes('-topmost',True)
            self.register_code_window.title("Register Code")
            self.register_code_window.geometry(f"300x310")
            self.register_code_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            tk.Label(
                self.register_code_window,
                text="Code for user registration",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            tk.Label(
                self.register_code_window,
                text="Code:",
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=5)
            self.register_code_entry = tk.Entry(
                self.register_code_window, bg="#46516e", fg="#E0E6F0"
            )
            self.register_code_entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
            submit_code_button = tk.Button(
                self.register_code_window,
                text="Submit",
                command=self.register_code,
                **self.button_style,
            )
            submit_code_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            send_again_button = tk.Button(
                self.register_code_window,
                text="Send Email Again",
                command=self.verify_email,
                **self.button_style,
            )
            send_again_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            register_button = tk.Button(
                self.register_code_window,
                text="Return To Register",
                command=self.init_register,
                **self.button_style,
            )
            register_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_update_password(self, err=None):
        """
        Initializes the update password window.

        This function sets up the update password window with field for entering new password.

        Args:
            err (str, optional): Error message to display, if any. Defaults to None.
        """
        try:
            if err:
                messagebox.showerror("Update Password Error", err)
            self.update_password_window = tk.Tk()
            self.running_window = self.update_password_window
            self.update_password_window.attributes('-topmost',True)
            self.update_password_window.title("Update Password")
            self.update_password_window.geometry(f"300x280")
            self.update_password_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            tk.Label(
                self.update_password_window,
                text="Update Password",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            tk.Label(
                self.update_password_window,
                text="New Password:",
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=5)
            self.password_entry = tk.Entry(
                self.update_password_window, bg="#46516e", fg="#E0E6F0", show="*"
            )
            self.password_entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
            update_password_button = tk.Button(
                self.update_password_window,
                text="Update Password",
                command=self.update_password,
                **self.button_style,
            )
            update_password_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
            login_button = tk.Button(
                self.update_password_window,
                text="Return To Login",
                command=self.init_login,
                **self.button_style,
            )
            login_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")

    @close_window
    def init_user_home(self, username, email):
        """
        Initializes the user home window.

        This function sets up the user home window with user information.

        Args:
            username (str): The username of the user.
            email (str): The email address of the user.
        """
        try:
            self.user_home_window = tk.Tk()
            self.running_window = self.user_home_window
            self.user_home_window.attributes('-topmost',True)
            self.user_home_window.title("User Home")
            self.user_home_window.geometry(f"300x220")
            self.user_home_window.configure(bg="#1E2533")
            header_font = font.Font(family="Helvetica", size=14, weight="bold")
            label_font = font.Font(family="Helvetica", size=10, weight="bold")
            tk.Label(
                self.user_home_window,
                text="User Home Page",
                font=header_font,
                bg="#1E2533",
                fg="#E0E6F0",
            ).pack(pady=20, padx=10, ipadx=10, ipady=5)
            tk.Label(
                self.user_home_window,
                text=f"User Name: {username}",
                bg="#1E2533",
                fg="#E0E6F0",
                font=label_font,
            ).pack(pady=5)
            tk.Label(
                self.user_home_window,
                text=f"Email Address: {email}",
                bg="#1E2533",
                fg="#E0E6F0",
                font=label_font,
            ).pack(pady=5)
            login_button = tk.Button(
                self.user_home_window,
                text="Logout",
                command=self.init_home,
                **self.button_style,
            )
            login_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        except Exception as e:
            print(f"Error: {e}")
    
    def register(self):
        '''Function that made to fix bugs'''
        self.username = self.register_entries[0].get()
        self.email = self.register_entries[1].get()
        self.password = self.register_entries[2].get()
        self.verify_password = self.register_entries[3].get()
        self.verify_email()

    def verify_email(self):
        '''Ask for the server to send verification code for the entered email address.'''
        try:
            if not self.username and not self.email and not self.password and not self.verify_password:
                self.username = self.register_entries[0].get()
                self.email = self.register_entries[1].get()
                self.password = self.register_entries[2].get()
                self.verify_password = self.register_entries[3].get()
            if (
                "" in (self.username, self.email, self.password, self.verify_password)
                or self.password != self.verify_password
                or not bool(match(r"[^@]+@[^@]+\.[^@]+", self.email))
            ):
                self.init_register(
                    "Not all fields have been filled, or the entered password does not match the second password, or the email entered is not valid"
                )
                return
            keys = ["Email Address"]
            values = [self.email]
            self.send_data(5, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "SNTC":
                    self.init_register_code()
                case "EROR":
                    match response[2]:
                        case Errors.INVALID_EMAIL:
                            self.init_register("The email entered is not valid")
                        case Errors.SERVER_ERROR:
                            self.init_register(
                                "The server had problems while dealing with the request"
                            )
                        case Errors.INVALID_REQUEST:
                            self.init_register(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def register_code(self):
        '''Handle the registration verification code.'''
        try:
            code = self.register_code_entry.get()
            if len(code) != 6 or not code.isnumeric():
                self.init_register_code(
                    "The entered code isn't 6 digits, or it's not a number"
                )
                return
            keys = ["Code", "Email"]
            values = [code, self.email]
            self.send_data(3, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "CDEK":
                    self.register_user()
                case "CDEW":
                    self.init_register_code("The code entered does not match the real code")
                case "EROR":
                    match response[2]:
                        case Errors.INVALID_CODE:
                            self.init_register_code(
                                "The entered code isn't 6 digits, or it's not a number"
                            )
                        case Errors.EMAIL_NOT_EXIST:
                            self.init_register(
                                "The email does not apper in the server's database"
                            )
                        case Errors.CODE_EXPIRED:
                            self.init_register(
                                "The code has expired"
                            )
                        case Errors.SERVER_ERROR:
                            self.init_register_code(
                                "The server had problems while dealing with the request"
                            )
                        case Errors.INVALID_REQUEST:
                            self.init_register_code(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def register_user(self):
        '''Ask for the server to register a new user.'''
        try:
            keys = ["Username", "Email Address", "Password"]
            values = [self.username, self.email, self.password]
            self.send_data(0, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "REGK":
                    print(f"The user {self.username} has successfully registered")
                    self.init_home()
                case "EROR":
                    match response[2]:
                        case Errors.INVALID_USERNAME:
                            self.init_register("The username entered is not valid")
                        case Errors.INVALID_EMAIL:
                            self.init_register("The email entered is not valid")
                        case Errors.INVALID_PASSWORD:
                            self.init_register("The password entered is not valid")
                        case Errors.USERNAME_IN_USE:
                            self.init_register("The username entered is already in use")
                        case Errors.EMAIL_IN_USE:
                            self.init_register("The email entered is already in use")
                        case Errors.SERVER_ERROR:
                            self.init_register(
                                "The server had problems while dealing with the request"
                            )
                        case Errors.INVALID_REQUEST:
                            self.init_register(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def login_user(self):
        '''Ask for the server to login an existing user.'''
        try:
            username = self.login_entries[0].get()
            password = self.login_entries[1].get()
            if "" in (username, password):
                self.init_login("Not all fields have been filled")
                return
            keys = ["Username", "Password"]
            values = [username, password]
            self.send_data(1, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "LOGK":
                    username = response[2]
                    email = response[3]
                    self.init_user_home(username, email)
                case "EROR":
                    match response[2]:
                        case Errors.USERNAME_NOT_EXIST:
                            self.init_login(f"The username ({username}) does not exist")
                        case Errors.INCORRECT_PASSWORD:
                            self.init_login(f"The password ({password}) is incorrect")
                        case Errors.SERVER_ERROR:
                            self.init_login(
                                "The server had problems while dealing with the request"
                            )
                        case Errors.INVALID_REQUEST:
                            self.init_login(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def forgot_password(self):
        '''Ask for the server to send code for password recovery.'''
        try:
            if not self.forgot_password_email:
                self.forgot_password_email = self.email_entry.get()
            if self.forgot_password_email == "":
                self.init_forgot_password("Not all fields have been filled")
                return
            keys = ["Email Address"]
            values = [self.forgot_password_email]
            self.send_data(2, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "SNTC":
                    self.init_password_code()
                case "EROR":
                    match response[2]:
                        case Errors.INVALID_EMAIL:
                            self.init_forgot_password("The email entered is not valid")
                        case Errors.EMAIL_NOT_EXIST:
                            self.init_forgot_password("The email entered does not exist")
                        case Errors.SERVER_ERROR:
                            self.init_forgot_password(
                                "The server had problems while dealing with the request"
                            )
                        case Errors.INVALID_REQUEST:
                            self.init_forgot_password(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def password_code(self):
        '''Handle the password recovery verification code.'''
        try:
            code = self.password_code_entry.get()
            if len(code) != 6 or not code.isnumeric():
                self.init_password_code(
                    "The entered code isn't 6 digits, or it's not a number"
                )
                return
            keys = ["Code", "Email"]
            values = [code, self.forgot_password_email]
            self.send_data(3, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "CDEK":
                    self.init_update_password()
                case "CDEW":
                    self.init_password_code("The code entered does not match the real code")
                case "EROR":
                    match response[2]:
                        case Errors.INVALID_CODE:
                            self.init_password_code(
                                "The entered code isn't 6 digits, or it's not a number"
                            )
                        case Errors.EMAIL_NOT_EXIST:
                            self.init_forgot_password(
                                "The email does not apper in the server's database"
                            )
                        case Errors.CODE_EXPIRED:
                            self.init_forgot_password(
                                "The code has expired"
                            )
                        case Errors.SERVER_ERROR:
                            self.init_password_code(
                                "The server had problems while dealing with the request"
                            )
                        case Errors.INVALID_REQUEST:
                            self.init_password_code(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def update_password(self):
        '''Ask for the server to update the user's password.'''
        try:
            password = self.password_entry.get()
            if password == "":
                self.init_update_password("Not all fields have been filled")
                return
            keys = ["Password"]
            values = [password]
            self.send_data(4, dict(zip(keys, values)))
            response = recv_by_size(self.cli_sock).split("|")
            match response[1]:
                case "PWUK":
                    messagebox.showinfo(
                        "Update Password Message",
                        f"The password has been successfully updated to {password}",
                    )
                    self.init_login()
                case "EROR":
                    match response[2]:
                        case Errors.SERVER_ERROR:
                            self.init_forgot_password(
                                "The password was not updated due to server errors"
                            )
                        case Errors.INVALID_PASSWORD:
                            self.init_update_password("The password entered is not valid")
                        case Errors.INVALID_REQUEST:
                            self.init_update_password(
                                "The request sent to the server was invalid"
                            )
                        case _:
                            self.invalid_response()
                case _:
                    self.invalid_response()
        except Exception as e:
            print(f"Error: {e}")

    def send_data(self, request_type: int, user_data: dict) -> None:
        '''Send data to the server based on request type and user data.'''
        try:
            match request_type:
                case 0:
                    msg = f"|REGS|{user_data['Username']}|{user_data['Password']}|"
                case 1:
                    msg = f"|LOGN|{user_data['Username']}|{user_data['Password']}|"
                case 2:
                    msg = f"|VERC|{user_data['Email Address']}|"
                case 3:
                    msg = f"|CODE|{user_data['Code']}|{user_data['Email']}|"
                case 4:
                    msg = f"|PWUP|{user_data['Password']}|"
                case 5:
                    msg = f"|REGC|{user_data['Email Address']}|"
            send_with_size(self.cli_sock, msg.encode())
        except Exception as e:
            print(f"Error: {e}")

    def invalid_response(self):
        '''Handle invalid responses from the server.'''
        try:
            print(f"The response sent from the server is not valid, closing connection...")
            self.cli_sock.close()
            exit()
        except Exception as e:
            print(f"Error: {e}")

    def run(self) -> None:
        """Run the client application.

        Returns:
            None
        """
        try:
            try:
                self.cli_sock.connect((self.ip, self.port))
                print(f"Connected to server {self.ip}:{self.port}")
            except Exception as e:
                print(
                    f"Error while trying to connect. Check IP or port -- {self.ip}:{self.port}"
                )
                exit()
            self.init_home()
            self.cli_sock.close()
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    if len(argv) == 3:
        ip = argv[1]
        port = int(argv[2])
        c = Client(ip, port)
        c.run()
    else:
        # print("Usage: python client.py <ip> <port>")
        c = Client(IP, PORT)
        c.run()