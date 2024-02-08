import tkinter as tk
from tkinter import font
import tcp_by_size
from socket import socket, AF_INET, SOCK_STREAM
from tcp_by_size import send_with_size, recv_by_size
from sys import argv, exit


IP = "127.0.0.1"
PORT = 1234


def close_window(func):
    def wrapper(self, *args, **kwargs):
        if self.running_window:
            self.running_window.destroy()
        result = func(self, *args, **kwargs)
        return result

    return wrapper


class Client:
    def __init__(self, ip, port, width=350, height=250):
        self.width = width
        self.height = height
        self.ip = ip
        self.port = port
        self.cli_sock = socket(AF_INET, SOCK_STREAM)
        self.running_window = None

    @close_window
    def init_home(self):
        self.home_window = tk.Tk()
        self.running_window = self.home_window
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

    @close_window
    def init_register(self, err=None):
        self.register_window = tk.Tk()
        self.running_window = self.register_window
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
            command=self.register_user,
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

    @close_window
    def init_login(self, err=None):
        self.login_window = tk.Tk()
        self.running_window = self.login_window
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

    @close_window
    def init_forgot_password(self, err=None):
        self.forgot_password_window = tk.Tk()
        self.running_window = self.forgot_password_window
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

    @close_window
    def init_password_code(self, err=None):
        self.password_code_window = tk.Tk()
        self.running_window = self.password_code_window
        self.password_code_window.title("Password Code")
        self.password_code_window.geometry(f"300x280")
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
        self.code_entry = tk.Entry(
            self.password_code_window, bg="#46516e", fg="#E0E6F0"
        )
        self.code_entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
        submit_code_button = tk.Button(
            self.password_code_window,
            text="Submit",
            command=self.password_code,
            **self.button_style,
        )
        submit_code_button.pack(pady=5, padx=10, ipadx=10, ipady=5)
        forgot_password_button = tk.Button(
            self.password_code_window,
            text="Return To Forgot Password",
            command=self.init_forgot_password,
            **self.button_style,
        )
        forgot_password_button.pack(pady=5, padx=10, ipadx=10, ipady=5)

    @close_window
    def init_update_password(self, err=None):
        self.update_password_window = tk.Tk()
        self.running_window = self.update_password_window
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

    def register_user(self):
        username = self.register_entries[0].get()
        email = self.register_entries[1].get()
        password = self.register_entries[2].get()
        verify_password = self.register_entries[3].get()
        if (
            "" in (username, email, password, verify_password)
            or password != verify_password
        ):
            print(
                "Error: Not all fields have been filled, or the entered password does not match the second password"
            )
            print("Please try again...")
            self.init_register()
            return
        keys = ["Username", "Email Address", "Password"]
        values = [username, email, password]
        self.send_data(0, dict(zip(keys, values)))

    def login_user(self):
        username = self.login_entries[0].get()
        password = self.login_entries[1].get()
        if "" in (username, password):
            print("Error: Not all fields have been filled")
            print("Please try again...")
            self.init_login()
            return
        keys = ["Username", "Password"]
        values = [username, password]
        self.send_data(1, dict(zip(keys, values)))

    def forgot_password(self):
        email = self.email_entry.get()
        if email == "":
            print("Error: Not all fields have been filled")
            print("Please try again...")
            self.init_forgot_password()
            return
        keys = ["Email Address"]
        values = [email]
        self.send_data(2, dict(zip(keys, values)))
        response = recv_by_size(self.cli_sock).split("|")
        match response[1]:
            case "SNTC":
                self.init_password_code()
            case "EROR":
                error_code = response[1]
                # todo: check the error code and call init_forgot_password() with right error arg
            case _:
                self.invalid_response()

    def password_code(self):
        code = self.code_entry.get()
        if len(code) != 6 or not code.isnumeric():
            print("Error: The entered code isn't 6 digits, or it's not a number")
            print("Please try again...")
            self.init_password_code()
            return
        keys = ["Code"]
        values = [code]
        self.send_data(3, dict(zip(keys, values)))
        response = recv_by_size(self.cli_sock).split("|")
        match response[1]:
            case "CDEK":
                self.init_update_password()
            case "CDEW":
                print(f"Error: the code entered does not match the real code")
                print("Please try again...")
                self.init_password_code()
                return
            case "EROR":
                error_code = response[1]
                # todo: check the error code and call init_forgot_password() with right error arg
            case _:
                self.invalid_response()

    def update_password(self):
        password = self.password_entry.get()
        if password == "":
            print("Error: Not all fields have been filled")
            print("Please try again...")
            self.init_update_password()
            return
        keys = ["Password"]
        values = [password]
        self.send_data(4, dict(zip(keys, values)))
        response = recv_by_size(self.cli_sock).split("|")
        match response[1]:
            case "PWUK":
                print(f"The password has been successfully updated to {password}")
                self.init_login()
            case "PWUF":
                print("The password was not updated due to errors in the server")
                print("Please try again...")
                self.init_forgot_password()
            case _:
                self.invalid_response()

    def send_data(
        self, request_type: int, user_data: dict
    ) -> (
        None
    ):  # request_type: 0 - register, 1 - login, 2 - forgot password, 3 - password code, 4 - update password
        match request_type:
            case 0:
                msg = f"|REGS|{user_data['Username']}|{user_data['Email Address']}|{user_data['Password']}|"
            case 1:
                msg = f"|LOGN|{user_data['Username']}|{user_data['Password']}|"
            case 2:
                msg = f"|FRGP|{user_data['Email Address']}|"
            case 3:
                msg = f"|CODE|{user_data['Code']}|"
            case 4:
                msg = f"|PWUP|{user_data['Password']}|"
        send_with_size(self.cli_sock, msg.encode())

    def invalid_response(self):
        print(
            f"The response sent from the server is not valid, closing connection..."
        )
        self.cli_sock.close()
        exit()

    def run(self) -> None:
        """Run the client application.
        Returns:
            None
        """
        try:
            try:
                self.cli_sock.connect((self.ip, self.port))
                print(f"Connected to the server {self.ip}:{self.port}")
            except Exception as e:
                print(
                    f"Error while trying to connect. Check IP or port -- {self.ip}:{self.port}"
                )
                exit()
            self.init_home()
        except Exception as e:
            print(f"Error: {e}")
        self.cli_sock.close()


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
