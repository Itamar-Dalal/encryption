import tkinter as tk
from tkinter import font

class Gui(tk.Tk):
    def __init__(self, width=350, height=250):
        super().__init__()
        self.width = width
        self.height = height
        self.title("User Login")
        self.geometry(f"{self.width}x{self.height}")
        self.configure(bg='#1E2533')
        header_font = font.Font(family="Helvetica", size=16, weight="bold")
        header_label = tk.Label(self, text="User Login", font=header_font, bg='#1E2533', fg='#E0E6F0')
        header_label.pack(pady=20, padx=10, ipadx=10, ipady=5)
        self.button_style = {'bg': '#46516e', 'fg': 'white', 'borderwidth': 0, 'activebackground': '#2980B9', 'activeforeground': 'white'}
        register_button = tk.Button(self, text="Open Register Window", command=self.init_register, **self.button_style)
        register_button.pack(pady=20, padx=10, ipadx=10, ipady=5)
        login_button = tk.Button(self, text="Open Login Window", command=self.init_login, **self.button_style)
        login_button.pack(pady=20, padx=10, ipadx=10, ipady=5)
        self.mainloop()

    def init_register(self):
        register_window = tk.Toplevel(self)
        register_window.title("Register")
        register_window.geometry(f"300x440")
        register_window.configure(bg='#1E2533')
        header_font = font.Font(family="Helvetica", size=14, weight="bold")
        tk.Label(register_window, text="Register", font=header_font, bg='#1E2533', fg='#E0E6F0').pack(pady=20, padx=10, ipadx=10, ipady=5)
        labels = ["Username:", "Email Address:", "Password:", "Verify password:"]
        self.register_entries = [tk.Entry(register_window, bg='#46516e', fg='#E0E6F0', show="*" if label in ("Password:", "Verify password:") else None) for label in labels]
        for label, entry in zip(labels, self.register_entries):
            tk.Label(register_window, text=label, bg='#1E2533', fg='#E0E6F0').pack(pady=5)
            entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
        register_button = tk.Button(register_window, text="Register", command=self.register_user, **self.button_style)
        register_button.pack(pady=20, padx=10, ipadx=10, ipady=5)

    def init_login(self):
        login_window = tk.Toplevel(self)
        login_window.title("Login")
        login_window.geometry(f"300x380")
        login_window.configure(bg='#1E2533')
        header_font = font.Font(family="Helvetica", size=14, weight="bold")
        tk.Label(login_window, text="Login", font=header_font, bg='#1E2533', fg='#E0E6F0').pack(pady=20, padx=10, ipadx=10, ipady=5)
        labels = ["Username:", "Password:"]
        self.login_entries = [tk.Entry(login_window, bg='#46516e', fg='#E0E6F0', show="*" if label == "Password:" else None) for label in labels]
        for label, entry in zip(labels, self.login_entries):
            tk.Label(login_window, text=label, bg='#1E2533', fg='#E0E6F0').pack(pady=5)
            entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
        login_button = tk.Button(login_window, text="Login", command=self.login_user, **self.button_style)
        login_button.pack(pady=20, padx=10, ipadx=10, ipady=5)
        forgot_password_button = tk.Button(login_window, text="Forgot Password", command=self.forgot_password_init, **self.button_style)
        forgot_password_button.pack(pady=20, padx=10, ipadx=10, ipady=5)

    def forgot_password_init(self):
        forgot_password_window = tk.Toplevel(self)
        forgot_password_window.title("Forgot Password")
        forgot_password_window.geometry(f"300x250")
        forgot_password_window.configure(bg='#1E2533')
        header_font = font.Font(family="Helvetica", size=14, weight="bold")
        tk.Label(forgot_password_window, text="Forgot Password", font=header_font, bg='#1E2533', fg='#E0E6F0').pack(pady=20, padx=10, ipadx=10, ipady=5)
        tk.Label(forgot_password_window, text="Email Address:", bg='#1E2533', fg='#E0E6F0').pack(pady=5)
        self.email_entry = tk.Entry(forgot_password_window, bg='#46516e', fg='#E0E6F0')
        self.email_entry.pack(pady=5, padx=10, ipadx=10, ipady=5)
        send_email_button = tk.Button(forgot_password_window, text="Send Email", command=self.forgot_password, **self.button_style)
        send_email_button.pack(pady=20, padx=10, ipadx=10, ipady=5)

    def register_user(self):
        username = self.register_entries[0].get()
        email = self.register_entries[1].get()
        password = self.register_entries[2].get()
        verify_password = self.register_entries[3].get()
        print(f"Username: {username}, Email Address: {email}, Password: {password}, Verify Password: {verify_password}")

    def login_user(self):
        username = self.login_entries[0].get()
        password = self.login_entries[1].get()
        print(f"Username: {username}, Password: {password}")
    
    def forgot_password(self):
        email = self.email_entry.get()
        print(f"Email Address: {email}")

if __name__ == "__main__":
    test_gui = Gui()
