import sqlite3
from hashlib import sha256
from secrets import token_bytes

class DataBaseHandler:
    SALT_LENGTH = 8
    PEPPER = b'my_secret_pepper'

    def __init__(self, db_name="user.db") -> None:
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                                username TEXT UNIQUE NOT NULL PRIMARY KEY,
                                email TEXT UNIQUE NOT NULL,
                                password TEXT NOT NULL,
                                salt TEXT NOT NULL)"""
        )
        self.conn.commit()

    def is_username_exist(self, username):
        self.cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        return self.cursor.fetchone() is not None

    def is_email_exist(self, email):
        self.cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        return self.cursor.fetchone() is not None

    def get_email(self, username):
        if not self.is_username_exist(username):
            return None
        self.cursor.execute("SELECT email FROM users WHERE username=?", (username,))
        email = self.cursor.fetchone()[0]
        return email

    def get_username(self, email) -> str:
        if not self.is_email_exist(email):
            return None
        self.cursor.execute("SELECT username FROM users WHERE email=?", (email,))
        username = self.cursor.fetchone()[0]
        return username

    def is_password_ok(self, username, password):
        self.cursor.execute("SELECT password, salt FROM users WHERE username=?", (username,))
        stored_password, stored_salt = self.cursor.fetchone()

        if stored_password:
            hashed_password = sha256(password.encode() + stored_salt + DataBaseHandler.PEPPER).hexdigest()
            return hashed_password == stored_password
        return False

    def save_user(self, username, email, password) -> None:
        salt = token_bytes(DataBaseHandler.SALT_LENGTH)
        hashed_password = sha256(password.encode() + salt + DataBaseHandler.PEPPER).hexdigest()
        self.cursor.execute(
            "INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, salt),
        )
        self.conn.commit()

    def update_user_password(self, username, new_password) -> None:
        self.cursor.execute("SELECT salt FROM users WHERE username=?", (username,))
        stored_salt = self.cursor.fetchone()[0]
        hashed_password = sha256(new_password.encode() + stored_salt + DataBaseHandler.PEPPER).hexdigest()
        self.cursor.execute(
            "UPDATE users SET password=? WHERE username=?", (hashed_password, username)
        )
        self.conn.commit()

if __name__ == "__main__":
    # example usage:
    db_test = DataBaseHandler()
    if not db_test.is_username_exist("user1"):
        db_test.save_user("user1", "user1@example.com", "password123")
    print(db_test.is_username_exist("user1"))
    print(db_test.is_password_ok("user1", "password123"))
    print(db_test.is_password_ok("user1", "pass123"))
    db_test.update_user_password("user1", "newpassword456")
    print(db_test.get_username("user1@example.com"))
    if not db_test.is_username_exist("itamar"):
        db_test.save_user("itamar", "dalalitamar@gmail.com", "dllilo05")
    print(db_test.is_username_exist("itamar"))
    print(db_test.is_email_exist("dalalitamar@gmail.com"))
    print(db_test.get_email("itamar"))
    print(db_test.is_password_ok("itamar", "dllilo05"))
