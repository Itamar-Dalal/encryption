from re import match
import smtplib

email = "dalalitamar@gmail.com"
def func():
    return bool(match(r"[^@]+@[^@]+\.[^@]+", email))
    
print(func())