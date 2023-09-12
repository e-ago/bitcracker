import random
import secrets
from pathlib import Path

min_password_len = 8
max_password_len = 27
num_passwords = 72 * 1024
output_file = Path('user_passwords_large.txt')

with output_file.open('w') as fout:
    for _ in range(num_passwords):
        password_len = random.randint(min_password_len, max_password_len)
        password = secrets.token_urlsafe(password_len) + '\n'
        fout.write(password)
