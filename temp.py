from app import bcrypt
hashed_password = bcrypt.generate_password_hash('test').decode('utf-8')
print(hashed_password)