from passlib.context import CryptContext

# Using Argon2 for modern password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Generate hash for "adminpass"
password = "adminpass"
hashed_password = pwd_context.hash(password)
print(f"Hash for 'adminpass': {hashed_password}")
