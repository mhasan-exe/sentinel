from pwdlib import PasswordHash
import jwt
from datetime import datetime, timedelta,timezone

SECRET_KEY = "thewickedwitchdidntfindthewayoutanywheresoon"
ALGORITHM = "NEW ALGO"
user_id = int(input("Enter an Id: "))

expire = datetime.now(timezone.utc) + timedelta(minutes=30)
payload = {
    "sub": str(user_id),
    "exp": expire,
}
key = jwt.encode(payload,SECRET_KEY,algorithm=ALGORITHM)
token = key
print("Encoded JWT:", key)
cont = input("continue? y/n: ")
if cont == "y":

    decoded = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
    print("Decoded JWT:", decoded)



