import threading
import requests
import os
from queue import Queue

NUM_THREADS = 4
sslCrt = os.getenv("SSL_CRT_FILE")
sslKey = os.getenv("SSL_KEY_FILE")
URL = "https://localhost:9443/app/aggregates"

def make_request(url):
    try:
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            print(f"Success: {response.text}")
        else:
            print(f"Error: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def worker(queue):
    while True:
        try:
            url = queue.get(block=True, timeout=1)
            make_request(url)
            queue.task_done()
        except Exception as e:
            print(f"Error in worker: {e}")
            break

if __name__ == "__main__":
    queue = Queue()

    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=worker, args=(queue,))
        thread.daemon = True
        thread.start()

    for i in range(5000):
        url = f"{URL}?username=alex"
        queue.put(url)

    queue.join()
    print("All requests completed")
