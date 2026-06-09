# Simulation de cryptomineur — fichier de test uniquement, ne jamais exécuter
import hashlib
import multiprocessing
import time

POOL_URL = "stratum+tcp://pool.monero.hashvault.pro:3333"

def mine(nonce_start: int) -> None:
    target = "0000"
    nonce = nonce_start
    while True:
        data = f"block_data_{nonce}".encode()
        result = hashlib.sha256(data).hexdigest()
        if result.startswith(target):
            print(f"[+] Nonce trouvé : {nonce} -> {result}")
        nonce += 1

cpu_count = multiprocessing.cpu_count()
workers = [
    multiprocessing.Process(target=mine, args=(i * 100_000,))
    for i in range(cpu_count)
]
for w in workers:
    w.start()
for w in workers:
    w.join()
