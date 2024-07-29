import random
import os
from ecdsa import SECP256k1, VerifyingKey
from math import isqrt
from concurrent.futures import ProcessPoolExecutor
from pybloom_live import BloomFilter

BLOOM_FILTER_FILE = 'bloom_filter.bloom'

def point_to_hex(point):
    return point.x().to_bytes(32, byteorder='big').hex() + point.y().to_bytes(32, byteorder='big').hex()

def compute_baby_steps(subrange, G, num_steps, bloom_filter):
    baby_steps = {}
    for i in range(num_steps):
        k = random.randint(*subrange)
        if k in bloom_filter:
            continue
        point = k * G
        point_hex = point_to_hex(point)
        baby_steps[point_hex] = k
        bloom_filter.add(k)
        print(f"\rCounting: {i + 1} of {num_steps}", end="")
    return baby_steps

def baby_step_giant_step_random(public_key_hex, min_value, max_value, curve=SECP256k1, num_random_baby_steps=2000000, num_workers=6):
    print()
    print(f"Testing {num_random_baby_steps} Baby Steps...")
    
    public_key_bytes = bytes.fromhex(public_key_hex)
    public_key_point = VerifyingKey.from_string(public_key_bytes, curve=curve).pubkey.point

    G = curve.generator
    order = curve.order

    range_size = max_value - min_value + 1
    m = isqrt(range_size) + 1

    step_size = (range_size // num_workers)
    subranges = [(min_value + i * step_size, min_value + (i + 1) * step_size - 1) for i in range(num_workers)]
    subranges[-1] = (subranges[-1][0], max_value)

    bloom_filter = load_bloom_filter(BLOOM_FILTER_FILE)

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        future_to_baby_steps = {
            executor.submit(compute_baby_steps, subrange, G, num_random_baby_steps // num_workers, bloom_filter): subrange
            for subrange in subranges
        }

    baby_steps = {}
    for future in future_to_baby_steps:
        result = future.result()
        baby_steps.update(result)
    
    save_bloom_filter(bloom_filter, BLOOM_FILTER_FILE)

    giant_step = m * G
    current_point = public_key_point
    print(f"\nTesting {m} Giant Steps...")
    
    for i in range(m):
        current_point_hex = point_to_hex(current_point)
        if current_point_hex in baby_steps:
            private_key = (baby_steps[current_point_hex] + i * m) % order
            private_key_hex = format(private_key, '064x')
            return private_key_hex, public_key_hex
        current_point = current_point + (-giant_step)
        print(f"\rCounting: {i + 1} of {m}", end="")

    return None, None

def load_bloom_filter(filename):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return BloomFilter.fromfile(f)
    else:
        return BloomFilter(capacity=200000000, error_rate=0.001)  # Aumente a capacidade conforme necessário

def save_bloom_filter(bloom_filter, filename):
    with open(filename, 'wb') as f:
        bloom_filter.tofile(f)

if __name__ == '__main__':
    public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'
    min_value_hex = '0x200000000000000000000000000000000'
    max_value_hex = '0x3ffffffffffffffffffffffffffffffff'
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)

    print(f"Chave Pública: {public_key_hex}")
    print("Intervalo:")
    print(f" - De: {min_value_hex}")
    print(f" - Até: {max_value_hex}")
    print("1 - Buscando...")

    try:
        found_private_key, found_public_key = baby_step_giant_step_random(public_key_hex, min_value, max_value)
        if found_private_key:
            print(f"Chave Privada Encontrada: {found_private_key}")
            with open("chaves_encontradas.txt", "w") as file:
                file.write(f"Chave Pública: {found_public_key}\n")
                file.write(f"Chave Privada: {found_private_key}\n")
    except KeyboardInterrupt:
        print("Busca interrompida pelo usuário.")
