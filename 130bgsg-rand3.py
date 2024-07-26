import random
from ecdsa import SECP256k1, VerifyingKey
from math import isqrt
from concurrent.futures import ProcessPoolExecutor

def point_to_hex(point):
    return point.x().to_bytes(32, byteorder='big').hex() + point.y().to_bytes(32, byteorder='big').hex()

def compute_baby_steps(subrange, G, num_steps):
    baby_steps = {}
    tested_private_keys = set()
    for _ in range(num_steps):
        k = random.randint(*subrange)
        if k in tested_private_keys:
            continue
        point = k * G
        point_hex = point_to_hex(point)
        baby_steps[point_hex] = k
        tested_private_keys.add(k)
    return baby_steps

def baby_step_giant_step_random(public_key_hex, min_value, max_value, curve=SECP256k1, num_random_baby_steps=100000, num_workers=4):
    print(f"Testing {num_random_baby_steps} Baby Steps...")
    public_key_bytes = bytes.fromhex(public_key_hex)
    public_key_point = VerifyingKey.from_string(public_key_bytes, curve=curve).pubkey.point

    G = curve.generator
    order = curve.order

    range_size = max_value - min_value + 1
    m = isqrt(range_size) + 1

    # Divide the range into subranges for parallel processing
    step_size = (range_size // num_workers)
    subranges = [(min_value + i * step_size, min_value + (i + 1) * step_size - 1) for i in range(num_workers)]
    subranges[-1] = (subranges[-1][0], max_value)  # Ensure the last subrange ends at max_value

    # Use ProcessPoolExecutor to compute baby steps in parallel
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        future_to_baby_steps = {executor.submit(compute_baby_steps, subrange, G, num_random_baby_steps // num_workers): subrange for subrange in subranges}

    # Collect and merge results from all futures
    baby_steps = {}
    for future in future_to_baby_steps:
        result = future.result()
        baby_steps.update(result)

    giant_step = m * G
    current_point = public_key_point
    print(f"Testing {m} Giant Steps...")
    for i in range(m):
        current_point_hex = point_to_hex(current_point)
        if current_point_hex in baby_steps:
            private_key = (baby_steps[current_point_hex] + i * m) % order
            private_key_hex = format(private_key, '064x')
            return private_key_hex, public_key_hex
        current_point = current_point + (-giant_step)

    return None, None

if __name__ == '__main__':

    public_key_hex = '0230210c23b1a047bc9bdbb13448e67deddc108946de6de639bcc75d47c0216b1b'
    min_value_hex = '0x10000000000000000'
    max_value_hex = '0x1ffffffffffffffff'
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
