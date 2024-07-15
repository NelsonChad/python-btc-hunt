import random
from ecdsa import SECP256k1, VerifyingKey, SigningKey

# Chave pública fornecida
public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'

# Função de força bruta aleatória para encontrar a chave privada
def brute_force_private_key_random(public_key_hex, min_value_hex, max_value_hex, max_attempts):
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)
    attempts = set()
    
    for _ in range(max_attempts):
        attempt = random.randint(min_value, max_value)
        if attempt in attempts:
            continue
        attempts.add(attempt)
        attempt_sk = SigningKey.from_secret_exponent(attempt, curve=SECP256k1)
        attempt_vk = attempt_sk.verifying_key
        
        # Convert attempt_vk to compressed format to match the given public key format
        attempt_vk_hex = attempt_vk.to_string('compressed').hex()
        
        if attempt_vk_hex == public_key_hex:
            return attempt_sk.to_string().hex()
    return None

# Definir o intervalo de chaves de 2^129 a 2^130 - 1 em hexadecimal
min_value_hex = '0x200000000000000000000000000000000'
max_value_hex = '0x3ffffffffffffffffffffffffffffffff'
max_attempts = 1000000  # Número de tentativas, ajustável conforme necessário

found_private_key = brute_force_private_key_random(public_key_hex, min_value_hex, max_value_hex, max_attempts)

if found_private_key:
    print(f"Chave Privada Encontrada: {found_private_key}")
else:
    print("Chave Privada não encontrada dentro do limite de tentativas.")
