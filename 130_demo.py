import random
from ecdsa import SECP256k1, SigningKey

# Função para gerar uma chave privada de 130 bits para fins educacionais
def generate_private_key():
    return SigningKey.generate(curve=SECP256k1)

sk = generate_private_key()
vk = sk.verifying_key

# Chave privada e pública em hexadecimal
private_key = sk.to_string().hex()
public_key = vk.to_string().hex()

print(f"Chave Privada: {private_key}")
print(f"Chave Pública: {public_key}")

# Função de força bruta aleatória para encontrar a chave privada
def brute_force_private_key_random(public_key, min_value_hex, max_value_hex, max_attempts):
    attempts = set()
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)
    for _ in range(max_attempts):
        attempt = random.randint(min_value, max_value)
        if attempt in attempts:
            continue
        attempts.add(attempt)
        attempt_sk = SigningKey.from_secret_exponent(attempt, curve=SECP256k1)
        attempt_vk = attempt_sk.verifying_key
        if attempt_vk.to_string().hex() == public_key:
            return attempt_sk.to_string().hex()
    return None

# Definir o intervalo de chaves de 2^129 a 2^130 - 1 em hexadecimal
min_value_hex = '0x200000000000000000000000000000000'
max_value_hex = '0x3ffffffffffffffffffffffffffffffff'
max_attempts = 1000000  # Número de tentativas, ajustável conforme necessário

found_private_key = brute_force_private_key_random(public_key, min_value_hex, max_value_hex, max_attempts)

if found_private_key:
    print(f"Chave Privada Encontrada: {found_private_key}")
else:
    print("Chave Privada não encontrada dentro do limite de tentativas.")
