import random
from ecdsa import SECP256k1, SigningKey

# Chave pública fornecida
public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'

# Função de força bruta aleatória para encontrar a chave privada
def brute_force_private_key_random(public_key_hex, min_value_hex, max_value_hex):
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)
    attempts = set()
    
    while True:  # Loop infinito até o usuário interromper
        attempt = random.randint(min_value, max_value)
        if attempt in attempts:
            continue
        attempts.add(attempt)
        attempt_sk = SigningKey.from_secret_exponent(attempt, curve=SECP256k1)
        attempt_vk = attempt_sk.verifying_key
        
        # Convert attempt_vk to compressed format to match the given public key format
        attempt_vk_hex = attempt_vk.to_string('compressed').hex()
        
        if attempt_vk_hex == public_key_hex:
            return attempt_sk.to_string().hex(), public_key_hex

# Definir o intervalo de chaves de 2^129 a 2^130 - 1 em hexadecimal
min_value_hex = '0x200000000000000000000000000000000'
max_value_hex = '0x3ffffffffffffffffffffffffffffffff'

# Mostrar a chave pública e o intervalo
print(f"Chave Pública: {public_key_hex}")
print(f"Intervalo de Chaves: {min_value_hex} a {max_value_hex}")
print("Procurando...")

try:
    found_private_key, found_public_key = brute_force_private_key_random(public_key_hex, min_value_hex, max_value_hex)
    if found_private_key:
        print(f"Chave Privada Encontrada: {found_private_key}")
        # Salvar as chaves em um arquivo de texto
        with open("chaves_encontradas.txt", "w") as file:
            file.write(f"Chave Pública: {found_public_key}\n")
            file.write(f"Chave Privada: {found_private_key}\n")
except KeyboardInterrupt:
    print("Busca interrompida pelo usuário.")
