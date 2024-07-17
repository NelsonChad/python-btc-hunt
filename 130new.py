import random
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import binascii
import os

# Chave pública fornecida
public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'

# Função para gerar uma chave privada com os primeiros 32 caracteres como zeros
def generate_130_bit_private_key(min_value_hex,max_value_hex):
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)
    private_key_int = random.randint(min_value, max_value)
    return private_key_int

# Função para derivar a chave pública a partir da chave privada
def get_public_key_from_private(private_key_int):
    signing_key = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key_hex = verifying_key.to_string('compressed').hex()
    return public_key_hex

# Função de força bruta aleatória para encontrar a chave privada
def brute_force_private_key_random(public_key_hex, min_value_hex, max_value_hex):
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)
    attempts = set()
    
    while True:  # Loop infinito até o usuário interromper
        attempt = generate_130_bit_private_key(min_value_hex,max_value_hex)
        if attempt in attempts:
            continue
        attempts.add(attempt)
        attempt_vk_hex = get_public_key_from_private(attempt)

        #print(f"PrK: {attempt}")
        #print(f"puK: {attempt_vk_hex}")
        #print(f"---: {public_key_hex}")
        #print("-------------------------------------------------------------------------")

        if attempt_vk_hex == public_key_hex:
            attempt_sk = SigningKey.from_secret_exponent(attempt, curve=SECP256k1)
            return attempt_sk.to_string().hex(), public_key_hex

if __name__ == '__main__':
    # Definir o intervalo de chaves de 2^129 a 2^130 - 1 em hexadecimal
    min_value_hex = '0x200000000000000000000000000000000'
    max_value_hex = '0x3ffffffffffffffffffffffffffffffff'

    # Mostrar a chave pública e o intervalo
    print(f"Chave Pública: {public_key_hex}")
    print("Intervalo:")
    print(f" - De: {min_value_hex}")
    print(f" - Ate: {max_value_hex}")
    print("2- Buscando...")

    try:
        found_private_key, found_public_key = brute_force_private_key_random(public_key_hex, min_value_hex, max_value_hex)
        if found_private_key:
            print(f"Chave Privada Encontrada: {found_private_key}")
            # Salvar as chaves em um arquivo de texto
            with open("encontradas.txt", "a") as file:
                file.write(f"Chave Pública: {found_public_key}\n")
                file.write(f"Chave Privada: {found_private_key}\n")
    except KeyboardInterrupt:
        print("Busca interrompida pelo usuário.")
