import random
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.numbertheory import inverse_mod
from math import isqrt

# Function to perform Baby-step Giant-step algorithm
def baby_step_giant_step(public_key_hex, curve=SECP256k1):
    # Convert the public key from hex to the verifying key object
    public_key_bytes = bytes.fromhex(public_key_hex)
    public_key_point = VerifyingKey.from_string(public_key_bytes, curve=curve).pubkey.point
    
    # Get the generator point and order of the curve
    G = curve.generator
    n = curve.order
    
    # Define m as the integer square root of n, plus one
    m = isqrt(n) + 1
    
    # Compute baby steps and store them in a dictionary
    baby_steps = {}
    for j in range(m):
        point = j * G
        baby_steps[point.__repr__()] = j  # Convert the point to a string
    
    # Compute the giant step multiplier
    giant_step = m * G
    
    # Initialize current point as the public key point
    current_point = public_key_point
    
    # Perform giant steps
    for i in range(m):
        current_point_str = current_point.__repr__()  # Convert the point to a string
        if current_point_str in baby_steps:
            # Private key found
            private_key = i * m + baby_steps[current_point_str]
            private_key_hex = format(private_key, '064x')

            return private_key_hex, public_key_hex
        
        # Move to the next giant step
        current_point -= giant_step
    
    # Private key not found
    return None, None

if __name__ == '__main__':
    # Chave pública fornecida
    public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'

    # Mostrar a chave pública
    print(f"Chave Pública: {public_key_hex}")
    print("1 - Buscando...")

    try:
        found_private_key, found_public_key = baby_step_giant_step(public_key_hex)
        if found_private_key:
            print(f"Chave Privada Encontrada: {found_private_key}")
            # Salvar as chaves em um arquivo de texto
            with open("chaves_encontradas.txt", "w") as file:
                file.write(f"Chave Pública: {found_public_key}\n")
                file.write(f"Chave Privada: {found_private_key}\n")
    except KeyboardInterrupt:
        print("Busca interrompida pelo usuário.")
