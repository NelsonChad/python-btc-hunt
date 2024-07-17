import random
import binascii
import os

# Definir a chave pública para fins de teste
public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'

# Função para gerar uma chave privada de 130 bits com os primeiros 32 caracteres sendo zeros
def generate_130_bit_private_key():
    # Gerar 64 bits aleatórios (16 dígitos hexadecimais)
    random_part = binascii.hexlify(os.urandom(16)).decode('utf-8')  # 16 bytes = 128 bits = 32 hex digits
    # Preencher os primeiros 32 caracteres com zeros
    private_key = '0' * 32 + random_part[-32:]
    return private_key

# Função para simular a obtenção da chave pública a partir da chave privada (somente para demonstração)
def get_public_key_from_private(private_key_hex):
    # Aqui você deve usar a biblioteca apropriada para derivar a chave pública da chave privada
    # Por exemplo, a biblioteca ecdsa ou coincurve para Bitcoin e outras criptografias de curva elíptica
    return private_key_hex  # Esta linha é apenas um espaço reservado para o exemplo

# Função principal de força bruta
def brute_force_search(public_key_hex):
    print(f"Chave Pública: {public_key_hex}")
    print(f"Intervalo de Chaves: 0x{'0' * 32}00000000000000000000000000000000 a 0x{'0' * 32}ffffffffffffffffffffffffffffffff")

    while True:
        # Gerar uma chave privada aleatória de 130 bits
        private_key_hex = generate_130_bit_private_key()
        
        # Obter a chave pública correspondente
        derived_public_key_hex = get_public_key_from_private(private_key_hex)
        
        # Verificar se a chave pública derivada corresponde à chave pública fornecida
        if derived_public_key_hex == public_key_hex:
            print(f"Chave privada encontrada: {private_key_hex}")
            # Salvar a chave privada e a chave pública em um arquivo
            with open('found_keys.txt', 'a') as f:
                f.write(f"Chave Pública: {public_key_hex}\n")
                f.write(f"Chave Privada: {private_key_hex}\n")
                f.write("\n")
            break
        
        print(f"Tentando chave privada: {private_key_hex}")

if __name__ == "__main__":
    brute_force_search(public_key_hex)
