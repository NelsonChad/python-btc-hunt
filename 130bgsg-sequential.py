import random
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from math import isqrt

# Função para realizar o algoritmo Baby-step Giant-step com passos aleatórios e intervalo específico
def baby_step_giant_step_random(public_key_hex, min_value, max_value, curve=SECP256k1):
    # Converte a chave pública de hexadecimal para o objeto de chave de verificação
    public_key_bytes = bytes.fromhex(public_key_hex)
    public_key_point = VerifyingKey.from_string(public_key_bytes, curve=curve).pubkey.point
    
    # Obtém o ponto gerador e a ordem da curva
    G = curve.generator
    order = curve.order
    
    # Define o tamanho do intervalo
    range_size = max_value - min_value + 1
    
    # Define m como a raiz quadrada inteira do tamanho do intervalo, mais um
    m = isqrt(range_size) + 1
    
    # Computa os baby steps e armazena-os em um dicionário
    baby_steps = {}
    for j in range(m):
        k = min_value + j
        point = k * G
        point_hex = point.to_bytes().hex()
        baby_steps[point_hex] = k
        # Imprimir a chave privada testada (baby step)
        print(f"Testando Baby Step - Chave Privada: {k}")

    # Computa o multiplicador do giant step
    giant_step = m * G
    
    # Inicializa o ponto atual como o ponto da chave pública
    current_point = public_key_point
    
    # Realiza os giant steps
    for i in range(m):
        current_point_hex = current_point.to_bytes().hex()
        if current_point_hex in baby_steps:
            # Chave privada encontrada
            private_key = (baby_steps[current_point_hex] + i * m) % order
            private_key_hex = format(private_key, '064x')
            return private_key_hex, public_key_hex
        
        # Imprimir o giant step testado
        print(f"Testando Giant Step - i: {i}")

        # Move para o próximo giant step
        current_point = current_point + (-giant_step)
    
    # Chave privada não encontrada
    return None, None

if __name__ == '__main__':
    # Chave pública fornecida
    public_key_hex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'
    
    # Definir o intervalo de chaves de 2^129 a 2^130 - 1 em hexadecimal
    min_value_hex = '0x200000000000000000000000000000000'
    max_value_hex = '0x3ffffffffffffffffffffffffffffffff'
    min_value = int(min_value_hex, 16)
    max_value = int(max_value_hex, 16)

    # Mostrar a chave pública e o intervalo
    print(f"Chave Pública: {public_key_hex}")
    print("Intervalo:")
    print(f" - De: {min_value_hex}")
    print(f" - Até: {max_value_hex}")
    print("1 - Buscando...")

    try:
        found_private_key, found_public_key = baby_step_giant_step_random(public_key_hex, min_value, max_value)
        if found_private_key:
            print(f"Chave Privada Encontrada: {found_private_key}")
            # Salvar as chaves em um arquivo de texto
            with open("chaves_encontradas.txt", "w") as file:
                file.write(f"Chave Pública: {found_public_key}\n")
                file.write(f"Chave Privada: {found_private_key}\n")
    except KeyboardInterrupt:
        print("Busca interrompida pelo usuário.")
