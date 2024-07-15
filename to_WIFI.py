import hashlib
import base58

def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def private_key_to_wif(private_key_hex, compressed=False):
    # Passo 1: Adicionar prefixo 0x80
    private_key_bytes = bytes.fromhex('80' + private_key_hex)
    
    # Passo 2: Adicionar sufixo 0x01 se comprimido
    if compressed:
        private_key_bytes += b'\x01'
    
    # Passo 3: Calcular checksum
    checksum = hash256(private_key_bytes)[:4]
    
    # Passo 4: Adicionar checksum ao final
    private_key_wif = private_key_bytes + checksum
    
    # Passo 5: Codificar em Base58Check
    wif = base58.b58encode(private_key_wif)
    
    return wif.decode()

# Exemplo de chave privada
private_key_hex = '000000000000000000000000000000000000000000000001a838b13505b26867'
wif_key = private_key_to_wif(private_key_hex, compressed=True)
print(f'Chave Privada WIF: {wif_key}')
