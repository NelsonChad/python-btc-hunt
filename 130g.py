import random
import binascii
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import sys

def generate_private_key_in_range(start_range, end_range):
    """Generates a private key within a specified range.

    Args:
        start_range (int): The lower bound of the range for private key generation.
        end_range (int): The upper bound of the range for private key generation.

    Returns:
        str: The generated private key in hexadecimal format.
    """
    # Generate a random integer in the specified range [start_range, end_range]
    private_key_int = random.randint(start_range, end_range)

    # Convert the integer to hexadecimal format
    private_key_hex = hex(private_key_int)[2:].zfill(64)  # 64 characters (32 bytes)

    return private_key_hex

def compute_public_key(private_key_hex, compressed=True):
    """Computes the public key from a given private key.

    Args:
        private_key_hex (str): The private key in hexadecimal format.
        compressed (bool): Whether to compute the public key in compressed format.

    Returns:
        str: The computed public key in hexadecimal format.
    """
    # Convert the private key from hexadecimal to bytes
    private_key_bytes = binascii.unhexlify(private_key_hex)

    # Generate the signing key from the private key bytes
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Get the verifying key
    vk = sk.verifying_key

    # Compute the public key in compressed or uncompressed format
    if compressed:
        public_key = vk.to_string("compressed")
    else:
        public_key = vk.to_string("uncompressed")

    # Convert the public key bytes to hexadecimal format
    public_key_hex = binascii.hexlify(public_key).decode('utf-8')

    return public_key_hex

def find_private_key(public_key_hex, start_range, end_range):
    """Attempts to find the private key corresponding to a given public key within a specified range.

    Args:
        public_key_hex (str): The public key in hexadecimal format (compressed).
        start_range (int): The lower bound of the range for private key generation.
        end_range (int): The upper bound of the range for private key generation.

    Returns:
        str: The computed private key if found, or None if not found.
    """
    # Convert the public key from hexadecimal to bytes
    public_key_bytes = binascii.unhexlify(public_key_hex)

    # Create a verifying key object
    vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)

    # Attempt to find the private key within the specified range
    used_private_keys = set()
    while True:
        private_key_hex = generate_private_key_in_range(start_range, end_range)

        # Skip if private key has already been used
        if private_key_hex in used_private_keys:
            continue

        used_private_keys.add(private_key_hex)

        # Compute the public key from the private key
        computed_public_key_hex = compute_public_key(private_key_hex, compressed=True)

        #print(f"PrK: {private_key_hex}")
        #print(f"puK: {computed_public_key_hex}")
        #print(f"---: {public_key_hex}")
        #print("-------------------------------------------------------------------------")

        # Compare the computed public key with the given public key
        if computed_public_key_hex == public_key_hex:
            return private_key_hex

def main():
    """Main function."""
    try:
        public_key_hex = "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852"
        start_range = 2**129  # 0x200000000000000000000000000000000
        end_range = 2**130 - 1  # 0x3ffffffffffffffffffffffffffffffff

        print(f"Searching for private key corresponding to public key: {public_key_hex}")
        print(f" - From: {hex(start_range)}")
        print(f" - To: {hex(end_range)}")

        # Attempt to find the corresponding private key within the specified range
        private_key = find_private_key(public_key_hex, start_range, end_range)
        if private_key:
            print(f"Found private key: {private_key}")
            # Salvar as chaves em um arquivo de texto
            with open("found_keys.txt", "w") as file:
                file.write(f"Public Key: {public_key_hex}\n")
                file.write(f"Private Key: {private_key}\n")
        else:
            print("Private key not found within the specified range.")
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")

if __name__ == "__main__":
    main()
