import itertools
import string
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def is_printable_text(text):
    """
    Check if the decrypted text appears to be a readable ASCII message
    Criteria:
    - Contains mostly printable ASCII characters
    - Has a reasonable ratio of printable to total characters
    """
    try:
        decoded_text = text.decode('ascii')
        printable_chars = sum(1 for c in decoded_text if c.isprintable() or c.isspace())
        return printable_chars / len(decoded_text) > 0.8
    except:
        return False

def generate_key_variants(base_key, unknown_chars):
    """
    Generate all possible key combinations
    """
    # Characters to use for brute force
    chars = string.ascii_letters + string.digits
    
    # Replace X with all possible character combinations
    unknown_positions = [i for i, c in enumerate(base_key) if c == 'X']
    
    for combination in itertools.product(chars, repeat=len(unknown_positions)):
        current_key = list(base_key)
        for pos, char in zip(unknown_positions, combination):
            current_key[pos] = char
        yield ''.join(current_key)

def crack_aes_ecb(cipher_hex, base_key):
    """
    Attempt to crack AES-ECB encryption by brute-forcing the key
    """
    # Convert hex to bytes
    cipher_bytes = bytes.fromhex(cipher_hex)
    
    # Track performance
    attempts = 0
    start_time = time.time()
    
    # Try all possible key combinations
    for key in generate_key_variants(base_key, unknown_chars='X'):
        attempts += 1
        
        try:
            # Create AES cipher in ECB mode
            cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
            
            # Attempt decryption
            decrypted = cipher.decrypt(cipher_bytes)
            
            # Remove PKCS7 padding
            try:
                unpadded = unpad(decrypted, AES.block_size)
            except:
                continue
            
            # Check if decrypted text looks like readable ASCII
            if is_printable_text(unpadded):
                end_time = time.time()
                print(f"Success! Key found: {key}")
                print(f"Decrypted text: {unpadded.decode('ascii')}")
                print(f"Total attempts: {attempts}")
                print(f"Time taken: {end_time - start_time:.2f} seconds")
                print(f"Keys tested per second: {attempts / (end_time - start_time):.2f}")
                return key, unpadded.decode('ascii')
        
        except Exception as e:
            # Silently continue if decryption fails
            continue
    
    return None, None

def main():
    # Weak key scenario
    weak_file = "arquivo-weak-4.in-full.hex"
    weak_base_key = "SecurityAES" + "X" * 5
    
    print("Cracking Weak Key Scenario:")
    with open(weak_file, 'r') as f:
        weak_cipher_hex = f.read().strip()
    
    weak_key, weak_text = crack_aes_ecb(weak_cipher_hex, weak_base_key)
    
    # Strong key scenario
    strong_file = "arquivo-strong-4.in-full.hex"
    strong_base_key = "Security00" + "X" * 6
    
    print("\nCracking Strong Key Scenario:")
    with open(strong_file, 'r') as f:
        strong_cipher_hex = f.read().strip()
    
    strong_key, strong_text = crack_aes_ecb(strong_cipher_hex, strong_base_key)

if __name__ == "__main__":
    main()