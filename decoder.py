import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import reedsolo
import soundfile as sf
import os
import hashlib
import random
import getpass

# --- CONFIG (must match the encoder that created your files) ---
DECODED_OUTPUT_FILE = "DECODED_payload.txt"
CARRIER_A_AUDIO = "carrier_a_audio_lsb.wav"
CARRIER_B_IMAGE = "carrier_b_image_lsb.png"
INTEGRITY_FILE = "integrity_check.dat"  # NEW: Integrity check file
KEY_SIZE = 16
IV_SIZE = 16
RS_ECC_SYMBOLS = 64
# This header only contains the length of payload B
HEADER_BITS = 32

# --- UTILS (Unchanged) ---
def bits_to_bytes(bit_string):
    if len(bit_string) % 8 != 0:
        raise ValueError("Bitstream length is not a multiple of 8.")
    return int(bit_string, 2).to_bytes(len(bit_string) // 8, byteorder='big')

def extract_bits_from_image(image_path, num_bits):
    image = Image.open(image_path).convert("RGB")
    flat_pixels = np.array(image).flatten()
    if num_bits > len(flat_pixels):
        raise ValueError(f"Requesting {num_bits} bits, but image only has {len(flat_pixels)} pixels/values.")
    extracted_bits = [str(p & 1) for p in flat_pixels[:num_bits]]
    return "".join(extracted_bits)

def extract_bits_from_audio(audio_path, num_bits_to_extract):
    samples_int16, _ = sf.read(audio_path, dtype='int16')
    if num_bits_to_extract > len(samples_int16):
        raise ValueError(f"Requesting {num_bits_to_extract} bits, but audio only has {len(samples_int16)} samples.")
    extracted_bits = [str(s & 1) for s in samples_int16[:num_bits_to_extract]]
    return "".join(extracted_bits)

# --- NEW: INTEGRITY CHECK FUNCTIONS ---
def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def load_integrity_data(integrity_file):
    """Load stored integrity data."""
    try:
        data = {}
        with open(integrity_file, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    data[key] = value
        return data
    except Exception as e:
        print(f"   - [!!!] Could not load integrity file: {e}")
        return None

def check_file_integrity(audio_file, image_file, integrity_file):
    """Check if files have been tampered with."""
    print(f"\n[INTEGRITY CHECK] Verifying file integrity...")
    
    # Load stored integrity data
    stored_data = load_integrity_data(integrity_file)
    if not stored_data:
        print("   - [!!!] Cannot verify integrity - no integrity file found!")
        return False
    
    # Calculate current hashes and sizes
    current_audio_hash = calculate_file_hash(audio_file)
    current_image_hash = calculate_file_hash(image_file)
    current_audio_size = os.path.getsize(audio_file)
    current_image_size = os.path.getsize(image_file)
    
    # Check for tampering
    tampering_detected = False
    
    if stored_data.get('AUDIO_HASH') != current_audio_hash:
        print(f"   - [!!!] AUDIO FILE TAMPERED: Hash mismatch!")
        tampering_detected = True
    
    if stored_data.get('IMAGE_HASH') != current_image_hash:
        print(f"   - [!!!] IMAGE FILE TAMPERED: Hash mismatch!")
        tampering_detected = True
    
    if stored_data.get('AUDIO_SIZE') != str(current_audio_size):
        print(f"   - [!!!] AUDIO FILE TAMPERED: Size changed!")
        tampering_detected = True
    
    if stored_data.get('IMAGE_SIZE') != str(current_image_size):
        print(f"   - [!!!] IMAGE FILE TAMPERED: Size changed!")
        tampering_detected = True
    
    if not tampering_detected:
        print("   - [✓] Files integrity verified - no tampering detected.")
        return True
    else:
        return False

def garble_files(audio_file, image_file):
    """Garble/corrupt the files to make them unusable."""
    print(f"\n[GARBLING] Destroying tampered files...")
    
    try:
        # Garble audio file
        audio_data, sample_rate = sf.read(audio_file)
        garbled_audio = np.random.normal(0, 0.1, audio_data.shape).astype(audio_data.dtype)
        sf.write(audio_file, garbled_audio, sample_rate)
        print(f"   - [✓] Audio file '{audio_file}' has been garbled.")
        
        # Garble image file
        image = Image.open(image_file)
        image_array = np.array(image)
        garbled_image = np.random.randint(0, 256, image_array.shape, dtype=np.uint8)
        Image.fromarray(garbled_image).save(image_file)
        print(f"   - [✓] Image file '{image_file}' has been garbled.")
        
        print("   - [✓] File garbling complete - files are now unusable.")
        return True
        
    except Exception as e:
        print(f"   - [!!!] Error during file garbling: {e}")
        return False
    






def run_decoding_process():
    """Main decoding function that extracts and decrypts the hidden payload"""
    print("--- Starting Decoding Process ---")
    
    # Step 1: Read the header from Carrier A to find the length of B's payload
    print(f"\n[1] Reading header from Carrier A ('{CARRIER_A_AUDIO}')...")
    try:
        header_bits = extract_bits_from_audio(CARRIER_A_AUDIO, HEADER_BITS)
        num_bits_in_b = int(header_bits, 2)
        print(f"   - Header says Carrier B contains {num_bits_in_b} bits.")
    except Exception as e:
        print(f"   - [!!!] CRITICAL ERROR: Could not read or parse header. {e}")
        return False
    
    # Step 2: Extract the known-length payload from Carrier B
    print(f"\n[2] Extracting {num_bits_in_b} bits from Carrier B ('{CARRIER_B_IMAGE}')...")
    try:
        bits_b_payload = extract_bits_from_image(CARRIER_B_IMAGE, num_bits_in_b)
        print(f"   - Successfully extracted {len(bits_b_payload)} bits from Carrier B.")
    except Exception as e:
        print(f"   - [!!!] CRITICAL ERROR: Could not extract from Carrier B. {e}")
        return False
    
    # Step 3: Deduce the length of A and extract the EXACT number of bits
    print("\n[3] Deducing Carrier A payload length and extracting...")
    
    # We know the total length must be even, and A is roughly the same size as B.
    # So, the total length is either 2*len(B) or 2*len(B)+1.
    # From that, we can calculate len(A).
    total_length_candidate = num_bits_in_b * 2
    if (total_length_candidate / 8) % 1 != 0:
        total_length_candidate += 1
    
    num_bits_in_a = total_length_candidate - num_bits_in_b
    print(f"   - Deduced Payload A should contain {num_bits_in_a} bits.")
    
    try:
        total_bits_to_extract_from_a = HEADER_BITS + num_bits_in_a
        all_bits_from_a = extract_bits_from_audio(CARRIER_A_AUDIO, total_bits_to_extract_from_a)
        bits_a_payload = all_bits_from_a[HEADER_BITS:]
    except Exception as e:
        print(f"   - [!!!] CRITICAL ERROR: Could not extract from Carrier A. {e}")
        return False
    
    # Step 4: Recombine and convert to bytes
    full_bitstring = bits_a_payload + bits_b_payload
    print(f"\n[4] Re-combining bitstreams (A: {len(bits_a_payload)}, B: {len(bits_b_payload)}, Total: {len(full_bitstring)} bits).")
    
    try:
        encoded_data = bits_to_bytes(full_bitstring)
    except ValueError as e:
        print(f"   - [!!!] CRITICAL ERROR: {e}")
        return False
    
    # Step 5: Reed-Solomon decode
    print("\n[5] Performing Reed-Solomon decoding...")
    rs = reedsolo.RSCodec(RS_ECC_SYMBOLS)
    try:
        decoded_data, _, errata_pos = rs.decode(bytearray(encoded_data))
        if errata_pos: 
            print(f"   - Successfully corrected {len(errata_pos)} byte errors.")
        else: 
            print("   - No errors found.")
    except reedsolo.ReedSolomonError as e:
        print(f"   - [!!!] CRITICAL ERROR: Could not decode data. Too many errors. {e}")
        return False
    
    # Step 6: Decrypt payload
    print("\n[6] Parsing key/IV and decrypting payload...")
    try:
        key = bytes(decoded_data[0:KEY_SIZE])
        iv = bytes(decoded_data[KEY_SIZE : KEY_SIZE + IV_SIZE])
        ciphertext = bytes(decoded_data[KEY_SIZE + IV_SIZE :])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        payload = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError as e:
        print(f"   - [!!!] CRITICAL ERROR: Decryption failed. Incorrect key or corrupted data. {e}")
        return False
    except Exception as e:
        print(f"   - [!!!] CRITICAL ERROR: Decryption process failed. {e}")
        return False
    
    # Step 7: Save final output
    try:
        with open(DECODED_OUTPUT_FILE, 'wb') as f: 
            f.write(payload)
        print(f"\n[✓✓✓] DECODING COMPLETE.")
        print(f"    - Decoded payload saved to '{DECODED_OUTPUT_FILE}'")
        return True
    except Exception as e:
        print(f"   - [!!!] CRITICAL ERROR: Could not save decoded file. {e}")
        return False








def main():
    print("--- Decoder: For files with 32-bit (len_B) header ---")

    # NEW: Check file integrity BEFORE attempting to decode
    if not check_file_integrity(CARRIER_A_AUDIO, CARRIER_B_IMAGE, INTEGRITY_FILE):
        print("\n" + "="*60)
        print("🚨 TAMPERING DETECTED! 🚨")
        print("The steganographic files have been modified!")
        print("Initiating file destruction protocol...")
        print("="*60)
        
        # Garble the files
        if garble_files(CARRIER_A_AUDIO, CARRIER_B_IMAGE):
            print("\n[✓✓✓] SECURITY PROTOCOL COMPLETE.")
            print("Files have been destroyed to prevent unauthorized access.")
        else:
            print("\n[!!!] File destruction failed - manual intervention required.")
        
        return  # Exit without decoding
    
    





    print("=== PASSWORD AUTHENTICATION ===")
    
    for attempt in range(2):
        remaining_attempts = 2 - attempt
        print(f"\nAttempt {attempt + 1} of {2}")
        
        try:
            password = getpass.getpass(f"Enter passphrase to unlock ({remaining_attempts} attempts remaining): ")
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            return False
        
        if password == "abc":
            print("\n✅ Access granted!")
            run_decoding_process()
            return True
        else:
            if attempt <2 - 1:
                print("❌ Incorrect passphrase. Please try again.")
            else:
                print("❌ Maximum attempts exceeded!")
                print("🚨 SECURITY BREACH DETECTED!")
                garble_files(CARRIER_A_AUDIO, CARRIER_B_IMAGE)
                return False





if __name__ == "__main__":
    main()