import torch
import numpy as np
from diffusers import StableDiffusionPipeline
from PIL import Image
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import reedsolo
import librosa
import soundfile as sf

# --- CONFIG ---
PAYLOAD_FILE = "malicious2.txt"
CARRIER_A_AUDIO = "carrier_a_audio_lsb.wav"
CARRIER_B_IMAGE = "carrier_b_image_lsb.png"
CARRIER_B_AUDIO = "carrier_b_from_image.wav"
INTEGRITY_FILE = "integrity_check.dat"  # NEW: Store file hashes
MODEL_ID = "riffusion/riffusion-model-v1"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
DTYPE = torch.float32
KEY_SIZE = 16
IV_SIZE = 16
RS_ECC_SYMBOLS = 64
HEADER_BITS = 32 # 32 bits (4 bytes) to store the length of the second payload

# --- UTILS ---
def bytes_to_bits(data):
    """Converts a bytes object to a string of bits."""
    return ''.join(f'{byte:08b}' for byte in data)

def embed_bits_into_image(bits, image):
    """Embeds a bit string into the LSB of an image's pixels."""
    if len(bits) > image.width * image.height * 3:
        raise ValueError("Not enough space in image to embed bits.")
    flat_pixels = np.array(image).flatten()
    for i in range(len(bits)):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bits[i])
    return Image.fromarray(flat_pixels.reshape(np.array(image).shape))

# --- CORRECTED FUNCTION ---
def embed_bits_into_audio(bits, ref_image, sample_rate=44100):
    """
    Generates audio from a reference image, embeds bits into the LSB of the
    16-bit integer samples, and returns the resulting int16 NumPy array.
    """
    spec_array = np.array(ref_image.convert('L')).astype(np.float32)
    # Generate audio as floats using Griffin-Lim
    audio_float = librosa.griffinlim(librosa.db_to_power(-80.0 + (spec_array / 255.0) * 160.0))

    if len(bits) > len(audio_float):
        raise ValueError(f"Not enough audio space. Needs {len(bits)}, has {len(audio_float)}.")

    # Clip and convert to int16 ONCE
    audio_clipped = np.clip(audio_float, -1.0, 1.0)
    samples_int16 = np.array(audio_clipped * 32767, dtype=np.int16)

    # Perform LSB embedding on the integer array
    num_samples_to_modify = len(bits)
    target_samples = samples_int16[:num_samples_to_modify]

    bit_array = np.array([int(b) for b in bits], dtype=np.int16)
    lsb_clear_mask = ~np.int16(1)  # Mask to clear the LSB (e.g., ...11111110)

    cleared_samples = target_samples & lsb_clear_mask
    stego_samples = cleared_samples | bit_array

    # Place the modified samples back into the main audio array
    samples_int16[:num_samples_to_modify] = stego_samples

    # Return the final int16 array directly to avoid float conversion errors
    return samples_int16

# --- NEW: INTEGRITY CHECK FUNCTIONS ---
def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def save_integrity_data(audio_file, image_file, integrity_file):
    """Save file hashes and metadata for integrity checking."""
    try:
        audio_hash = calculate_file_hash(audio_file)
        image_hash = calculate_file_hash(image_file)
        audio_size = os.path.getsize(audio_file)
        image_size = os.path.getsize(image_file)
        
        with open(integrity_file, 'w') as f:
            f.write(f"AUDIO_HASH:{audio_hash}\n")
            f.write(f"IMAGE_HASH:{image_hash}\n")
            f.write(f"AUDIO_SIZE:{audio_size}\n")
            f.write(f"IMAGE_SIZE:{image_size}\n")
        
        print(f"   - Integrity data saved to '{integrity_file}'")
        return True
    except Exception as e:
        print(f"   - [!!!] Could not save integrity data: {e}")
        return False

# --- MAIN ---
def main():
    print("--- Encoder: AES-CBC + Reed-Solomon + Split-Carrier LSB Steganography (v2 with Header) ---")
    pipe = StableDiffusionPipeline.from_pretrained(MODEL_ID, torch_dtype=DTYPE).to(DEVICE)

    # Step 1: Encrypt Payload
    print("\n[1] Encrypting Payload...")
    with open(PAYLOAD_FILE, 'rb') as f: payload = f.read()
    key = get_random_bytes(KEY_SIZE)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(payload, AES.block_size))
    
    # Step 2: Add Reed-Solomon ECC
    print("\n[2] Adding Reed-Solomon ECC...")
    rs = reedsolo.RSCodec(RS_ECC_SYMBOLS)
    data_to_protect = key + iv + ciphertext
    encoded_data = rs.encode(data_to_protect)

    # Step 3: Convert to bits, create header, and split
    print("\n[3] Converting to bits, creating header, and splitting...")
    full_bitstring = bytes_to_bits(encoded_data)
    half_point = len(full_bitstring) // 2
    bits_a_payload = full_bitstring[:half_point]
    bits_b_payload = full_bitstring[half_point:]
    
    len_b = len(bits_b_payload)
    header_bits = f'{len_b:0{HEADER_BITS}b}' # e.g., '000...010110' (32 chars long)
    final_bits_a = header_bits + bits_a_payload
    
    print(f"   - Total payload bits: {len(full_bitstring)}")
    print(f"   - Bits for Carrier A (payload): {len(bits_a_payload)}")
    print(f"   - Bits for Carrier B (payload): {len(bits_b_payload)}")
    print(f"   - Header created for B's length: {len_b} bits ({int(header_bits, 2)})")
    print(f"   - Total bits for Carrier A (header+payload): {len(final_bits_a)}")

    # Step 4: Embed final_bits_a into Carrier A
    print("\n[4] Generating Carrier A and embedding header + first half...")
    generator_a = torch.Generator(device=DEVICE).manual_seed(1337)
    image_a_ref = pipe("a clean sine wave spectrogram", generator=generator_a, num_inference_steps=30).images[0].convert("RGB")
    
    stego_audio_a_int16 = embed_bits_into_audio(final_bits_a, image_a_ref)
    
    # Save the int16 array directly using the appropriate subtype
    sf.write(CARRIER_A_AUDIO, stego_audio_a_int16, 44100, subtype='PCM_16')
    print(f"   - Carrier A (Audio) saved to '{CARRIER_A_AUDIO}'")

    # Step 5: Embed bits_b_payload into Carrier B
    print("\n[5] Generating Carrier B and embedding second half...")
    generator_b = torch.Generator(device=DEVICE).manual_seed(42)
    image_b_clean = pipe("cinematic orchestral music score spectrogram", generator=generator_b, num_inference_steps=50).images[0].convert("RGB")
    
    stego_image_b = embed_bits_into_image(bits_b_payload, image_b_clean)
    stego_image_b.save(CARRIER_B_IMAGE)
    print(f"   - Carrier B (Stego Image) saved to '{CARRIER_B_IMAGE}'")
    
    # This part is just for demonstration/listening; the stego data is in the image
    spec_array_b = np.array(stego_image_b.convert('L')).astype(np.float32)
    audio_b = librosa.griffinlim(librosa.db_to_power(-80.0 + (spec_array_b / 255.0) * 160.0))
    sf.write(CARRIER_B_AUDIO, audio_b, 44100)
    print(f"   - Carrier B (Final Audio for listening) saved to '{CARRIER_B_AUDIO}'")

    # NEW: Step 6: Create integrity check file
    print("\n[6] Creating integrity check file...")
    save_integrity_data(CARRIER_A_AUDIO, CARRIER_B_IMAGE, INTEGRITY_FILE)

    print("\n[✓✓✓] ENCODING COMPLETE.")

if __name__ == "__main__":
    main()