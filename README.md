# Adaptive-Steganography
# Adaptive Steganography

Concept for hiding encrypted payload data across two AI-generated carrier media files (an audio spectrogram and an image), designed to resist tampering and basic digital forensics analysis.

1. **Encryption** — The payload file is encrypted using AES-CBC with a randomly generated key and IV.
2. **Error Correction** — Reed-Solomon error correction codes (ECC) are added to the encrypted data so it can survive minor corruption.
3. **AI-Generated Carriers** — Two carrier media files are generated using a Stable Diffusion pipeline (`riffusion/riffusion-model-v1`), producing realistic-looking spectrogram images that double as carriers for hidden data.
4. **Split-Carrier LSB Embedding** — The encoded payload is split in half and embedded into the least significant bits (LSB) of:
   - **Carrier A** — a generated audio file (with a header encoding payload length)
   - **Carrier B** — a generated image file
5. **Integrity Verification** — SHA-256 hashes and file sizes of both carriers are recorded in an integrity file so any tampering can be detected later.

## Files

| File | Purpose |
|---|---|
| `encoder.py` | Encrypts, error-corrects, and embeds the payload across both carriers; generates an integrity file |
| `decoder.py` | Extracts and reconstructs the original payload from the two carriers, verifying integrity along the way |
| `tamper.py` | A simple test script that appends a byte to the audio carrier file, used to simulate tampering and test integrity detection |
| `malicious2.txt` | Sample payload file used as the default input for encoding |

## Tech Stack

- **AI Generation:** `diffusers` (Stable Diffusion / Riffusion), `torch`
- **Cryptography:** `pycryptodome` (AES-CBC encryption)
- **Error Correction:** `reedsolo`
- **Audio Processing:** `librosa`, `soundfile`
- **Image Processing:** `Pillow`, `numpy`

## Installation

1. Clone the repository
   ```bash
   git clone https://github.com/spandhana-2128/adaptive-steganography.git
   cd adaptive-steganography
   ```

2. Install dependencies
   ```bash
   pip install torch numpy diffusers pillow pycryptodome reedsolo librosa soundfile
   ```
   > Note: there's no `requirements.txt` in this repo yet — these are the packages imported directly in the code. A GPU (CUDA) is recommended for running the Stable Diffusion pipeline at reasonable speed, though it will fall back to CPU automatically if unavailable.

3. Make sure you have a payload file (default expected: `malicious2.txt`) in the project root, or update the `PAYLOAD_FILE` variable in `encoder.py`.

## Usage

**Encode a payload:**
```bash
python encoder.py
```
This generates `carrier_a_audio_lsb.wav`, `carrier_b_image_lsb.png`, `carrier_b_from_image.wav`, and `integrity_check.dat`.

**Decode a payload:**
```bash
python decoder.py
```
Extracts the original payload from the two carrier files.

**Test tamper detection:**
```bash
python tamper.py
```
Appends a byte to `carrier_a_audio_lsb.wav` to simulate file tampering, then re-run the decoder to see integrity verification fail.


