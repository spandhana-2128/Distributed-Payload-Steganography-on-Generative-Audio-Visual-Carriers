# Create this as tamper_test.py
with open('carrier_a_audio_lsb.wav', 'ab') as f:
    f.write(b'X')  # Add one byte
print("File tampered!")