import time
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

start_total = time.time()

# Étape 1 : Génération des clés ECC
print("Étape 1 : Génération des clés ECC (SECP256R1)")
start = time.time()
private_key_sender = ec.generate_private_key(ec.SECP256R1())
public_key_sender = private_key_sender.public_key()

private_key_receiver = ec.generate_private_key(ec.SECP256R1())
public_key_receiver = private_key_receiver.public_key()
end = time.time()
print(f"Temps : {end - start:.4f} secondes")

print("Clé privée (PEM) :")
print(private_key_sender.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode())

print("Clé publique (PEM) :")
print(public_key_sender.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())

# Étape 2 : Chiffrement avec ECC + AES
print("\nÉtape 2 : Chiffrement du message avec ECC + AES")
message = b"Bonjour tout le monde"
start = time.time()

# ECDH + dérivation de la clé AES
shared_key = private_key_sender.exchange(ec.ECDH(), public_key_receiver)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecies'
).derive(shared_key)

# AES-CBC avec IV
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
encryptor = cipher.encryptor()

# Padding du message
while len(message) % 16 != 0:
    message += b' '

ciphertext = iv + encryptor.update(message) + encryptor.finalize()
end = time.time()
print(f"Temps : {end - start:.4f} secondes")
print("Message chiffré (hex) :", ciphertext.hex())

# Étape 3 : Conversion en binaire
print("\nÉtape 3 : Conversion en binaire")
start = time.time()
bitstream = ''.join(format(byte, '08b') for byte in ciphertext)
end = time.time()
print(f"Temps : {end - start:.4f} secondes")
print("Flux binaire (extrait) :", bitstream[:64], "...")

# Étape 4 : Insertion dans l'image via LSB
print("\nÉtape 4 : Insertion des bits dans l’image")
start = time.time()
def embed_lsb(image_path, output_path, data):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    flat_pixels = [val for pixel in pixels for val in (pixel if isinstance(pixel, tuple) else (pixel,))]
    if len(data) > len(flat_pixels):
        raise ValueError("Message trop long pour l’image.")
    new_pixels = [(flat_pixels[i] & ~1) | int(data[i]) for i in range(len(data))] + flat_pixels[len(data):]
    if img.mode == "RGB":
        pixels = [tuple(new_pixels[i:i+3]) for i in range(0, len(new_pixels), 3)]
    else:
        pixels = new_pixels
    result = Image.new(img.mode, img.size)
    result.putdata(pixels)
    result.save(output_path)

embed_lsb("image.png", "image_stego_ecc.png", bitstream)
end = time.time()
print(f"Insertion terminée en {end - start:.4f} secondes. Image sauvegardée sous 'image_stego_ecc.png'.")

# Étape 5 : Extraction
print("\nÉtape 5 : Extraction depuis l’image")
start = time.time()
def extract_lsb(image_path, bit_length):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    flat_pixels = [val for pixel in pixels for val in (pixel if isinstance(pixel, tuple) else (pixel,))]
    bits = ''.join(str(flat_pixels[i] & 1) for i in range(bit_length))
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

ciphertext_extracted = extract_lsb("image_stego_ecc.png", len(bitstream))
end = time.time()
print(f"Extraction effectuée en {end - start:.4f} secondes.")
print("Message chiffré extrait (hex) :", ciphertext_extracted.hex())

# Étape 6 : Déchiffrement
print("\nÉtape 6 : Déchiffrement du message")
start = time.time()
shared_key_receiver = private_key_receiver.exchange(ec.ECDH(), public_key_sender)
derived_key_receiver = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecies'
).derive(shared_key_receiver)

iv_received = ciphertext_extracted[:16]
real_cipher = ciphertext_extracted[16:]

cipher = Cipher(algorithms.AES(derived_key_receiver), modes.CBC(iv_received))
decryptor = cipher.decryptor()
plaintext = decryptor.update(real_cipher) + decryptor.finalize()
end = time.time()
print(f"Déchiffrement effectué en {end - start:.4f} secondes.")
print("Message final déchiffré :", plaintext.rstrip().decode())

# Fin
end_total = time.time()
print(f"\nTemps total d'exécution : {end_total - start_total:.4f} secondes")
