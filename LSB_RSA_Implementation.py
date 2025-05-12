
# Programme complet : Stéganographie LSB + Chiffrement RSA avec affichage et temps

import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from PIL import Image

start_total = time.time()

# Étape 1 : Génération des clés RSA
start = time.time()
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
end = time.time()
print(f"Étape 1 : Génération des clés RSA (2048 bits) en {end - start:.4f} secondes")
print("Clé privée RSA (PEM) :")
print(private_key.private_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()).decode())
print("Clé publique RSA (PEM) :")
print(public_key.public_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())

# Étape 2 : Chiffrement du message
message = b"Bonjour tout le monde"
start = time.time()
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end = time.time()
print(f"\nÉtape 2 : Chiffrement en {end - start:.4f} secondes")
print("Message chiffré (hex) :", ciphertext.hex())

# Étape 3 : Conversion en binaire
start = time.time()
bitstream = ''.join(format(byte, '08b') for byte in ciphertext)
end = time.time()
print(f"\nÉtape 3 : Conversion en binaire en {end - start:.4f} secondes")
print("Flux binaire (extrait) :", bitstream[:64], "...")

# Étape 4 : Insertion dans LSB
print("\nÉtape 4 : Insertion des bits dans l’image...")
start = time.time()
def embed_lsb(image_path, output_path, data):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    flat_pixels = [val for pixel in pixels for val in (pixel if isinstance(pixel, tuple) else (pixel,))]
    new_pixels = [(flat_pixels[i] & ~1) | int(data[i]) for i in range(len(data))] + flat_pixels[len(data):]
    if img.mode == "RGB":
        pixels = [tuple(new_pixels[i:i+3]) for i in range(0, len(new_pixels), 3)]
    else:
        pixels = new_pixels
    result = Image.new(img.mode, img.size)
    result.putdata(pixels)
    result.save(output_path)
embed_lsb("image.png", "image_stego_rsa.png", bitstream)
end = time.time()
print(f"Insertion terminée en {end - start:.4f} secondes. Image sauvegardée sous 'image_stego_rsa.png'.")

# Étape 5 : Extraction
print("\nÉtape 5 : Extraction des bits depuis l’image...")
start = time.time()
def extract_lsb(image_path, bit_length):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    flat_pixels = [val for pixel in pixels for val in (pixel if isinstance(pixel, tuple) else (pixel,))]
    bits = ''.join(str(flat_pixels[i] & 1) for i in range(bit_length))
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
extracted_cipher = extract_lsb("image_stego_rsa.png", len(bitstream))
end = time.time()
print(f"Extraction effectuée en {end - start:.4f} secondes.")
print("Message chiffré extrait (hex) :", extracted_cipher.hex())

# Étape 6 : Déchiffrement
print("\nÉtape 6 : Déchiffrement du message...")
start = time.time()
plaintext = private_key.decrypt(
    extracted_cipher,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end = time.time()
print(f"Déchiffrement effectué en {end - start:.4f} secondes.")
print("Message final déchiffré :", plaintext.decode())

end_total = time.time()
print(f"\nTemps total d'exécution : {end_total - start_total:.4f} secondes")
