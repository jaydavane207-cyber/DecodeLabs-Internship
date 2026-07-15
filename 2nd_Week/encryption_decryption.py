def encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + key) % 26
            result += chr(shifted + base)
        else:
            result += char
    return result


def decrypt(text, key):
    # decryption is just encryption with a negative key
    return encrypt(text, -key)


message = input("Enter text to encrypt: ")
key = int(input("Enter shift key (number): "))

encrypted_text = encrypt(message, key)
decrypted_text = decrypt(encrypted_text, key)

print("Original text :", message)
print("Encrypted text:", encrypted_text)
print("Decrypted text:", decrypted_text)

# check if decryption correctly restores the original message
if decrypted_text == message:
    print("Decryption successful, message matches original.")
else:
    print("Something went wrong, decrypted text does not match.")