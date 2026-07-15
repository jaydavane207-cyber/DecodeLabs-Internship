def encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + key) % 26
            result += chr(shifted + base)
        else:
            result += char  # keep spaces, numbers, symbols unchanged
    return result


# quick test
message = input("Enter text to encrypt: ")
key = int(input("Enter shift key (number): "))

encrypted_text = encrypt(message, key)
print("Original text :", message)
print("Encrypted text:", encrypted_text)