def encrypt(text, key):
    """Shift every alphabet character forward by 'key' positions."""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + key) % 26
            result += chr(shifted + base)
        else:
            result += char  # numbers, spaces, punctuation stay unchanged
    return result


def decrypt(text, key):
    """Reverse the shift to recover the original text."""
    return encrypt(text, -key)


def get_valid_key():
    """Keep asking until the user gives a valid integer key."""
    while True:
        raw_key = input("Enter shift key (integer, e.g. 3): ").strip()
        try:
            return int(raw_key)
        except ValueError:
            print("Invalid key. Please enter a whole number.\n")


def get_valid_text(prompt):
    """Keep asking until the user gives non-empty text."""
    while True:
        text = input(prompt)
        if text.strip() == "":
            print("Text cannot be empty. Try again.\n")
        else:
            return text


def display_result(original, key, encrypted, decrypted):
    print("\n" + "-" * 40)
    print(f"{'Original Text':15}: {original}")
    print(f"{'Key Used':15}: {key}")
    print(f"{'Encrypted Text':15}: {encrypted}")
    print(f"{'Decrypted Text':15}: {decrypted}")
    print("-" * 40)
    if decrypted == original:
        print("Status: Decryption verified — matches original text.\n")
    else:
        print("Status: Mismatch detected — check the key.\n")


def menu():
    print("=" * 40)
    print(" CAESAR CIPHER - ENCRYPTION/DECRYPTION TOOL")
    print("=" * 40)
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Encrypt and Decrypt (demo both together)")
    print("4. Exit")


def main():
    while True:
        menu()
        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            text = get_valid_text("Enter text to encrypt: ")
            key = get_valid_key()
            encrypted = encrypt(text, key)
            print(f"\nEncrypted Text: {encrypted}\n")

        elif choice == "2":
            text = get_valid_text("Enter text to decrypt: ")
            key = get_valid_key()
            decrypted = decrypt(text, key)
            print(f"\nDecrypted Text: {decrypted}\n")

        elif choice == "3":
            original = get_valid_text("Enter text to encrypt: ")
            key = get_valid_key()
            encrypted = encrypt(original, key)
            decrypted = decrypt(encrypted, key)
            display_result(original, key, encrypted, decrypted)

        elif choice == "4":
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid choice. Please select 1-4.\n")


if __name__ == "__main__":
    main()