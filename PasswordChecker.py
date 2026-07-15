import re


def check_password_strength(password):
    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=~`\[\];\'/\\]', password))

    # Count how many character-type checks passed
    checks_passed = sum([has_lower, has_upper, has_digit, has_symbol])

    # Determine strength
    if length < 6:
        strength = "Weak"
    elif length >= 6 and length < 10:
        if checks_passed >= 3:
            strength = "Medium"
        else:
            strength = "Weak"
    else:  # length >= 10
        if checks_passed == 4:
            strength = "Strong"
        elif checks_passed >= 2:
            strength = "Medium"
        else:
            strength = "Weak"

    return strength, {
        "length": length,
        "lowercase": has_lower,
        "uppercase": has_upper,
        "digit": has_digit,
        "symbol": has_symbol,
    }


def print_report(password):
    strength, details = check_password_strength(password)
    print(f"\nPassword: {password}")
    print(f"Length: {details['length']}")
    print(f"Lowercase letters: {'Yes' if details['lowercase'] else 'No'}")
    print(f"Uppercase letters: {'Yes' if details['uppercase'] else 'No'}")
    print(f"Numbers: {'Yes' if details['digit'] else 'No'}")
    print(f"Symbols: {'Yes' if details['symbol'] else 'No'}")
    print(f"Strength: {strength}")


if __name__ == "__main__":
    while True:
        pwd = input("\nEnter a password to check (or 'q' to quit): ")
        if pwd.lower() == 'q':
            break
        print_report(pwd)