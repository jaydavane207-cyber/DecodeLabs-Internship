import re

# Each rule: (label, regex pattern)
CHARACTER_RULES = {
    "lowercase": r'[a-z]',
    "uppercase": r'[A-Z]',
    "digit": r'\d',
    "symbol": r'[!@#$%^&*(),.?":{}|<>_\-+=~`\[\];\'/\\]',
}


def get_password_stats(password):
    stats = {"length": len(password)}
    for label, pattern in CHARACTER_RULES.items():
        stats[label] = bool(re.search(pattern, password))
    return stats


def determine_strength(stats):
    length = stats["length"]
    passed = sum(stats[label] for label in CHARACTER_RULES)

    if length < 6:
        return "Weak"

    if length < 10:
        return "Medium" if passed >= 3 else "Weak"

    if passed == 4:
        return "Strong"
    elif passed >= 2:
        return "Medium"
    return "Weak"


def format_yes_no(flag):
    return "Yes" if flag else "No"


def print_password_report(password):
    stats = get_password_stats(password)
    strength = determine_strength(stats)

    print(f"\nPassword: {password}")
    print(f"Length: {stats['length']}")
    print(f"Lowercase letters: {format_yes_no(stats['lowercase'])}")
    print(f"Uppercase letters: {format_yes_no(stats['uppercase'])}")
    print(f"Numbers: {format_yes_no(stats['digit'])}")
    print(f"Symbols: {format_yes_no(stats['symbol'])}")
    print(f"Strength: {strength}")


def main():
    while True:
        entered_password = input("\nEnter a password to check (or 'q' to quit): ")
        if entered_password.lower() == 'q':
            break
        print_password_report(entered_password)


if __name__ == "__main__":
    main()