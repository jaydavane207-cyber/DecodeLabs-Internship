import string

SYMBOLS = '!@#$%^&*(),.?":{}|<>_-+=~`[];\'/\\'


def contains_any(password, char_set):
    return any(ch in char_set for ch in password)


def analyze_password(password):
    analysis = {
        "length": len(password),
        "lowercase": contains_any(password, string.ascii_lowercase),
        "uppercase": contains_any(password, string.ascii_uppercase),
        "digit": contains_any(password, string.digits),
        "symbol": contains_any(password, SYMBOLS),
    }
    return analysis


def classify_strength(analysis):
    length = analysis["length"]
    checks_passed = sum([
        analysis["lowercase"],
        analysis["uppercase"],
        analysis["digit"],
        analysis["symbol"],
    ])

    if length < 6:
        return "Weak"

    if length < 10:
        return "Medium" if checks_passed >= 3 else "Weak"

    # length >= 10
    if checks_passed == 4:
        return "Strong"
    if checks_passed >= 2:
        return "Medium"
    return "Weak"


def display_report(password):
    analysis = analyze_password(password)
    strength = classify_strength(analysis)

    yes_no = lambda flag: "Yes" if flag else "No"

    print(f"\nPassword: {password}")
    print(f"Length: {analysis['length']}")
    print(f"Lowercase letters: {yes_no(analysis['lowercase'])}")
    print(f"Uppercase letters: {yes_no(analysis['uppercase'])}")
    print(f"Numbers: {yes_no(analysis['digit'])}")
    print(f"Symbols: {yes_no(analysis['symbol'])}")
    print(f"Strength: {strength}")


def run():
    while True:
        user_input = input("\nEnter a password to check (or 'q' to quit): ")
        if user_input.strip().lower() == 'q':
            break
        display_report(user_input)


if __name__ == "__main__":
    run()