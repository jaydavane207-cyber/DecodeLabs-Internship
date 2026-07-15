"""
Password Strength Checker - Version 3 (Dataclass + Rule-List Style)
"""

import re
from dataclasses import dataclass

RULES = {
    "lowercase": r'[a-z]',
    "uppercase": r'[A-Z]',
    "digit": r'\d',
    "symbol": r'[!@#$%^&*(),.?":{}|<>_\-+=~`\[\];\'/\\]',
}


@dataclass
class PasswordReport:
    password: str
    length: int
    lowercase: bool
    uppercase: bool
    digit: bool
    symbol: bool
    strength: str


def evaluate_rules(password):
    """Run each regex rule against the password and return a flag dict."""
    results = {}
    for name, pattern in RULES.items():
        results[name] = re.search(pattern, password) is not None
    return results


def determine_strength(length, flags):
    passed = list(flags.values()).count(True)

    if length < 6:
        return "Weak"
    elif length < 10:
        return "Medium" if passed >= 3 else "Weak"
    else:
        if passed == 4:
            return "Strong"
        elif passed >= 2:
            return "Medium"
        else:
            return "Weak"


def build_report(password) -> PasswordReport:
    flags = evaluate_rules(password)
    length = len(password)
    strength = determine_strength(length, flags)
    return PasswordReport(
        password=password,
        length=length,
        lowercase=flags["lowercase"],
        uppercase=flags["uppercase"],
        digit=flags["digit"],
        symbol=flags["symbol"],
        strength=strength,
    )


def print_report(report: PasswordReport) -> None:
    fmt = lambda b: "Yes" if b else "No"
    print(f"\nPassword: {report.password}")
    print(f"Length: {report.length}")
    print(f"Lowercase letters: {fmt(report.lowercase)}")
    print(f"Uppercase letters: {fmt(report.uppercase)}")
    print(f"Numbers: {fmt(report.digit)}")
    print(f"Symbols: {fmt(report.symbol)}")
    print(f"Strength: {report.strength}")


def main():
    while True:
        pwd = input("\nEnter a password to check (or 'q' to quit): ")
        if pwd.lower() == 'q':
            break
        report = build_report(pwd)
        print_report(report)


if __name__ == "__main__":
    main()