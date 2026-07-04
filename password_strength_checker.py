# ============================================
# Project 1: Password Strength Checker
# Intern: Arooj Fatima Rizvi
# Organization: DecodeLabs | Batch 2026
# Track: Cybersecurity Analyst
# ============================================

import string

def evaluate_password(pwd):
    """
    Evaluates a given password and returns its strength
    along with detailed feedback for the user.
    """

    score = 0
    feedback = []

    # --- Rule 1: Length Check ---
    if len(pwd) < 8:
        return "WEAK", ["Password must be at least 8 characters long."]

    if len(pwd) >= 8:
        score += 1
    if len(pwd) >= 12:
        score += 1  # bonus for longer passwords

    # --- Rule 2: Uppercase Letter Check ---
    has_upper = any(ch.isupper() for ch in pwd)
    if has_upper:
        score += 1
    else:
        feedback.append("Add at least one uppercase letter (A-Z).")

    # --- Rule 3: Lowercase Letter Check ---
    has_lower = any(ch.islower() for ch in pwd)
    if has_lower:
        score += 1
    else:
        feedback.append("Add at least one lowercase letter (a-z).")

    # --- Rule 4: Digit Check ---
    has_digit = any(ch.isdigit() for ch in pwd)
    if has_digit:
        score += 1
    else:
        feedback.append("Include at least one number (0-9).")

    # --- Rule 5: Special Symbol Check ---
    special_chars = set(string.punctuation)
    has_symbol = any(ch in special_chars for ch in pwd)
    if has_symbol:
        score += 1
    else:
        feedback.append("Add a special character (e.g., @, #, $, !).")

    # --- Rule 6: Common & Personal Name Check ---
    # I added this rule because attackers always try common words first.
    # Using your own name or simple words makes a password very easy to guess.
    common_passwords = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "welcome", "monkey", "dragon", "master", "sunshine",
        "arooj", "admin", "login", "iloveyou", "pakistan"
    ]
    if pwd.lower() in common_passwords:
        return "WEAK", ["This is a commonly used password. Attackers can guess it instantly. Please choose something unique."]

    # --- Strength Classification ---
    if score <= 3:
        strength = "WEAK"
    elif score <= 5:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    return strength, feedback


def display_result(password, strength, feedback):
    """
    Displays the evaluation result in a clean, readable format.
    """
    print("\n" + "=" * 45)
    print(f"  Password Entered : {'*' * len(password)}")
    print(f"  Strength Level   : {strength}")
    print("=" * 45)

    if strength == "STRONG":
        print("  [✔] Your password meets all security criteria.")
    else:
        print("  [!] Suggestions to improve your password:")
        for tip in feedback:
            print(f"      → {tip}")

    print("=" * 45 + "\n")


def main():
    print("\n╔══════════════════════════════════════════╗")
    print("║      PASSWORD STRENGTH CHECKER           ║")
    print("║      DecodeLabs | Cybersecurity Track    ║")
    print("╚══════════════════════════════════════════╝\n")

    while True:
        user_input = input("Enter a password to evaluate (or 'quit' to exit): ").strip()

        if user_input.lower() == 'quit':
            print("\n[✔] Session ended. Stay secure!\n")
            break

        if not user_input:
            print("[!] No input detected. Please enter a password.\n")
            continue

        strength, feedback = evaluate_password(user_input)
        display_result(user_input, strength, feedback)

        again = input("Check another password? (yes/no): ").strip().lower()
        if again != 'yes':
            print("\n[✔] Thank you for using Password Strength Checker. Stay safe!\n")
            break


if __name__ == "__main__":
    main()
