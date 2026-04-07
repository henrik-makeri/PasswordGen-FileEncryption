from __future__ import annotations

import argparse

from .files import decrypt_file, encrypt_file, read_password
from .hashing import HASH_ALGORITHMS, hash_file, hash_text
from .passwords import (
    PasswordOptions,
    classify_entropy_bits,
    classify_strength,
    estimate_entropy_bits,
    estimate_pronounceable_entropy_bits,
    generate_password,
    generate_pronounceable_password,
)


def build_parser() -> argparse.ArgumentParser:
    # cli args live here
    parser = argparse.ArgumentParser(
        prog="crypto-tools",
        description="Generate strong passwords, encrypt files, hash data, or launch the desktop GUI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    password_parser = subparsers.add_parser("password", help="Generate a password.")
    password_parser.add_argument("--length", type=int, default=16, help="Password length.")
    password_parser.add_argument(
        "--count", type=int, default=1, help="How many passwords to generate."
    )
    password_parser.add_argument(
        "--mode",
        choices=["random", "pronounceable"],
        default="random",
        help="Password generation mode.",
    )
    password_parser.add_argument(
        "--words",
        type=int,
        default=4,
        help="How many words to use in pronounceable mode.",
    )
    password_parser.add_argument(
        "--no-uppercase", action="store_true", help="Exclude uppercase letters."
    )
    password_parser.add_argument(
        "--no-lowercase", action="store_true", help="Exclude lowercase letters."
    )
    password_parser.add_argument(
        "--no-numbers", action="store_true", help="Exclude numeric characters."
    )
    password_parser.add_argument(
        "--symbols", action="store_true", help="Include symbol characters."
    )
    password_parser.add_argument(
        "--show-strength",
        action="store_true",
        help="Print an estimated strength label and entropy after each password.",
    )

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file with a password.")
    encrypt_parser.add_argument("source", help="Path to the input file.")
    encrypt_parser.add_argument("-o", "--output", help="Path for the encrypted file.")
    encrypt_parser.add_argument("-p", "--password", help="Password to use.")
    encrypt_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite an existing output file."
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted file.")
    decrypt_parser.add_argument("source", help="Path to the encrypted file.")
    decrypt_parser.add_argument("-o", "--output", help="Path for the decrypted file.")
    decrypt_parser.add_argument("-p", "--password", help="Password to use.")
    decrypt_parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite an existing output file."
    )

    hash_parser = subparsers.add_parser("hash", help="Hash text or a file.")
    target_group = hash_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--text", help="Text to hash.")
    target_group.add_argument("--file", help="Path to a file to hash.")
    hash_parser.add_argument(
        "--algorithm",
        choices=sorted(HASH_ALGORITHMS),
        default="sha256",
        help="Hash algorithm to use.",
    )

    subparsers.add_parser("gui", help="Launch the desktop GUI.")

    return parser


def _password_options_from_args(args: argparse.Namespace) -> PasswordOptions:
    # map cli flags into the options object
    return PasswordOptions(
        length=args.length,
        uppercase=not args.no_uppercase,
        lowercase=not args.no_lowercase,
        numbers=not args.no_numbers,
        symbols=args.symbols,
    )


def _run_password_command(args: argparse.Namespace) -> int:
    if args.count < 1:
        raise ValueError("--count must be at least 1.")

    if args.mode == "pronounceable":
        if args.words < 1:
            raise ValueError("--words must be at least 1.")

        entropy = estimate_pronounceable_entropy_bits(args.words)
        strength = classify_entropy_bits(entropy)
        for _ in range(args.count):
            # same word count, same strength label
            print(generate_pronounceable_password(args.words))
            if args.show_strength:
                print(f"Strength: {strength} ({entropy:.1f} bits)")
        return 0

    options = _password_options_from_args(args)
    strength = classify_strength(options)
    entropy = estimate_entropy_bits(options)

    for _ in range(args.count):
        print(generate_password(options))
        if args.show_strength:
            print(f"Strength: {strength} ({entropy:.1f} bits)")

    return 0


def _run_encrypt_command(args: argparse.Namespace) -> int:
    password = read_password(args.password)
    output_path = encrypt_file(
        args.source,
        password,
        destination=args.output,
        overwrite=args.overwrite,
    )
    print(f"Encrypted: {output_path}")
    return 0


def _run_decrypt_command(args: argparse.Namespace) -> int:
    password = read_password(args.password)
    output_path = decrypt_file(
        args.source,
        password,
        destination=args.output,
        overwrite=args.overwrite,
    )
    print(f"Decrypted: {output_path}")
    return 0


def _run_hash_command(args: argparse.Namespace) -> int:
    if args.text is not None:
        print(hash_text(args.text, args.algorithm))
        return 0

    print(hash_file(args.file, args.algorithm))
    return 0


def _run_gui_command() -> int:
    # import late so plain cli use still works
    from .gui import launch_gui

    return launch_gui()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command

    try:
        if command == "password":
            return _run_password_command(args)
        if command == "encrypt":
            return _run_encrypt_command(args)
        if command == "decrypt":
            return _run_decrypt_command(args)
        if command == "hash":
            return _run_hash_command(args)
        if command == "gui":
            return _run_gui_command()
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        parser.exit(2, f"Error: {exc}\n")

    parser.exit(2, "Unknown command.\n")
    return 2
