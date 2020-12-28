import os
import argparse
from password_checker import pwned_api_check

parser = argparse.ArgumentParser(prog='pwnedPassword', description="Checks if the password is pwned or not...")

p = parser.add_mutually_exclusive_group()

p.add_argument("-p",
               "--passwords",
               nargs="*",
               help="passwords to be checked")
p.add_argument("-f",
               "--file",
               help="file containing passwords")
parser.add_argument("-s",
                    "--save",
                    action="store_true",
                    help="save passwords with its count in an output file")

args = parser.parse_args()

password_counts = []


def check_passwords(password_list):
    for password in password_list:
        count = pwned_api_check(password)
        if count:
            print(f"{password} has been pwned {count} times before...")
        else:
            print(f"{password} has not been pwned.")
        password_counts.append((password, count))
    print("\nNOTE: Pwned passwords have previously appeared in a data breach and should never be used. If you've "
          "ever used it anywhere before, change it!")


if args.passwords:
    check_passwords(args.passwords)

if args.file:
    if os.path.exists(args.file):
        with open(args.file, "r") as file:
            passwords = [password.split("\n")[0] for password in file.readlines()]
            check_passwords(passwords)
    else:
        try:
            raise FileNotFoundError(f"File {args.file} was not found...")
        except FileNotFoundError as err:
            print(err)

if args.save:
    with open("password_counts.csv", "w") as file:
        file.write("password, counts\n")
        for password, count in password_counts:
            file.write(f"{password}, {count}\n")
