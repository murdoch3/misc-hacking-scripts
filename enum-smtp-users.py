# Enumerates SMTP users using VRFY requests
# Will establish a new connection in event of being disconnected

from pwn import *
import argparse

def connect(host):
    target = remote(host, 25)
    target.recv(4096)
    return target

def vrfy_user(target, user, success_code):
    print(f"Checking user {user}...")
    try:
        s = f"VRFY {user}"
        target.send(s.encode() + b"\r\n")
        response = target.recv(4096)
        if b'421' in response:
            # Indicates error with our connection to the server
            return -1
        elif success_code in response:
            return 1
        return 0
    except EOFError:
        print("[*] Connection lost")
        return -1
    return -1

def enum_users(host, user_file, success_code):
    with open(user_file, 'r') as f:
        users = [user.strip() for user in f.readlines()]

    target = connect(host)
    valid_users = []
    i = 0
    while i < len(users):
        user = users[i]
        res = vrfy_user(target, user, success_code)
        match res:
            case 1:
                print(f"[+] Valid user found: {user}")
                valid_users.append(user)
                i += 1
            case -1:
                # reconnect
                target = connect(host)
            case _:
                i += 1
    return valid_users

def main():
    parser = argparse.ArgumentParser(prog='enum_smtp_users.py', 
                                     description='Enumerates SMTP users via VRFY requests')
    parser.add_argument('target_host', help='SMTP server to target')
    parser.add_argument('user_list', help='File containing username list')
    parser.add_argument('success_code', help='Code to match for success')
    args = parser.parse_args()
    valid_users = enum_users(args.target_host, args.user_list, success_code=args.success_code.encode())
    print("\nValid users found:")
    for user in valid_users:
        print(f"- {user}")

if __name__ == '__main__':
    main()
