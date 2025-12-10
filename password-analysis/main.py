def main():
    from auth import register_user, authenticate, get_totp_uri #importing functions from the auth.py script

    username = "alice"
    password = "Str0ng!Passw0rd"

    try:
        record = register_user(username, password)
        print(f"Registered {record['username']}")
        print(f"TOTP provisioning URI: {get_totp_uri(username)}")
    except ValueError as e:
        print(f"Registration failed: {e}")

    # Attempt authentication
    ok = authenticate(username, password)
    print(f"Authentication with correct password: {ok}")

    ok = authenticate(username, "wrong-password")
    print(f"Authentication with wrong password: {ok}")


if __name__ == "__main__":
    main()
