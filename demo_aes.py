from src.utils import int_to_bitlist
from src.aes import AES, ShiftRows, InvShiftRows

if __name__ == "__main__":
    # --- Unit Test for ShiftRows ---
    print("--- Testing ShiftRows ---")
    temp_state = [i for i in range(0, 16)]
    print("Before:", temp_state)
    res = ShiftRows(temp_state)
    print("After: ", res)
    expected = [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14]
    assert res == expected, "ShiftRows failed"

    print("Before Inv:", res)
    InvRes = InvShiftRows(res)
    print("After Inv: ", InvRes)
    assert temp_state == InvRes, "InvShiftRows failed"
    print("ShiftRows Tests Passed.\n")

    # --- Full Encryption/Decryption Test ---
    print("--- Testing Full AES ---")

    # Test vector from original file
    int_str = 1987034928369859712
    _key = 1235282586324778

    print(f"Plaintext (Int): {int_str}")
    print(f"Key (Int):       {_key}")

    aes = AES(_key)

    # Encrypt
    cipher_int, cipher_bytes = aes.encrypt(int_str)
    print(f"Ciphertext (Int): {cipher_int}")
    print(f"Ciphertext (Hex): {hex(cipher_int)}")

    # Decrypt
    plain_int, plain_bytes = aes.decrypt(cipher_bytes)
    print(f"Decrypted (Int):  {plain_int}")

    assert plain_int == int_str, "Decryption failed to match original plaintext"
    print("AES Encryption/Decryption Test Passed.")
