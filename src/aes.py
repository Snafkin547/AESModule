from .utils import bitlist_to_int, int_to_bitlist, int_to_bytes_list, bytes_list_to_int, xor_bytes
from .tables import Sbox, InvSbox, Enc_mtx, Inv_mtx

Nk = 4  # Number of 32-bit words in CipherKey
Nr = 10  # Number of rounds
Nb = 4  # Block size in word


def SubBytes(state, Inv=False):
    """
    Replaces each byte in the state with the corresponding value from the SBox.
    State is a list of 16 integers (0-255).
    """
    sbox_to_use = InvSbox if Inv else Sbox
    # Direct list comprehension mapping
    return [sbox_to_use[val] for val in state]


def ShiftRows(state):
    """
    Shifts rows of the state.
    State is a list of 16 integers.
    """
    if len(state) != 16:
        raise ValueError("State must have exactly 16 elements")

    shifted = []
    for shift in range(4):
        shifted_row = [state[(i + shift) % 4 + 4 * shift] for i in range(4)]
        shifted += shifted_row
    return shifted


def InvShiftRows(state):
    if len(state) != 16:
        raise ValueError("State must have exactly 16 elements")

    shifted = []
    for shift in range(4, 0, -1):
        shifted_row = [state[(i + shift) % 4 + 4 * (4 - shift)] for i in range(4)]
        shifted += shifted_row
    return shifted


def gf_mult_by_02(b):
    """
    Returns b * 2 within GF(2^8).
    Replaces the 'mux' logic with standard bitwise operations.
    """
    if b & 0x80:  # If MSB is 1
        return ((b << 1) ^ 0x1B) & 0xFF
    else:
        return (b << 1) & 0xFF


def gf_mult_by_03(b):
    """Returns b * 3 within GF(2^8) => (b * 2) ^ b"""
    return gf_mult_by_02(b) ^ b


def gf_mult_by_09(b):
    """Returns b * 9 within GF(2^8) => (((b * 2) * 2) * 2) ^ b"""
    temp = gf_mult_by_02(gf_mult_by_02(gf_mult_by_02(b)))
    return temp ^ b


def gf_mult_by_0B(b):
    """Returns b * 0xB within GF(2^8)"""
    temp = gf_mult_by_02(gf_mult_by_02(gf_mult_by_02(b)))  # 8*b
    temp2 = gf_mult_by_02(b)  # 2*b
    return temp ^ temp2 ^ b


def gf_mult_by_0D(b):
    """Returns b * 0xD within GF(2^8)"""
    temp = gf_mult_by_02(gf_mult_by_02(gf_mult_by_02(b)))  # 8*b
    temp2 = gf_mult_by_02(gf_mult_by_02(b))  # 4*b
    return temp ^ temp2 ^ b


def gf_mult_by_0E(b):
    """Returns b * 0xE within GF(2^8)"""
    temp = gf_mult_by_02(gf_mult_by_02(gf_mult_by_02(b)))  # 8*b
    temp2 = gf_mult_by_02(gf_mult_by_02(b))  # 4*b
    temp3 = gf_mult_by_02(b)  # 2*b
    return temp ^ temp2 ^ temp3


def gf_mult_by_constant(constant, byte):
    """
    Multiplies a byte by a constant in GF(2^8).
    """
    if constant == 0x01:
        return byte
    elif constant == 0x02:
        return gf_mult_by_02(byte)
    elif constant == 0x03:
        return gf_mult_by_03(byte)
    elif constant == 0x09:
        return gf_mult_by_09(byte)
    elif constant == 0x0B:
        return gf_mult_by_0B(byte)
    elif constant == 0x0D:
        return gf_mult_by_0D(byte)
    elif constant == 0x0E:
        return gf_mult_by_0E(byte)
    else:
        raise ValueError(f"Invalid constant {constant} for multiplication in GF(2^8)")


def MixColumns(state, Inv=False):
    """
    Mixes the columns of the state matrix.
    Operates on a list of 16 byte integers.
    """
    mixed_state = []

    # Process row by row
    for idx in range(0, len(state), 4):
        # Extract a chunk of 4 bytes
        state_column = state[idx : idx + 4]
        
        # Placeholder for the output
        mixed_column = [0, 0, 0, 0]
        MixCol_mtx = Inv_mtx if Inv else Enc_mtx

        # Matrix multiplication in GF(2^8)
        for i in range(4):
            val = (
                gf_mult_by_constant(MixCol_mtx[i][0], state_column[0])
                ^ gf_mult_by_constant(MixCol_mtx[i][1], state_column[1])
                ^ gf_mult_by_constant(MixCol_mtx[i][2], state_column[2])
                ^ gf_mult_by_constant(MixCol_mtx[i][3], state_column[3])
            )
            mixed_column[i] = val
        
        mixed_state += mixed_column

    return mixed_state


def rot_word(word):
    """Rotates a list of 4 bytes."""
    return word[1:] + word[:1]


def sub_word(word):
    """Substitutes each byte in a word (list of 4 bytes) using the SBox."""
    return [Sbox[b] for b in word]


def key_expansion(key_bytes):
    """
    Expands the 128-bit key into a key schedule.
    Input: list of 16 integers (bytes).
    Output: list of integers (bytes) for all rounds.
    """
    assert len(key_bytes) == 16

    key_schedule = list(key_bytes) # Copy initial key
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    bytes_generated = len(key_schedule)
    
    # We need 44 words total (11 round keys * 4 words/key * 4 bytes/word = 176 bytes)
    while bytes_generated < Nb * (Nr + 1) * 4:
        # Read the last word (4 bytes)
        temp = key_schedule[-4:]
        
        # Every Nk words (16 bytes), we do complex transformation
        if (bytes_generated // 4) % Nk == 0:
            rotated = rot_word(temp)
            temp = sub_word(rotated)
            # XOR with Rcon. Rcon is applied to the first byte of the word only.
            rcon_idx = (bytes_generated // 16) - 1
            temp[0] = temp[0] ^ rcon[rcon_idx]

        # XOR with the word Nk positions back (16 bytes back)
        prev_word = key_schedule[-16:-12] # Get the word 4 positions back in the *word* schedule (16 bytes)
        
        new_word = [t ^ p for t, p in zip(temp, prev_word)]
        
        key_schedule.extend(new_word)
        bytes_generated += 4

    return key_schedule


def AddRoundKey(round_key, state):
    """XORs the state with the round key."""
    return xor_bytes(round_key, state)


class AES:
    def __init__(self, _key_int):
        """
        Initialize AES with a 128-bit integer key.
        """
        # Convert integer key to list of 16 bytes
        key_bytes = int_to_bytes_list(_key_int, 16)
        self.round_keys = key_expansion(key_bytes)

    def encrypt(self, plain_text_int):
        """
        Encrypts a 128-bit integer plaintext.
        Returns: (Cipher Integer, Cipher Bytes List)
        """
        # Convert integer inputs to list of 16 bytes
        state = int_to_bytes_list(plain_text_int, 16)
        
        # Round 0: AddRoundKey
        _round_keys = self.round_keys[0:16]
        state = AddRoundKey(_round_keys, state)

        # Rounds 1 to 9
        for i in range(1, Nr):
            state = SubBytes(state)
            state = ShiftRows(state)
            state = MixColumns(state)
            _round_keys = self.round_keys[i * 16 : (i + 1) * 16]
            state = AddRoundKey(_round_keys, state)

        # Round 10 (Final): No MixColumns
        state = SubBytes(state)
        state = ShiftRows(state)
        _round_keys = self.round_keys[160:176]
        state = AddRoundKey(_round_keys, state)

        cipher_int = bytes_list_to_int(state)
        
        # Return tuple to match original signature (int, list_of_something)
        # Original returned list of bits, we return list of bytes or bits depending on strictness needed.
        # The test expects `val_of(ct)` which implies looking at values. 
        # To keep maximum compatibility with logic, we return the bytes list.
        return cipher_int, state

    def decrypt(self, cipher_bytes_or_int):
        """
        Decrypts cipher text. 
        Input can be integer or list of bytes.
        """
        if isinstance(cipher_bytes_or_int, int):
             state = int_to_bytes_list(cipher_bytes_or_int, 16)
        else:
             state = cipher_bytes_or_int

        # Round 0 (Inverse of Final Round): AddRoundKey
        _round_keys = self.round_keys[160:176]
        state = AddRoundKey(_round_keys, state)

        # Rounds 9 to 1
        for i in range(Nr - 1, 0, -1):
            state = InvShiftRows(state)
            state = SubBytes(state, Inv=True)
            _round_keys = self.round_keys[i * 16 : (i + 1) * 16]
            state = AddRoundKey(_round_keys, state)
            state = MixColumns(state, Inv=True)

        # Round 10 (Inverse of Initial): No MixColumns
        state = InvShiftRows(state)
        state = SubBytes(state, Inv=True)
        _round_keys = self.round_keys[0:16]
        plain_text = AddRoundKey(_round_keys, state)

        plain_text_int = bytes_list_to_int(plain_text)
        return plain_text_int, plain_text