from data import *

# Perform bit permutation according to the replacement table.
def permutation(data: list, table: list) -> list:
    """
    :param data: 64-bit initial data.
    :param table: Replacement table.
    :return: Permuted data.
    """
    return [data[i - 1] for i in table]

# Function: Permute the data according to the replacement table.
def permutation_reverse(data: list, table: list) -> list:
    """
    :param data: 64-bit initial data.
    :param table: Replacement table.
    :return: Permuted data.
    """
    return [data[table.index(i + 1)] for i in range(len(table))]

# Left rotate a list of bits by n positions
def left_shift(data: list, n: int) -> list:
    """
    :param data: Data to be shifted.
    :param n: Number of bits to shift.
    :return: Shifted data.
    """
    return data[n:] + data[:n]

# Calculate 16 groups of keys based on the key.
def calculate_keys(key: list) -> list:
    """
    :param key: 64-bit initial key of the algorithm.
    :return: 16 groups of keys, each group has 48 bits.
    """
    keys = []
    CD = permutation(key, PC_1)  # Use PC_1 substitution to output 56 bits.
    C = CD[:28]
    D = CD[28:]
    for i in range(16):
        # Perform a left circular shift on the C and D halves of the key
        C = left_shift(C, SHIFTS[i])
        D = left_shift(D, SHIFTS[i])
        # Concatenate C and D, then permute using PC_2 to generate the subkey
        K = permutation(C + D, PC_2)
        # Append the generated subkey to the keys list
        keys.append(K)
    return keys


def xor(data1: list, data2: list) -> list:
    """
    Function: Perform XOR operation on two data.
    :param data1: Data 1.
    :param data2: Data 2.
    :return: XOR result.
    """
    if len(data1) != len(data2):
        raise ValueError("The length of the two data must be the same.")
    return [a ^ b for a, b in zip(data1, data2)]

# Perform S-box compression processing. (48 bits → 32 bits)
def s_box_compression(data: list, S_list: list) -> list:
    """
    :param data: 48-bit data.
    :param S_list: S-box list.
    :return: Compressed data, 32 bits.
    """
    compressed_data = []
    for i in range(8):
        # Extract the row number from the first and last bit of the current 6-bit segment
        row = (data[i * 6] << 1) + data[i * 6 + 5]
        # Extract the column number from the middle 4 bits of the current 6-bit segment
        column = 0
        for j in range(1, 5):
            column = (column << 1) + data[i * 6 + j]
        # Retrieve the 4-bit output from the S-box and convert to binary
        s_box_value = S_list[i][row][column]
        compressed_4bit = [int(bit) for bit in f"{s_box_value:04b}"]
        # Append the 4-bit output to the result list
        compressed_data.extend(compressed_4bit)
    return compressed_data


# Encrypt the input text using the DES algorithm.
def encryption(plaintext: list, key: list) -> list:
    """
    :param plaintext: 64-bit plaintext to be encrypted.
    :param key: 56-bit key used for encryption.
    :return: 64-bit encrypted ciphertext.
    """
    # Initial permutation
    combined_text = permutation(plaintext, IP)
    L = combined_text[:32]
    R = combined_text[32:]
    # Generate 16 subkeys
    keys = calculate_keys(key)
    # 16 rounds of encryption
    for i in range(16):
        # Expansion permutation to 48 bits
        expanded_R = permutation(R, E)
        # XOR with the current key
        xor_R = xor(expanded_R, keys[i])
        # S-box compression to 32 bits
        compressed_R = s_box_compression(xor_R, S_BOX)
        # P-box permutation
        permuted_R = permutation(compressed_R, P)
        # XOR with L to get the new R
        final_R = xor(permuted_R, L)
        # Prepare for the next round
        L = R
        R = final_R
    # Combine R and L
    final_permuted = permutation(R + L, IP_INV)
    return final_permuted

# Decrypt the input text using the DES algorithm.
def decryption(ciphertext: list, key: list) -> list:
    """
    :param ciphertext: 64-bit ciphertext to be decrypted.
    :param key: 56-bit key used for decryption.
    :return: 64-bit decrypted plaintext.
    """
    # Initial permutation (inverse)
    combined_text = permutation_reverse(ciphertext, IP_INV)
    R = combined_text[:32]
    L = combined_text[32:]
    # Generate 16 subkeys and reverse the order for decryption
    keys = calculate_keys(key)[::-1]
    # 16 rounds of the DES algorithm
    for i in range(16):
        # Swap L and R for decryption
        temp = L
        final_R = R
        R = temp
        # Expansion permutation to 48 bits
        expanded_R = permutation(R, E)
        # XOR with the current key
        xor_R = xor(expanded_R, keys[i])
        # S-box compression to 32 bits
        compressed_R = s_box_compression(xor_R, S_BOX)
        # P-box permutation
        permuted_R = permutation(compressed_R, P)
        # XOR with L to get the new L
        L = xor(permuted_R, final_R)
    # Final permutation after recombining L and R
    final_permuted = permutation_reverse(L + R, IP)
    return final_permuted
