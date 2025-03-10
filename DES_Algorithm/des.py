# Tablice S-bloków
sbox = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Tablica permutacji
permutation_table = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
]


# Tablica przesunięć dla rund
round_shifts = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

round_key_shifts = [
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2
]

# Rozszerzenia bitów dla permutacji
extend_bits_table = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

# Tablica permutacji początkowej
initial_permutation_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Tablica permutacji końcowej
final_permutation_table = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
]

key_compression_permutation = [
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Tablica permutacji klucza początkowego
initial_key_permutation = [
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
]

# Tablica permutacji końcowej klucza rundowego
final_key_permutation = [
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]


# Rundy szyfrowania DES
rounds = 16

def pad(data):
    if len(data) % 8 != 0:
        padding_length = 8 - (len(data) % 8)
        padding = bytes([padding_length]) * padding_length
        return data + padding
    else:
        return data

def unpad(data):
    pad_length = data[-1]
    if pad_length > 0 and pad_length <= 8:
        return data[:-pad_length]
    else:
        return data

# Funkcja wykonująca pojedynczą rundę DES
def des_round(block, subkey):
    expanded_block = [block[i - 1] for i in extend_bits_table]  # Rozszerzanie bitów
    xored_block = [int(expanded_block[i]) ^ int(subkey[i]) for i in range(48)]  # XOR z podkluczem rundy

    # Rozbicie na 8 bloków po 6 bitów
    sub_blocks = [xored_block[i:i + 6] for i in range(0, 48, 6)]

    # Podstawienie S-bloków
    substituted_block = []
    for i in range(8):
        row = (sub_blocks[i][0] << 1) + sub_blocks[i][-1]
        column = (sub_blocks[i][1] << 3) + (sub_blocks[i][2] << 2) + (sub_blocks[i][3] << 1) + sub_blocks[i][4]
        val = sbox[i][row][column]
        substituted_block.extend([(val >> j) & 1 for j in range(3, -1, -1)])

    # Permutacja P
    permuted_block = [substituted_block[i - 1] for i in permutation_table]

    return permuted_block

# Funkcja szyfrująca DES
def encrypt_des(bits_list, key):
    # Konwertujemy klucz na bajty
    key = bytes.fromhex(key)
    key = ''.join(format(byte, '08b') for byte in key)

    bytes_data = int(''.join(bits_list), 2).to_bytes((len(bits_list) + 7) // 8, byteorder='big')
    bytes_data = pad(bytes_data)
    bits_list = ''.join(format(byte, '08b') for byte in bytes_data)

    # Tworzenie podkluczy
    subkeys = generate_subkeys(key)

    # Permutacja początkowa
    permuted_bits = [bits_list[i - 1] for i in initial_permutation_table]

    # Podział na bloki
    blocks = [permuted_bits[i:i + 64] for i in range(0, len(permuted_bits), 64)]


    # Szyfrowanie danych wejściowych blok po bloku
    encrypted_bits = ""
    for i in range(0, len(bits_list), 64):
        # Dzielimy dane na bloki 64-bitowe
        block = bits_list[i:i+64]

        # Permutacja początkowa
        permuted_block = [block[j - 1] for j in initial_permutation_table]

        # Dzielimy na lewą i prawą połowę
        left_half = permuted_block[:32]
        right_half = permuted_block[32:]

        # 16 rund DES
        for round_key in subkeys:
            next_right_half = [str(int(left) ^ right) for left, right in zip(left_half, des_round(right_half, round_key))]
            left_half = right_half
            right_half = next_right_half

        # Permutacja końcowa
        block = right_half + left_half
        encrypted_block = [block[i - 1] for i in final_permutation_table]

        encrypted_bits += ''.join(encrypted_block)

    return encrypted_bits

# Funkcja wykonująca przesunięcie bitowe w lewo o n bitów
def left_shift(bits, n):
    return bits[n:] + bits[:n]

# Funkcja wykonująca permutację zgodnie z daną tabelą
def permute(bits, table):
    if len(bits) >= max(table):
        return [bits[i - 1] for i in table]
    else:
        raise ValueError("Bits string is too short for permutation table")


# Funkcja generująca podklucze DES
def generate_subkeys(key):
    if len(key) == 64:
        subkeys = []
        # reszta kodu generowania podkluczy
    else:
        print(len(key))
        raise ValueError("Key must be 64 bits long")

    # Permutacja klucza początkowego
    key_permuted = permute(key, initial_key_permutation)

    # Podział klucza na lewą i prawą połowę
    left_half_key = key_permuted[:28]
    right_half_key = key_permuted[28:]

    # Generowanie podkluczy
    for i in range(rounds):
        # Przesunięcie bitowe lewej i prawej połowy klucza
        left_half_key = left_shift(left_half_key, round_key_shifts[i])
        right_half_key = left_shift(right_half_key, round_key_shifts[i])

        # Łączenie i permutacja wynikowych połówek klucza
        combined_key = left_half_key + right_half_key
        subkey = permute(combined_key, final_key_permutation)

        subkeys.append(subkey)

    return subkeys

# Funkcja deszyfrująca DES
def decrypt_des(bits_list, key):
    # Funkcja deszyfrująca DES jest taka sama jak funkcja szyfrująca, ale podklucze są używane w odwrotnej kolejności

    # Konwertujemy klucz na bajty
    key = bytes.fromhex(key)
    key = ''.join(format(byte, '08b') for byte in key)

    bytes_data = int(''.join(bits_list), 2).to_bytes((len(bits_list) + 7) // 8, byteorder='big')

    bits_list = ''.join(format(byte, '08b') for byte in bytes_data)

    # Tworzenie podkluczy
    subkeys = generate_subkeys(key)[::-1]  # Odwrócenie kolejności podkluczy
    # Permutacja początkowa
    permuted_bits = [bits_list[i - 1] for i in initial_permutation_table]

    # Podział na bloki
    blocks = [permuted_bits[i:i + 64] for i in range(0, len(permuted_bits), 64)]

    # Szyfrowanie danych wejściowych blok po bloku
    encrypted_bits = ""
    for i in range(0, len(bits_list), 64):
        # Dzielimy dane na bloki 64-bitowe
        block = bits_list[i:i + 64]

        # Permutacja początkowa
        permuted_block = [block[j - 1] for j in initial_permutation_table]

        # Dzielimy na lewą i prawą połowę
        left_half = permuted_block[:32]
        right_half = permuted_block[32:]

        # 16 rund DES
        for round_key in subkeys:
            next_right_half = [str(int(left) ^ right) for left, right in
                               zip(left_half, des_round(right_half, round_key))]
            left_half = right_half
            right_half = next_right_half

        # Permutacja końcowa
        block = right_half + left_half
        encrypted_block = [block[i - 1] for i in final_permutation_table]

        encrypted_bits += ''.join(encrypted_block)

    decrypted_bytes = int(encrypted_bits, 2).to_bytes((len(encrypted_bits) + 7) // 8, byteorder='big')
    unpadded_bytes = unpad(decrypted_bytes)
    decrypted_bits_list = ''.join(format(byte, '08b') for byte in unpadded_bytes)

    return decrypted_bits_list
