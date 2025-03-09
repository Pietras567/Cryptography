"""
Autorzy:
    - Piotr Janiszek 247678
    - Aliaksei Vishniavetski 249518
"""

import tkinter as tk
from math import ceil
from tkinter import filedialog, scrolledtext
from Crypto.Util import number
global bits_list
import random

pqlen = 2048

def process_file(file_path):
    # Otwórz i przeczytaj plik jako bajty
    with open(file_path, 'rb') as file:
        content = file.read()

    # Konwertuj bajty na bity
    bits = ''.join(format(byte, '08b') for byte in content)

    # Zwróć bity jako ciąg znaków
    return bits


def save_file_dialog(bits_list):
    # Wybierz miejsce zapisu i nazwę pliku
    file_path = filedialog.asksaveasfilename(defaultextension=".bin")

    # Konwertuj ciąg bitów na bajty
    bytes_arr = bytearray(int(bits_list[i : i + 8], 2) for i in range(0, len(bits_list), 8))

    # Zapisz bajty do pliku
    with open(file_path, 'wb') as file:
        file.write(bytes_arr)

def open_file_dialog():
    file_path = filedialog.askopenfilename()
    global bits_list  # zapisujemy listę bitów jako zmienną globalną
    bits_list = process_file(file_path)

    text_area.config(state='normal')  # tymczasowo odblokowujemy pole tekstowe
    text_area.insert(tk.END, 'Wczytałem ' + file_path + '\n')
    text_area.config(state='disabled')  # z powrotem blokujemy pole tekstowe

def generuj_liczbe_pierwsza(dlugosc_w_bitach):
    return number.getPrime(dlugosc_w_bitach)

def generate_keys(): #p mod 4 = 3 oraz q mod 4 = 3
    p = generuj_liczbe_pierwsza(pqlen)
    n = 0
    while n.bit_length() != 4096:
        while(p % 4 != 3):
            p = generuj_liczbe_pierwsza(pqlen)
        q = generuj_liczbe_pierwsza(pqlen)
        while(q % 4 != 3):
            q = generuj_liczbe_pierwsza(pqlen)
        n = p * q
    pkey_entry.insert(tk.END, hex(p).lstrip("0x"))
    qkey_entry.insert(tk.END, hex(q).lstrip("0x"))
    nkey_entry.insert(tk.END, hex(n).lstrip("0x"))
    print(p.bit_length())
    print(q.bit_length())
    print(n.bit_length())
    text_area.insert(tk.END, 'Wygenerowałem klucze '+'\n')



def remove_trailing_zero_bytes(bit_string):
    while bit_string and bit_string[-8:] == '00000000':
        bit_string = bit_string[:-8]


    return bit_string

def encrypt():
    global bits_list
    bytes_list = int(''.join(bits_list), 2).to_bytes((len(bits_list) + 7) // 8, byteorder='big')

    if ((nkey_entry.get() == '') & (qkey_entry.get() != '') & (pkey_entry.get() != '')):
        pkey = int(pkey_entry.get(), 16)
        qkey = int(qkey_entry.get(), 16)
        nkey = pkey * qkey  # n = p * q
        text_area.config(state='normal')
        text_area.insert(tk.END, 'Ustawiono klucz publiczny n\n')
        text_area.config(state='disabled')

        if is_prime(pkey, 80) == False:
            tk.messagebox.showwarning("Warning",
                                      "Klucz p nie jest liczbą pierwszą!")  # Wyświetlamy komunikat o złym kluczu
            return

        text_area.config(state='normal')
        text_area.insert(tk.END, 'Klucz prywatny p jest poprawny\n')
        text_area.config(state='disabled')

        if is_prime(qkey, 80) == False:
            tk.messagebox.showwarning("Warning",
                                      "Klucz q nie jest liczbą pierwszą!")  # Wyświetlamy komunikat o złym kluczu
            return

        text_area.config(state='normal')
        text_area.insert(tk.END, 'Klucz prywatny q jest poprawny\n')
        text_area.config(state='disabled')
    elif ((nkey_entry.get() != '') & (qkey_entry.get() != '') & (pkey_entry.get() !='')):
        pkey = int(pkey_entry.get(), 16)
        qkey = int(qkey_entry.get(), 16)
        nkey = int(nkey_entry.get(), 16)
        if(nkey != pkey * qkey):
            nkey = pkey * qkey
            text_area.config(state='normal')
            text_area.insert(tk.END, 'Ustawiono klucz publiczny n, gdyż nie był wynikiem mnożenia p i q\n')
            text_area.config(state='disabled')

        if is_prime(pkey, 80) == False:
            tk.messagebox.showwarning("Warning",
                                      "Klucz p nie jest liczbą pierwszą!")  # Wyświetlamy komunikat o złym kluczu
            return

        text_area.config(state='normal')
        text_area.insert(tk.END, 'Klucz prywatny p jest poprawny\n')
        text_area.config(state='disabled')

        if is_prime(qkey, 80) == False:
            tk.messagebox.showwarning("Warning",
                                      "Klucz q nie jest liczbą pierwszą!")  # Wyświetlamy komunikat o złym kluczu
            return

        text_area.config(state='normal')
        text_area.insert(tk.END, 'Klucz prywatny q jest poprawny\n')
        text_area.config(state='disabled')
    elif (nkey_entry.get() != ''):
        nkey = int(nkey_entry.get(), 16)
    else:
        tk.messagebox.showwarning("Warning", "Podaj klucz publiczny N!")  # Wyświetlamy komunikat o braku klucza publicznego
        return

    c = ''

    message = list(bytes_list)
    amountChars = (nkey.bit_length()-10) // 8
    
    print("znaki: " + str(amountChars))
    while len(message) % amountChars != 0:
        message.append(0)

    print('Pobrane dane: ' + ''.join('{:02x}'.format(b) for b in message) + '\n')

    blocks = len(message) // amountChars

    cipher = [0]*blocks
    for i in range(blocks):
        temp = message[amountChars * i : amountChars * (i + 1)]
        temp = bytes(temp)
        #print('Temp dane: ' + ''.join('{:02x}'.format(b) for b in temp) + '\n')
        cipher[i] = int.from_bytes(temp, byteorder='big')
        cipher[i] = (cipher[i] ** 2) % nkey #pow(cipher[i], 2, nkey)


        ciph = cipher[i].to_bytes((cipher[i].bit_length() + 7) // 8, byteorder='big')
        #print("Długość szyfru: " + str(len(list(ciph))))
        bitCipher = ''.join([format(byte, '08b') for byte in ciph])

        #print("len przed: " + str(len(bitCipher)))
        #print("cipher przed: " + bitCipher)

        while (len(bitCipher) // 8) < (nkey.bit_length()) // 8:
            bitCipher = '0' + bitCipher
            #print("poprawione")

        #print("len po: " + str(len(bitCipher)))
        #print("cipher po: " + bitCipher)

        c += bitCipher
        #print("szyfr: " + ''.join('{:02x}'.format(b) for b in ciph))

    #print("test")
    #print(len(c))
    #print(str(c))
    save_file_dialog(c)
    bits_list = c
    return c
def decrypt():
    global bits_list
    bytes_list = int(''.join(bits_list), 2).to_bytes((len(bits_list) + 7) // 8, byteorder='big')

    if((nkey_entry.get() == '') & (pkey_entry.get() != '') & (qkey_entry.get() != '')):
        pkey = int(pkey_entry.get(), 16)
        qkey = int(qkey_entry.get(), 16)
        nkey = pkey * qkey # n = p * q
        text_area.config(state='normal')
        text_area.insert(tk.END, 'Ustawiono klucz publiczny n\n')
        text_area.config(state='disabled')
    elif((nkey_entry.get() != '') & (pkey_entry.get() != '') & (qkey_entry.get() != '')):
        pkey = int(pkey_entry.get(), 16)
        qkey = int(qkey_entry.get(), 16)
        nkey = int(nkey_entry.get(), 16)
        if(nkey != pkey * qkey):
            nkey = pkey * qkey  # n = p * q
            text_area.config(state='normal')
            text_area.insert(tk.END, 'Ustawiono klucz publiczny n, gdyż nie był wynikiem mnożenia p i q\n')
            text_area.config(state='disabled')
    else:
        tk.messagebox.showwarning("Warning", "Podaj klucze prywatne!")  # Wyświetlamy komunikat o braku kluczy
        return

    if is_prime(pkey, 80) == False:
        tk.messagebox.showwarning("Warning", "Klucz p nie jest liczbą pierwszą!")  # Wyświetlamy komunikat o złym kluczu
        return

    text_area.config(state='normal')
    text_area.insert(tk.END, 'Klucz prywatny p jest poprawny\n')
    text_area.config(state='disabled')

    if is_prime(qkey, 80) == False:
        tk.messagebox.showwarning("Warning", "Klucz q nie jest liczbą pierwszą!")  # Wyświetlamy komunikat o złym kluczu
        return

    text_area.config(state='normal')
    text_area.insert(tk.END, 'Klucz prywatny q jest poprawny\n')
    text_area.config(state='disabled')

    cipher = list(bytes_list)
    amountChars = (nkey.bit_length()) // 8

    print('Pobrane dane: ' + ''.join('{:02x}'.format(b) for b in cipher) + '\n')

    blocks = round(len(cipher) / amountChars)

    cipher_parts = [0] * blocks

    mes1 = ''
    mes2 = ''
    mes3 = ''
    mes4 = ''
    proposed = ''

    # Obliczanie a i b
    _, yp, yq = gcd_extended(pkey, qkey)
    #print("CZESC 1")
    print(_, yp, yq)
    #print("CZESC 2")
    #print(egcd(pkey, qkey))
    print("liczba bloków: " + str(blocks))
    for i in range(blocks):
        print("rundka: " + str(i))
        temp = cipher[amountChars * i : amountChars * (i + 1)]
        temp = bytes(temp)
        cipher_parts[i] = int.from_bytes(temp, byteorder='big')


        #Opcja 2
        # Obliczanie mp, mq
        mp = pow(cipher_parts[i], (pkey + 1) // 4, pkey)
        mq = pow(cipher_parts[i], (qkey + 1) // 4, qkey)

        x = (yp * pkey *mq + yq * qkey * mp) % nkey
        y = (yp * pkey * mq - yq * qkey * mp) % nkey

        M1 = x
        #M2 = (-1 * x) % nkey
        M2 = nkey - M1
        M3 = y
        #M4 = (-1 * y) % nkey
        M4 = nkey - M3


        # Wypisywanie wiadomości
        #print("M1:", str(hex(M1)))
        #print(
        #    "==================================================================================================================================")
        #print("M2:", str(hex(M2)))
        #print(
        #    "==================================================================================================================================")
        #print("M3:", str(hex(M3)))
        #print(
        #    "==================================================================================================================================")
        #print("M4:", str(hex(M4)))

        isM1Good = True
        isM2Good = True
        isM3Good = True
        isM4Good = True
        howMany = 4


        if i == blocks - 1:
            #print("Przed: ")
            #print(str(bin(M1)))
            #print(str(bin(M2)))
            #print(str(bin(M3)))
            #print(str(bin(M4)))
            #print("Przed: ")
            #print(mes1)
            #print(mes2)
            #print(mes3)
            #print(mes4)

            M1_bits = str(bin(M1).lstrip("0b"))
            print("len 1: " + str(len(M1_bits)))
            M2_bits = str(bin(M2).lstrip("0b"))
            print("len 2: " + str(len(M1_bits)))
            M3_bits = str(bin(M3).lstrip("0b"))
            print("len 3: " + str(len(M1_bits)))
            M4_bits = str(bin(M4).lstrip("0b"))
            print("len 4: " + str(len(M1_bits)))

            if len(M1_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM1Good = False
                howMany -= 1
            if len(M2_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM2Good = False
                howMany -= 1
            if len(M3_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM3Good = False
                howMany -= 1
            if len(M4_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM4Good = False
                howMany -= 1

            print("znaki: " + str(amountChars))
            while (len(M1_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M1_bits = '0' + M1_bits
                #print("Poprawione M1")

            while (len(M2_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M2_bits = '0' + M2_bits
                #print("Poprawione M2")

            while (len(M3_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M3_bits = '0' + M3_bits
                #print("Poprawione M3")

            while (len(M4_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M4_bits = '0' + M4_bits
                #print("Poprawione M4")

            M1_bits = remove_trailing_zero_bytes(M1_bits)
            M2_bits = remove_trailing_zero_bytes(M2_bits)
            M3_bits = remove_trailing_zero_bytes(M3_bits)
            M4_bits = remove_trailing_zero_bytes(M4_bits)

            mes1 = mes1 + M1_bits
            mes2 = mes2 + M2_bits
            mes3 = mes3 + M3_bits
            mes4 = mes4 + M4_bits

            #print("Po: ")
            #print(str(bin(M1)))
            #print(str(bin(M2)))
            #print(str(bin(M3)))
            #print(str(bin(M4)))
            #print("Po: ")
            #print(mes1)
            #print(mes2)
            #print(mes3)
            #print(mes4)
        else:

            M1_bits = str(bin(M1).lstrip("0b"))
            print("len 1: " + str(len(M1_bits)))
            M2_bits = str(bin(M2).lstrip("0b"))
            print("len 2: " + str(len(M2_bits)))
            M3_bits = str(bin(M3).lstrip("0b"))
            print("len 3: " + str(len(M3_bits)))
            M4_bits = str(bin(M4).lstrip("0b"))
            print("len 4: " + str(len(M4_bits)))

            if len(M1_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM1Good = False
                howMany-=1
            if len(M2_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM2Good = False
                howMany -= 1
            if len(M3_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM3Good = False
                howMany -= 1
            if len(M4_bits) > ((nkey.bit_length() - 10) // 8) * 8:
                isM4Good = False
                howMany -= 1

            print("znaki: " + str(amountChars))
            while (len(M1_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M1_bits = '0' + M1_bits
                #print("Poprawione M1")

            while (len(M2_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M2_bits = '0' + M2_bits
                #print("Poprawione M2")

            while (len(M3_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M3_bits = '0' + M3_bits
                #print("Poprawione M3")

            while (len(M4_bits) // 8) < (nkey.bit_length() - 10) // 8:
                M4_bits = '0' + M4_bits
                #print("Poprawione M4")

            mes1 = mes1 + M1_bits
            mes2 = mes2 + M2_bits
            mes3 = mes3 + M3_bits
            mes4 = mes4 + M4_bits

        if howMany >= 1:
            # Tworzenie listy zmiennych, które mają wartość True
            zmienne = [var for var in [isM1Good, isM2Good, isM3Good, isM4Good] if var is True]

            # Losowanie jednej z zmiennych
            wylosowana_zmienna = random.choice(zmienne)

            if wylosowana_zmienna == isM1Good:
                proposed += M1_bits
            elif wylosowana_zmienna == isM2Good:
                proposed += M2_bits
            elif wylosowana_zmienna == isM3Good:
                proposed += M3_bits
            elif wylosowana_zmienna == isM4Good:
                proposed += M4_bits
        else:
            # Tworzenie listy zmiennych, które mają wartość True
            zmienne = [var for var in [isM1Good, isM2Good, isM3Good, isM4Good] if var is False]

            # Losowanie jednej z zmiennych
            wylosowana_zmienna = random.choice(zmienne)
            if wylosowana_zmienna == isM1Good:
                proposed += M1_bits
            elif wylosowana_zmienna == isM2Good:
                proposed += M2_bits
            elif wylosowana_zmienna == isM3Good:
                proposed += M3_bits
            elif wylosowana_zmienna == isM4Good:
                proposed += M4_bits


    save_file_dialog(mes1)
    save_file_dialog(mes2)
    save_file_dialog(mes3)
    save_file_dialog(mes4)
    save_file_dialog(proposed)
    bits_list = proposed
    return mes1, mes2, mes3, mes4, proposed

def gcd_extended(a, b):
    s = 0
    old_s = 1
    t = 1
    old_t = 0
    r = b
    old_r = a
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def save_file_dialog(bits_list):
    file_path = filedialog.asksaveasfilename(defaultextension=".bin")
    # Konwertujemy listę bitów z powrotem na bajty
    bytes_data = int(''.join(bits_list), 2).to_bytes((len(bits_list) + 7) // 8, byteorder='big')
    # Zapisujemy bajty do pliku
    with open(file_path, 'wb') as file:
        file.write(bytes_data)

def save_bits():
    save_file_dialog(bits_list)

def text_to_bits(text):
    bits = []
    for char in text:
        # Konwertuj każdy znak na jego wartość numeryczną (kod ASCII)
        byte = ord(char)
        # Konwertuj wartość numeryczną na ciąg bitów i dodaj do listy bitów
        bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
    return ''.join(str(bit) for bit in bits)

def bits_to_text(bits):
    text = ""
    for i in range(0, len(bits), 8):
        # Pobierz 8 bitów, aby utworzyć bajt
        byte_bits = bits[i:i+8]
        # Konwertuj ciąg bitów na liczbę całkowitą
        byte = int("".join(str(bit) for bit in byte_bits), 2)
        # Konwertuj liczbę całkowitą na znak tekstowy (kod ASCII)
        text += chr(byte)
    return text

def encrypt_text():
    text_to_encrypt = text_to_encrypt_area.get('1.0', tk.END).strip()  # Pobieramy tekst z pola tekstowego
    global bits_list
    if text_to_encrypt:  # Sprawdzamy, czy tekst nie jest pusty
        bits_list = text_to_bits(text_to_encrypt)  # Konwertujemy tekst na bity
        print(bits_list)
        bits_list = encrypt()  # Szyfrujemy tekst
        encrypted_text = bits_to_text(bits_list)  # Konwertujemy zaszyfrowane bity na tekst
        text_area_result.config(state='normal')  # Odblokowujemy pole wynikowe
        text_area_result.delete('1.0', tk.END)  # Czyścimy pole wynikowe
        text_area_result.insert(tk.END, encrypted_text)  # Wstawiamy zaszyfrowany tekst do pola wynikowego
        text_area_result.config(state='disabled')  # Blokujemy pole wynikowe
        text_area.config(state='normal')
        text_area.insert(tk.END, 'Zaszyfrowałem tekst\n')
        text_area.config(state='disabled')
    else:
        tk.messagebox.showwarning("Warning", "Text to encrypt is empty!")  # Wyświetlamy komunikat o pustym tekście


def decrypt_text():
    text_to_decrypt = text_to_encrypt_area.get('1.0', tk.END).strip()  # Pobieramy tekst z pola tekstowego
    global bits_list
    if text_to_decrypt:  # Sprawdzamy, czy tekst nie jest pusty
        bits_list = text_to_bits(text_to_decrypt)  # Konwertujemy tekst na bity
        print(bits_list)
        bits_list1, bits_list2, bits_list3, bits_list4, proposed = decrypt()  # Deszyfrujemy tekst
        decrypted_text1 = bits_to_text(bits_list1)  # Konwertujemy zaszyfrowane bity na tekst
        decrypted_text2 = bits_to_text(bits_list2)  # Konwertujemy zaszyfrowane bity na tekst
        decrypted_text3 = bits_to_text(bits_list3)  # Konwertujemy zaszyfrowane bity na tekst
        decrypted_text4 = bits_to_text(bits_list4)  # Konwertujemy zaszyfrowane bity na tekst
        decrypted_text5 = bits_to_text(proposed)    # Konwertujemy zaszyfrowane bity na tekst
        text_area_result.config(state='normal')  # Odblokowujemy pole wynikowe
        text_area_result.delete('1.0', tk.END)  # Czyścimy pole wynikowe
        text_area_result.insert(tk.END, decrypted_text1)  # Wstawiamy deszyfrowany tekst do pola wynikowego
        text_area_result.insert(tk.END, "\n================================\n")
        text_area_result.insert(tk.END, decrypted_text2)  # Wstawiamy deszyfrowany tekst do pola wynikowego
        text_area_result.insert(tk.END, "\n================================\n")
        text_area_result.insert(tk.END, decrypted_text3)  # Wstawiamy deszyfrowany tekst do pola wynikowego
        text_area_result.insert(tk.END, "\n================================\n")
        text_area_result.insert(tk.END, decrypted_text4)  # Wstawiamy deszyfrowany tekst do pola wynikowego
        text_area_result.insert(tk.END, "\n================================\n")
        text_area_result.insert(tk.END, decrypted_text5)  # Wstawiamy deszyfrowany tekst do pola wynikowego
        text_area_result.config(state='disabled')  # Blokujemy pole wynikowe
        text_area.config(state='normal')
        text_area.insert(tk.END, 'Deszyfrowałem tekst\n')
        text_area.config(state='disabled')
        bits_list = proposed
    else:
        tk.messagebox.showwarning("Warning", "Text to encrypt is empty!")  # Wyświetlamy komunikat o pustym tekście


def power(x, y, p):
    res = 1
    x = x % p
    while y > 0:
        if y & 1:
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res

def miller_rabin_test(d, n):
    a = 2 + random.randint(1, n - 4)
    x = power(a, d, n)
    if x == 1 or x == n - 1:
        return True
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False

def is_prime(n, k):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    d = n - 1
    while d % 2 == 0:
        d //= 2
    for _ in range(k):
        if not miller_rabin_test(d, n):
            return False
    return True


root = tk.Tk()
root.geometry("1600x800")
root.title("Algorytm Rabina")

frame1 = tk.Frame(root, width=800, height=800, bd=2)
frame1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

frame2 = tk.Frame(root, width=800, height=800, bd=2)
frame2.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

open_file_button = tk.Button(frame1, text="Otwórz plik", command=open_file_dialog, width="25", pady=5)
open_file_button.pack()

save_file_button = tk.Button(frame1, text="Zapisz plik", command=save_bits, width="25", pady=5)
save_file_button.pack()

encrypt_button = tk.Button(frame1, text="Szyfruj plik", command=encrypt, width="25", pady=5)
encrypt_button.pack()

decrypt_button = tk.Button(frame1, text="Deszyfruj plik", command=decrypt, width="25", pady=5)
decrypt_button.pack()

encrypt_text_button = tk.Button(frame1, text="Szyfruj tekst", command=encrypt_text, width="25", pady=5)
encrypt_text_button.pack()

decrypt_text_button = tk.Button(frame1, text="Deszyfruj tekst", command=decrypt_text, width="25", pady=5)
decrypt_text_button.pack()

generate_keys_button = tk.Button(frame1, text="Generuj losowe klucze", command=generate_keys, width="25", pady=5)
generate_keys_button.pack()

pkey_entry_label = tk.Label(frame1, text="Podaj heksadecymalnie klucz prywatny p:")
pkey_entry_label.pack()

pkey_entry = tk.Entry(frame1, width=75)
pkey_entry.pack()

qkey_entry_label = tk.Label(frame1, text="Podaj heksadecymalnie klucz prywatny q:")
qkey_entry_label.pack()

qkey_entry = tk.Entry(frame1, width=75)
qkey_entry.pack()

nkey_entry_label = tk.Label(frame1, text="Podaj heksadecymalnie klucz publiczny N:")
nkey_entry_label.pack()

nkey_entry = tk.Entry(frame1, width=75)
nkey_entry.pack()

# Używamy ScrolledText zamiast Text, aby dodać pasek przewijania
text_area = scrolledtext.ScrolledText(frame1)
text_area.pack(fill=tk.BOTH, expand=True)

# Blokujemy możliwość edycji pola tekstowego
text_area.config(state='disabled')



# Używamy ScrolledText zamiast Text, aby dodać pasek przewijania
text_to_encrypt_label = tk.Label(frame2, text="Tekst do szyfrowania/deszyfrowania:")
text_to_encrypt_label.pack()

text_to_encrypt_area = scrolledtext.ScrolledText(frame2)
text_to_encrypt_area.pack(fill=tk.BOTH, expand=True)


# Używamy ScrolledText zamiast Text, aby dodać pasek przewijania
text_result_label = tk.Label(frame2, text="Tekst po zaszyfrowaniu/deszyfrowaniu:")
text_result_label.pack()

# Używamy ScrolledText zamiast Text, aby dodać pasek przewijania
text_area_result = scrolledtext.ScrolledText(frame2)
text_area_result.pack(fill=tk.BOTH, expand=True)

# Blokujemy możliwość edycji pola tekstowego
text_area_result.config(state='disabled')

root.mainloop()
