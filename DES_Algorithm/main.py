"""
Autorzy:
    - Piotr Janiszek 247678
    - Aliaksei Vishniavetski 249518
"""

import tkinter as tk
from tkinter import filedialog, scrolledtext
from des import *
def process_file(file_path):
    # Otwieramy plik w trybie binarnym ('rb')
    with open(file_path, 'rb') as file:
        # Odczytujemy plik i zapisujemy dane do tablicy
        data = file.read()
        # Konwertujemy dane na postać bitową
        bits = format(int.from_bytes(data, byteorder='big'), '08b')
        # Zapisujemy bity do listy
        bits_list = list(bits)
        # Wyświetlamy listę bitów w polu tekstowym
        text_area.config(state='normal')  # tymczasowo odblokowujemy pole tekstowe
        #text_area.insert(tk.END, ''.join(bits_list))
        text_area.insert(tk.END, 'Wczytałem '+file_path+'\n')
        text_area.config(state='disabled')  # z powrotem blokujemy pole tekstowe
        return bits_list  # zwracamy listę bitów

def save_file_dialog(bits_list):
    file_path = filedialog.asksaveasfilename(defaultextension=".bin")
    # Konwertujemy listę bitów z powrotem na bajty
    bytes_data = int(''.join(bits_list), 2).to_bytes((len(bits_list) + 7) // 8, byteorder='big')
    # Zapisujemy bajty do pliku
    with open(file_path, 'wb') as file:
        file.write(bytes_data)

def open_file_dialog():
    file_path = filedialog.askopenfilename()
    global bits_list  # zapisujemy listę bitów jako zmienną globalną
    bits_list = process_file(file_path)

def encrypt():
    key = key_entry.get()
    encrypted_data = encrypt_des(bits_list, key)
    text_area.config(state='normal')
    text_area.insert(tk.END, 'Zaszyfrowałem plik\n')
    text_area.config(state='disabled')
    save_file_dialog(encrypted_data)

def decrypt():
    key = key_entry.get()
    decrypted_data = decrypt_des(bits_list, key)
    text_area.config(state='normal')
    text_area.insert(tk.END, 'Deszyfrowałem plik\n')
    text_area.config(state='disabled')
    save_file_dialog(decrypted_data)

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
    return bits

def bits_to_text(bits): #sprawdzic
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
        key = key_entry.get()  # Pobieramy klucz szyfrowania
        bits_list_text = text_to_bits(text_to_encrypt)  # Konwertujemy tekst na bity
        bits_list_str = [''.join(map(str, bits)) if isinstance(bits, list) else str(bits) for bits in bits_list_text]  # Konwertujemy listę bitów na listę ciągów znaków
        bits_list = encrypt_des(bits_list_str, key)  # Szyfrujemy tekst
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
        key = key_entry.get()  # Pobieramy klucz szyfrowania
        bits_list_text = text_to_bits(text_to_decrypt)  # Konwertujemy tekst na bity
        bits_list_str = [''.join(map(str, bits)) if isinstance(bits, list) else str(bits) for bits in
                         bits_list_text]  # Konwertujemy listę bitów na listę ciągów znaków
        bits_list = decrypt_des(bits_list_str, key)  # Szyfrujemy tekst
        decrypted_text = bits_to_text(bits_list)  # Konwertujemy zaszyfrowane bity na tekst
        text_area_result.config(state='normal')  # Odblokowujemy pole wynikowe
        text_area_result.delete('1.0', tk.END)  # Czyścimy pole wynikowe
        text_area_result.insert(tk.END, decrypted_text)  # Wstawiamy zaszyfrowany tekst do pola wynikowego
        text_area_result.config(state='disabled')  # Blokujemy pole wynikowe
        text_area.config(state='normal')
        text_area.insert(tk.END, 'Deszyfrowałem tekst\n')
        text_area.config(state='disabled')
    else:
        tk.messagebox.showwarning("Warning", "Text to encrypt is empty!")  # Wyświetlamy komunikat o pustym tekście

root = tk.Tk()
root.geometry("1600x800")
root.title("Algorytm DES")

frame1 = tk.Frame(root, width=800, height=800, bd=2)
frame1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

frame2 = tk.Frame(root, width=800, height=800, bd=2)
frame2.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

open_file_button = tk.Button(frame1, text="Otwórz plik", command=open_file_dialog, width="15", pady=5)
open_file_button.pack()

save_file_button = tk.Button(frame1, text="Zapisz plik", command=save_bits, width="15", pady=5)
save_file_button.pack()

encrypt_button = tk.Button(frame1, text="Szyfruj plik", command=encrypt, width="15", pady=5)
encrypt_button.pack()

decrypt_button = tk.Button(frame1, text="Deszyfruj plik", command=decrypt, width="15", pady=5)
decrypt_button.pack()

encrypt_text_button = tk.Button(frame1, text="Szyfruj tekst", command=encrypt_text, width="15", pady=5)
encrypt_text_button.pack()

decrypt_text_button = tk.Button(frame1, text="Deszyfruj tekst", command=decrypt_text, width="15", pady=5)
decrypt_text_button.pack()

key_entry_label = tk.Label(frame1, text="Podaj klucz (16 znaków w formie heksadecymalnej):")
key_entry_label.pack()

key_entry = tk.Entry(frame1)
key_entry.pack()

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
