# Cryptography---19CS412-classical-techqniques
# Caeser Cipher
Caeser Cipher using with different key values

# AIM:

To encrypt and decrypt the given message by using Ceaser Cipher encryption algorithm.


## DESIGN STEPS:

### Step 1:

Design of Caeser Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

1.	In Ceaser Cipher each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet.
2.	For example, with a left shift of 3, D would be replaced by A, E would become B, and so on.
3.	The encryption can also be represented using modular arithmetic by first transforming the letters into numbers, according to the   
    scheme, A = 0, B = 1, Z = 25.
4.	Encryption of a letter x by a shift n can be described mathematically as,
                       En(x) = (x + n) mod26
5.	Decryption is performed similarly,
                       Dn (x)=(x - n) mod26


## PROGRAM:
PROGRAM:
~~~
def caesar_encrypt(text, key):
    encrypted_text = ""
    for char in text:
        if 'A' <= char <= 'Z':
            encrypted_text += chr(((ord(char) - ord('A') + key) % 26) + ord('A'))
        elif 'a' <= char <= 'z':
            encrypted_text += chr(((ord(char) - ord('a') + key) % 26) + ord('a'))
        else:
            encrypted_text += char  # Keep non-alphabetic characters unchanged
    return encrypted_text

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)  # Decryption is the same as encryption with a negative key

if __name__ == "__main__":
    message = input("Enter the message to encrypt: ")
    key = int(input("Enter the Caesar Cipher key (an integer): "))
    
    encrypted_message = caesar_encrypt(message, key)
    print("Encrypted Message:", encrypted_message)
    
    decrypted_message = caesar_decrypt(encrypted_message, key)
    print("Decrypted Message:", decrypted_message)
~~~

## OUTPUT:
OUTPUT:
Simulating Caesar Cipher

![Screenshot 2025-03-19 084235](https://github.com/user-attachments/assets/ec4c7b79-c0c1-4374-bea6-3ee66670dd17)

Input : Anna University
Encrypted Message : Dqqd Xqlyhuvlwb Decrypted Message : Anna University

## RESULT:
The program is executed successfully

---------------------------------
# PlayFair Cipher
Playfair Cipher using with different key values

# AIM:

To implement a program to encrypt a plain text and decrypt a cipher text using play fair Cipher substitution technique.

 
## DESIGN STEPS:

### Step 1:

Design of PlayFair Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

ALGORITHM DESCRIPTION:
The Playfair cipher uses a 5 by 5 table containing a key word or phrase. To generate the key table, first fill the spaces in the table with the letters of the keyword, then fill the remaining spaces with the rest of the letters of the alphabet in order (usually omitting "Q" to reduce the alphabet to fit; other versions put both "I" and "J" in the same space). The key can be written in the top rows of the table, from left to right, or in some other pattern, such as a spiral beginning in the upper-left-hand corner and ending in the centre.
The keyword together with the conventions for filling in the 5 by 5 table constitutes the cipher key. To encrypt a message, one would break the message into digrams (groups of 2 letters) such that, for example, "HelloWorld" becomes "HE LL OW OR LD", and map them out on the key table. Then apply the following 4 rules, to each pair of letters in the plaintext:
1.	If both letters are the same (or only one letter is left), add an "X" after the first letter. Encrypt the new pair and continue. Some   
   variants of Playfair use "Q" instead of "X", but any letter, itself uncommon as a repeated pair, will do.
2.	If the letters appear on the same row of your table, replace them with the letters to their immediate right respectively (wrapping 
   around to the left side of the row if a letter in the original pair was on the right side of the row).
3.	If the letters appear on the same column of your table, replace them with the letters immediately below respectively (wrapping around 
   to the top side of the column if a letter in the original pair was on the bottom side of the column).
4.	If the letters are not on the same row or column, replace them with the letters on the same row respectively but at the other pair of 
   corners of the rectangle defined by the original pair. The order is important – the first letter of the encrypted pair is the one that 
    lies on the same row as the first letter of the plaintext pair.
To decrypt, use the INVERSE (opposite) of the last 3 rules, and the 1st as-is (dropping any extra "X"s, or "Q"s that do not make sense in the final message when finished).


## PROGRAM:
~~~
def generate_key_square(key):
    key = "".join(dict.fromkeys(key.upper().replace("J", "I")))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key += "".join([c for c in alphabet if c not in key])
    return [list(key[i:i+5]) for i in range(0, 25, 5)]

def find_position(square, letter):
    for r, row in enumerate(square):
        if letter in row:
            return r, row.index(letter)

def prepare_text(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    new_text = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"
        if a == b:
            new_text += a + "X"
            i += 1
        else:
            new_text += a + b
            i += 2
    return new_text

def playfair(text, key, encrypt=True):
    square = generate_key_square(key)
    text = prepare_text(text)
    result = ""
    for i in range(0, len(text), 2):
        r1, c1 = find_position(square, text[i])
        r2, c2 = find_position(square, text[i+1])
        if r1 == r2:
            result += square[r1][(c1 + (1 if encrypt else -1)) % 5] + square[r2][(c2 + (1 if encrypt else -1)) % 5]
        elif c1 == c2:
            result += square[(r1 + (1 if encrypt else -1)) % 5][c1] + square[(r2 + (1 if encrypt else -1)) % 5][c2]
        else:
            result += square[r1][c2] + square[r2][c1]
    return result

key = "Monarchy"
plaintext = "instruments"
ciphertext = playfair(plaintext, key, True)
decrypted = playfair(ciphertext, key, False)

print("Key:", key)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted:", decrypted)
~~~
## OUTPUT:
Output:
Key text: Monarchy Plain text: instruments Cipher text: gatlmzclrqtx

![Screenshot 2025-03-19 090606](https://github.com/user-attachments/assets/ee615056-c2b8-4693-adce-ec486e699ce9)

## RESULT:
The program is executed successfully


---------------------------
# Hill Cipher
Hill Cipher using with different key values

# AIM:

To develop a simple C program to implement Hill Cipher.

## DESIGN STEPS:

### Step 1:

Design of Hill Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 
ALGORITHM DESCRIPTION:
The Hill cipher is a substitution cipher invented by Lester S. Hill in 1929. Each letter is represented by a number modulo 26. To encrypt a message, each block of n letters is multiplied by an invertible n × n matrix, again modulus 26.
To decrypt the message, each block is multiplied by the inverse of the matrix used for encryption. The matrix used for encryption is the cipher key, and it should be chosen randomly from the set of invertible n × n matrices (modulo 26).
The cipher can, be adapted to an alphabet with any number of letters. All arithmetic just needs to be done modulo the number of letters instead of modulo 26.


## PROGRAM:
PROGRAM:
~~~
import numpy as np

def mod_inverse(matrix, modulus):
    det = int(round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    matrix_inv = det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    return matrix_inv

def text_to_numbers(text):
    return [ord(char) - ord('A') for char in text.upper() if char.isalpha()]

def numbers_to_text(numbers):
    return ''.join(chr(num + ord('A')) for num in numbers)

def encrypt(text, key):
    text_nums = text_to_numbers(text)
    while len(text_nums) % len(key) != 0:
        text_nums.append(ord('X') - ord('A'))
    text_matrix = np.array(text_nums).reshape(-1, len(key))
    encrypted_matrix = (np.dot(text_matrix, key) % 26).flatten()
    return numbers_to_text(encrypted_matrix)

def decrypt(ciphertext, key):
    key_inv = mod_inverse(key, 26)
    cipher_nums = text_to_numbers(ciphertext)
    cipher_matrix = np.array(cipher_nums).reshape(-1, len(key))
    decrypted_matrix = (np.dot(cipher_matrix, key_inv) % 26).flatten()
    return numbers_to_text(decrypted_matrix)

key_matrix = np.array([[1, 2, 1], [2, 3, 2], [2, 2, 1]])
plaintext = "SECURITYLABORATORY"
ciphertext = encrypt(plaintext, key_matrix)
decrypted_text = decrypt(ciphertext, key_matrix)

print("Key Matrix:\n", key_matrix)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)
~~~

## OUTPUT:
OUTPUT:
Simulating Hill Cipher

![Screenshot 2025-03-19 091421](https://github.com/user-attachments/assets/3856fb98-ce30-4d47-bf9b-8e4268488f28)

Input Message : SecurityLaboratory
Padded Message : SECURITYLABORATORY Encrypted Message : EACSDKLCAEFQDUKSXU Decrypted Message : SECURITYLABORATORY
## RESULT:
The program is executed successfully

-------------------------------------------------
# Vigenere Cipher
Vigenere Cipher using with different key values

# AIM:

To develop a simple C program to implement Vigenere Cipher.

## DESIGN STEPS:

### Step 1:

Design of Vigenere Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 
ALGORITHM DESCRIPTION:
The Vigenere cipher is a method of encrypting alphabetic text by using a series of different Caesar ciphers based on the letters of a keyword. It is a simple form of polyalphabetic substitution.To encrypt, a table of alphabets can be used, termed a Vigenere square, or Vigenere table. It consists of the alphabet written out 26 times in different rows, each alphabet shifted cyclically to the left compared to the previous alphabet, corresponding to the 26 possible Caesar ciphers. At different points in the encryption process, the cipher uses a different alphabet from one of the rows used. The alphabet at each point depends on a repeating keyword.



## PROGRAM:
PROGRAM:
~~~
def vigenere_encrypt(text, key):
    encrypted_text = []
    key_length = len(key)
    
    for i, char in enumerate(text.upper()):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            encrypted_text.append(encrypted_char)
        else:
            encrypted_text.append(char)
    
    return ''.join(encrypted_text)

def vigenere_decrypt(text, key):
    decrypted_text = []
    key_length = len(key)
    
    for i, char in enumerate(text.upper()):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted_text.append(decrypted_char)
        else:
            decrypted_text.append(char)
    
    return ''.join(decrypted_text)

key = "KEY"
plaintext = "SECURITYLABORATORY"
ciphertext = vigenere_encrypt(plaintext, key)
decrypted_text = vigenere_decrypt(ciphertext, key)

print("Key:", key)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)
~~~
## OUTPUT:
OUTPUT :

Simulating Vigenere Cipher

![Screenshot 2025-03-19 091731](https://github.com/user-attachments/assets/d09eb216-e602-4e5b-b082-5dd1e071b7cb)

Input Message : SecurityLaboratory
Encrypted Message : NMIYEMKCNIQVVROWXC Decrypted Message : SECURITYLABORATORY
## RESULT:
The program is executed successfully

-----------------------------------------------------------------------

# Rail Fence Cipher
Rail Fence Cipher using with different key values

# AIM:

To develop a simple C program to implement Rail Fence Cipher.

## DESIGN STEPS:

### Step 1:

Design of Rail Fence Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 
ALGORITHM DESCRIPTION:
In the rail fence cipher, the plaintext is written downwards and diagonally on successive "rails" of an imaginary fence, then moving up when we reach the bottom rail. When we reach the top rail, the message is written downwards again until the whole plaintext is written out. The message is then read off in rows.

## PROGRAM:

PROGRAM:
~~~
def rail_fence_encrypt(text, rails):
    fence, rail, step = [''] * rails, 0, 1
    for char in text:
        fence[rail] += char
        rail += step * (rail != 0 and rail != rails - 1 or -1)
    return ''.join(fence)

def rail_fence_decrypt(ciphertext, rails):
    pattern, rail, step = [0] * len(ciphertext), 0, 1
    for i in range(len(ciphertext)):
        pattern[i], rail = rail, rail + step * (rail != 0 and rail != rails - 1 or -1)
    result, fence = [''] * len(ciphertext), iter(ciphertext)
    for i in sorted(range(len(pattern)), key=lambda k: pattern[k]): result[i] = next(fence)
    return ''.join(result)

plaintext, rails = "SECURITYLABORATORY", 2
ciphertext, decrypted_text = rail_fence_encrypt(plaintext, rails), rail_fence_decrypt(rail_fence_encrypt(plaintext, rails), rails)
print(f"Rails: {rails}\nPlaintext: {plaintext}\nCiphertext: {ciphertext}\nDecrypted Text: {decrypted_text}")
~~~
## OUTPUT:
OUTPUT:
Enter a Secret Message wearediscovered
Enter number of rails 2
waeicvrderdsoee

![Screenshot 2025-03-19 092028](https://github.com/user-attachments/assets/8294b06a-d172-45a6-9af8-f9c711fbcc66)

## RESULT:
The program is executed successfully


