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
