from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2

SALT_SIZE = 16
KEY_SIZE = 16
ITERATIONS = 100000

def derive_key(password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    return salt + key

def encrypt_file(input_file: str, output_file: str, password: str):
    key = derive_key(password)
    cipher = AES.new(key[16:], AES.MODE_EAX)
    with open(input_file, 'rb') as f:
        data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(output_file, 'wb') as f:
        [f.write(x) for x in (key[:16], cipher.nonce, tag, ciphertext)]

def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_file, 'wb') as f:
        f.write(data)

str01 = "ШИФРОВАНИЕ ДАННЫХ"
str02 = "\nВыбрать операцию (1,2): "

menu = """
    1 - Зашифровать
    2 - Расшифровать
"""

print("*" * 4, str01, "*" * 4)
print(menu)
choise = ""
while choise != "0":
    choise = input(str02)
    if choise == "1":
        password = input("Введите пароль: ").strip()
        input_file = 'input.txt'
        output_file = 'encrypted_data.bin'
        encrypt_file(input_file, output_file, password)
        print("Данные успешно зашифрованы и сохранены в файле:", output_file)
    elif choise == "2":
        password = input("Введите пароль: ")
        input_file = 'encrypted_data.bin'
        output_file = 'decrypted_output.txt'
        try:
            decrypt_file(input_file, output_file, password)
            print("Данные успешно расшифрованы и сохранены в файле:", output_file)
        except (ValueError, KeyError):
            print("Ошибка: неверный пароль или поврежденный файл.")
    else:
        print("Неверный ввод.")