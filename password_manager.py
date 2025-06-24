import sqlite3
import hashlib
import os
import secrets

# Создание подключения к БД
conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()

# Создание таблицы
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL
)
''')
conn.commit()


def register_user(username, password):
    # Генерация соли и хеширование пароля
    salt = secrets.token_bytes(16)
    salted_password = salt + password.encode()
    password_hash = hashlib.sha256(salted_password).digest()

    # Сохранение в БД
    try:
        cursor.execute('INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)',
                       (username, salt, password_hash))
        conn.commit()
        print(f"Пользователь '{username}' зарегистрирован!")
    except sqlite3.IntegrityError:
        print(f"Ошибка: имя пользователя '{username}' занято.")


def verify_user(username, password):
    # Поиск пользователя в БД
    cursor.execute('SELECT salt, password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if not result:
        print("Пользователь не найден!")
        return False

    salt, stored_hash = result
    salted_password = salt + password.encode()
    input_hash = hashlib.sha256(salted_password).digest()

    # Сравнение хешей
    if secrets.compare_digest(input_hash, stored_hash):
        print("Пароль верный!")
        return True
    else:
        print("Неверный пароль!")
        return False


# Пример использования
if __name__ == "__main__":
    register_user("alice", "QwErTy123!")  # Регистрация
    verify_user("alice", "QwErTy123!")  # Успешная проверка
    verify_user("alice", "wrong_pass")  # Неудачная проверка