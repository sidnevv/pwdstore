import os.path
import secrets
import string
import sqlite3
import sys

from ttkwidgets import CheckboxTreeview
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import pickle
import datetime
import keyring
from cryptography.fernet import Fernet
import base64


# Генерация ключа шифрования
def generate_key():
    return Fernet.generate_key()


# Функция для сохранения ключа в системном хранилище паролей
def save_key():
    key = generate_key()
    key_base64 = base64.urlsafe_b64encode(key)
    keyring.set_password("fernet_key", "my_app", key_base64.decode())


# Функция для извлечения ключа из системного хранилища паролей
def get_key():
    key_base64 = keyring.get_password("fernet_key", "my_app")
    if key_base64:
        return base64.urlsafe_b64decode(key_base64)
    else:
        return None


# Проверка наличия ключа в системном хранилище паролей
key = get_key()
if key is None:
    save_key()
    key = get_key()

# Использование ключа для создания объекта Fernet
cipher_suite = Fernet(key)

# Создание базы данных
conn = sqlite3.connect('app.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, service text, username text, password text, description text, date text)''')
conn.commit()


# Функция генерации пароля
def generate_password(length):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                sum(c.isdigit() for c in password) >= 3 and
                any(c in string.punctuation for c in password)):
            break
    return password


# Функция для шифрования пароля
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())


# Функция для дешифрования пароля
def decrypt_password(encrypted_password):
    try:
        return cipher_suite.decrypt(encrypted_password).decode()
    except Exception as e:
        print(f"Error occurred during decryption: {e}")
        return None


# Функция добавления пароля в базу данных
def add_password(service, username, password, description):
    encrypted_password = encrypt_password(password)
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO passwords (service, username, password, description, date) VALUES (?, ?, ?, ?, ?)",
              (service, username, encrypted_password, description, current_time))
    conn.commit()


# Функция удаления пароля из базы данных
def delete_password(id):
    c.execute("DELETE FROM passwords WHERE id=?", (id,))
    conn.commit()


# Функция отображения всех паролей
def show_passwords():
    c.execute("SELECT * FROM passwords")
    records = c.fetchall()
    formatted_records = []
    for record in records:
        decrypted_password = decrypt_password(record[3])
        if decrypted_password:
            formatted_records.append((record[0], record[1], record[2], decrypted_password, record[4],
                                      datetime.datetime.strptime(record[5], "%Y-%m-%d %H:%M:%S").strftime("%d.%m.%Y")))
    return formatted_records


# Функция для проверки пользователя
def check_user():
    try:
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'users.pickle'), 'rb') as f:
            dialog = tk.Tk()
            dialog.title("Login")
            dialog.geometry("250x120")
            dialog.resizable(False, False)
            dialog.iconbitmap(default=os.path.join(os.path.dirname(sys.executable), 'favicon.ico'))

            dialog.eval('tk::PlaceWindow . center')

            username_label = ttk.Label(dialog, text="Username:")
            username_label.pack()
            username_entry = ttk.Entry(dialog)
            username_entry.pack()

            password_label = ttk.Label(dialog, text="Password:")
            password_label.pack()
            password_entry = ttk.Entry(dialog, show='*')
            password_entry.pack()

            ok_button = ttk.Button(dialog, text="Login",
                                   command=lambda: validate_user(dialog, username_entry.get(), password_entry.get()))
            ok_button.pack(padx=5, pady=5)

            dialog.mainloop()
    except (FileNotFoundError, EOFError):
        create_user()


# Функция для проверки учетных данных пользователя
def validate_user(dialog, username, password):
    try:
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'users.pickle'), 'rb') as f:
            users = pickle.load(f)
            if username in users and users[username] == password:
                dialog.destroy()
                main_app(username)
                return
    except (FileNotFoundError, EOFError):
        create_user()
    show_error_message("Authentication Failed", "Invalid username or password.")


# Функция для создания пользователя
def create_user():
    dialog = tk.Tk()
    dialog.title("Create User")
    dialog.geometry("250x120")
    dialog.iconbitmap(default=os.path.join(os.path.dirname(sys.executable), 'favicon.ico'))
    dialog.resizable(False, False)
    dialog.eval('tk::PlaceWindow . center')

    username_label = ttk.Label(dialog, text="Username:")
    username_label.pack()
    username_entry = ttk.Entry(dialog)
    username_entry.pack()

    password_label = ttk.Label(dialog, text="Password:")
    password_label.pack()
    password_entry = ttk.Entry(dialog, show='*')
    password_entry.pack()

    ok_button = ttk.Button(dialog, text="OK",
                           command=lambda: save_user(dialog, username_entry.get(), password_entry.get()))
    ok_button.pack(padx=5, pady=5)

    dialog.mainloop()


# Функция для сохранения пользователя
def save_user(dialog, username, password):
    with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'users.pickle'), 'wb') as f:
        pickle.dump({username: password}, f)
    dialog.destroy()
    check_user()


# Функция для отображения сообщения об ошибке
def show_error_message(title, message):
    messagebox.showerror(title, message)


# Создание главного графического интерфейса с использованием Tkinter
def main_app(username):
    root = tk.Tk()
    root.title("Password Manager")
    root.resizable(False, False)

    # Функция для добавления записи
    def add_record():
        add_window = tk.Toplevel(root)
        add_window.title("Add Record")
        add_window.resizable(False, False)
        service_label = ttk.Label(add_window, text="Service:")
        service_label.grid(row=0, column=0, padx=5, pady=5)
        service_entry = ttk.Entry(add_window)
        service_entry.grid(row=0, column=1, padx=5, pady=5)
        username_label = ttk.Label(add_window, text="Username:")
        username_label.grid(row=1, column=0, padx=5, pady=5)
        username_entry = ttk.Entry(add_window)
        username_entry.grid(row=1, column=1, padx=5, pady=5)
        password_label = ttk.Label(add_window, text="Password:")
        password_label.grid(row=2, column=0, padx=5, pady=5)
        password_entry = ttk.Entry(add_window)
        password_entry.grid(row=2, column=1, padx=5, pady=5)
        description_label = ttk.Label(add_window, text="Description:")
        description_label.grid(row=3, column=0, padx=5, pady=5)
        description_entry = ttk.Entry(add_window)
        description_entry.grid(row=3, column=1, padx=5, pady=5)
        length_label = ttk.Label(add_window, text="Password Length:")
        length_label.grid(row=4, column=0, padx=5, pady=5)
        length_entry = ttk.Entry(add_window)
        length_entry.insert(0, "12")  # Default password length
        length_entry.grid(row=4, column=1, padx=5, pady=5)

        def generate_and_insert_password():
            length = int(length_entry.get())
            password = generate_password(length)
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)

        def save_record():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            description = description_entry.get()
            add_password(service, username, password, description)
            messagebox.showinfo("Success", "Password added to the database")
            add_window.destroy()
            update_table()

        def close_window():
            add_window.destroy()

        generate_button = ttk.Button(add_window, text="Generate Password", command=generate_and_insert_password)
        generate_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        save_button = ttk.Button(add_window, text="Save", command=save_record)
        save_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5)
        close_button = ttk.Button(add_window, text="Close", command=close_window)
        close_button.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

    # Функция для удаления записи
    def delete_record():
        selected_item = tree.focus()
        if selected_item:
            item = tree.item(selected_item)
            values = item['values']
            confirmation = messagebox.askyesno("Confirmation", f"Do you want to delete the record for {values[0]}?")
            if confirmation:
                delete_password(item['text'])
                update_table()
        else:
            messagebox.showerror("Error", "No record selected for deletion.")

    # Создание таблицы для отображения данных
    columns = ("Service", "Username", "Password", "Description", "Date")
    tree = CheckboxTreeview(root, columns=columns, show=("headings", "tree"))

    tree.heading("Service", text="Service")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.heading("Description", text="Description")
    tree.heading("Date", text="Date")

    tree.column("Service", anchor="center")
    tree.column("Username", anchor="center")
    tree.column("Password", anchor="center")
    tree.column("Description", anchor="center")
    tree.column("Date", anchor="center")

    tree.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
    tree.columnconfigure(0, weight=1)
    tree.columnconfigure(1, weight=1)
    tree.columnconfigure(2, weight=1)
    tree.columnconfigure(3, weight=1)
    tree.columnconfigure(4, weight=1)

    def update_table():
        records = show_passwords()
        tree.delete(*tree.get_children())
        for record in records:
            tree.insert("", "end", values=(record[1], record[2], record[3], record[4], record[5]), text=record[0])

    update_table()

    add_button = ttk.Button(root, text="Add Record", command=add_record)
    add_button.grid(row=1, column=0, ipadx=6, ipady=6, padx=5, pady=5, sticky="ew")
    delete_button = ttk.Button(root, text="Delete Record", command=delete_record)
    delete_button.grid(row=2, column=0, ipadx=6, ipady=6, padx=5, pady=5, sticky="ew")

    root.grid_columnconfigure(0, weight=1)

    root.mainloop()


if __name__ == "__main__":
    check_user()