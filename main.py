"""
Module for managing a password manager application.

This module includes functions for generating, encrypting, and managing passwords,
as well as interacting with a database for storage.

"""
import os.path
import secrets
import string
import sqlite3
import sys

import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import pickle
import datetime
import base64
import keyring
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken


def generate_key():
    """
    Generate a Fernet key for encryption and decryption.

    Returns:
        bytes: A Fernet key.
    """
    return Fernet.generate_key()


def save_key():
    """
    Save the encryption key to the system keyring.
    """
    new_key = generate_key()
    key_base64 = base64.urlsafe_b64encode(new_key)
    keyring.set_password("fernet_key", "my_app", key_base64.decode())


def get_key():
    """
    Retrieve the encryption key from the system keyring.

    Returns:
        bytes: A Fernet key.
    """
    key_base64 = keyring.get_password("fernet_key", "my_app")
    if key_base64:
        return base64.urlsafe_b64decode(key_base64)
    return None


key = get_key()
if key is None:
    save_key()
    key = get_key()

cipher_suite = Fernet(key)

conn = sqlite3.connect('app.db')
c = conn.cursor()
c.execute(
    '''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, service text, username text, password text, description text, date text)'''
)
conn.commit()


def generate_password(length):
    """
    Generate a secure random password of a specified length.

    Args:
        length (int): The length of the password to generate.

    Returns:
        str: A secure random password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                sum(c.isdigit() for c in password) >= 3 and
                any(c in string.punctuation for c in password)):
            break
    return password


def encrypt_password(password):
    """
    Encrypt a password using Fernet encryption.

    Args:
        password (str): The password to encrypt.

    Returns:
        bytes: The encrypted password.
    """
    return cipher_suite.encrypt(password.encode())


def decrypt_password(encrypted_password):
    """
    Decrypt an encrypted password using the Fernet key.

    Args:
        encrypted_password (bytes): The encrypted password.

    Returns:
        str: The decrypted password, or None if decryption fails.
    """
    try:
        return cipher_suite.decrypt(encrypted_password).decode()
    except InvalidToken as e:
        print(f"Error occurred during decryption: {e}")
        return None


def add_password(service, username, password, description):
    """
        Add a new password record to the database.

        Args:
            service (str): The name of the service.
            username (str): The username for the service.
            password (str): The password for the service.
            description (str): Additional information about the service.
        """
    encrypted_password = encrypt_password(password)
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO passwords (service, username, password, description, date) VALUES (?, ?, ?, ?, ?)",
              (service, username, encrypted_password, description, current_time))
    conn.commit()


def delete_password(id_value):
    """
    Delete a password record from the database.

    Args:
        id_value (int): The ID of the password record to delete.
    """
    c.execute("DELETE FROM passwords WHERE id=?", (id_value,))
    conn.commit()


def show_passwords():
    """
        Returns formatted password records from the database.

        The function retrieves all records from the password database, decrypts the passwords,
        and formats the data for return.
        Returns a list of tuples containing the ID, service, username, password, description, and date.
    """
    c.execute("SELECT * FROM passwords")
    records = c.fetchall()
    formatted_records = []
    for record in records:
        decrypted_password = decrypt_password(record[3])
        if decrypted_password:
            formatted_records.append((record[0], record[1], record[2], decrypted_password, record[4],
                                      datetime.datetime.strptime(record[5], "%Y-%m-%d %H:%M:%S").strftime("%d.%m.%Y")))
    return formatted_records


def check_user():
    """
        Check if the user exists.

        This function checks if the user exists in the 'users.pickle' file.
        If the file exists, it creates a login window.
        If the file doesn't exist, it prompts the user to create a new user.
    """
    try:
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'users.pickle'), 'rb'):
            dialog = tk.Tk()
            dialog.title("Login")
            dialog.geometry("250x160")
            dialog.resizable(False, False)
            dialog.iconbitmap(default='favicon.ico')

            dialog.eval('tk::PlaceWindow . center')

            username_label = ttk.Label(dialog, text="Username:")
            username_label.pack(padx=5, pady=5, anchor="w")
            username_entry = ttk.Entry(dialog)
            username_entry.pack(padx=5, pady=5, fill="x")

            password_label = ttk.Label(dialog, text="Password:")
            password_label.pack(padx=5, pady=5, anchor="w")
            password_entry = ttk.Entry(dialog, show='*')
            password_entry.pack(padx=5, pady=5, fill="x")

            ok_button = ttk.Button(dialog, text="Login",
                                   command=lambda: validate_user(dialog, username_entry.get(), password_entry.get()))
            ok_button.pack(padx=5, pady=5, fill="x")

            dialog.mainloop()
    except (FileNotFoundError, EOFError):
        create_user()


def validate_user(dialog, username, password):
    """
        Validate the user's credentials.

        This function checks if the provided username and password match the records in the 'users.pickle' file.
        If the credentials are valid, it closes the login window and opens the main application window.
        If the credentials are invalid, it displays an error message.

        Args:
            dialog (tk.Tk): The login window dialog.
            username (str): The input username for validation.
            password (str): The input password for validation.
    """
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


def create_user():
    """
        Create a new user.

        This function opens a dialog window for creating a new user.
        It prompts the user to input a username and password.
        When the 'OK' button is clicked, it triggers the `save_user` function to save the new user's credentials.

        The dialog window includes fields for entering a username and password,
        as well as an 'OK' button to confirm the creation.

        Note:
            The 'favicon.ico' file should be present in the current directory.

        Raises:
            FileNotFoundError: If the 'favicon.ico' file is not found.

    """
    dialog = tk.Tk()
    dialog.title("Create User")
    dialog.geometry("250x160")
    dialog.iconbitmap(default='favicon.ico')
    dialog.resizable(False, False)
    dialog.eval('tk::PlaceWindow . center')

    username_label = ttk.Label(dialog, text="Username:")
    username_label.pack(padx=5, pady=5, anchor="w")
    username_entry = ttk.Entry(dialog)
    username_entry.pack(padx=5, pady=5, fill="x")

    password_label = ttk.Label(dialog, text="Password:")
    password_label.pack(padx=5, pady=5, anchor="w")
    password_entry = ttk.Entry(dialog, show='*')
    password_entry.pack(padx=5, pady=5, fill="x")

    ok_button = ttk.Button(dialog, text="OK",
                           command=lambda: save_user(dialog, username_entry.get(), password_entry.get()))
    ok_button.pack(padx=5, pady=5, fill="x")

    dialog.mainloop()


def save_user(dialog, username, password):
    """
        Save user information to a file.

        This function saves the provided username and password to a file called 'users.pickle'.
        It uses the `pickle` module to store the information as a dictionary.

        After saving the user information, it destroys the provided dialog window and calls the `check_user` function
        to prompt the user for login credentials.

        Args:
            dialog (tk.Tk): The Tkinter window to be closed after saving the user information.
            username (str): The username to be saved.
            password (str): The password to be saved.

        Note:
            The 'users.pickle' file will be created or overwritten in the current directory.

        """
    with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'users.pickle'), 'wb') as f:
        pickle.dump({username: password}, f)
    dialog.destroy()
    check_user()


def show_error_message(title, message):
    """
        Display an error message dialog.

        This function creates a pop-up dialog box using the `messagebox` module in Tkinter to display an error message.
        The dialog box includes the provided title and message as the main content.

        Args:
            title (str): The title of the error message dialog.
            message (str): The error message to be displayed.

    """
    messagebox.showerror(title, message)


def main_app(username):
    """
    Main application function for the Password Manager.

    This function sets up the main window for the Password Manager application.
    It creates a user interface that allows users to add, delete, and search for password records.
    The function also initializes the display of the stored password records in a Treeview and provides options
    to manipulate the data.

    Args:
        username (str): The username of the current user.

    """

    if username:
        root = tk.Tk()
        root.title("Password Manager")
        root.resizable(False, False)
        root.maxsize(width=800, height=480)

        def add_record():
            add_window = tk.Toplevel(root)
            add_window.title("Add Record")
            add_window.resizable(False, False)

            # Label and Entry for Service
            service_label = ttk.Label(add_window, text="Service:")
            service_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
            service_entry = ttk.Entry(add_window)
            service_entry.grid(row=0, column=1, padx=5, pady=5, sticky='we')

            # Label and Entry for Username
            username_label = ttk.Label(add_window, text="Username:")
            username_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
            username_entry = ttk.Entry(add_window)
            username_entry.grid(row=1, column=1, padx=5, pady=5, sticky='we')

            # Label and Entry for Password
            password_label = ttk.Label(add_window, text="Password:")
            password_label.grid(row=2, column=0, padx=5, pady=5, sticky='e')
            password_entry = ttk.Entry(add_window)
            password_entry.grid(row=2, column=1, padx=5, pady=5, sticky='we')

            # Label and Entry for Description
            description_label = ttk.Label(add_window, text="Description:")
            description_label.grid(row=3, column=0, padx=5, pady=5, sticky='e')
            description_entry = ttk.Entry(add_window)
            description_entry.grid(row=3, column=1, padx=5, pady=5, sticky='we')

            # Label and Entry for Password Length
            length_label = ttk.Label(add_window, text="Password Length:")
            length_label.grid(row=4, column=0, padx=5, pady=5, sticky='e')
            length_entry = ttk.Spinbox(add_window, from_=1.0, to=50.0)
            length_entry.insert(0, "12")  # Default password length
            length_entry.grid(row=4, column=1, padx=5, pady=5, sticky='we')

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

            # Button for generating password
            generate_button = ttk.Button(add_window, text="Generate Password", command=generate_and_insert_password)
            generate_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky='we')

            # Button for saving the record
            save_button = ttk.Button(add_window, text="Save", command=save_record)
            save_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky='we')

            # Button for closing the window
            close_button = ttk.Button(add_window, text="Close", command=close_window)
            close_button.grid(row=7, column=0, columnspan=2, padx=5, pady=5, sticky='we')

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

        # Функция для поиска записей
        def search_records():
            search_term = search_entry.get()
            all_records = show_passwords()
            filtered_records = [record for record in all_records if search_term.lower() in record[1].lower() or
                                search_term.lower() in record[2].lower() or search_term.lower() in record[4].lower()]
            tree.delete(*tree.get_children())
            for record in filtered_records:
                tree.insert("", "end", values=(record[1], record[2], record[3], record[4], record[5]), text=record[0])

        # Добавление поля поиска
        search_label = ttk.Label(root, text="Search:")
        search_label.grid(row=0, column=0, padx=5, pady=10, sticky='w')
        search_entry = ttk.Entry(root, width=80)
        search_entry.grid(row=0, column=1, padx=5, pady=10, sticky='we')
        search_button = ttk.Button(root, text="Search", command=search_records)
        search_button.grid(row=0, column=2, padx=5, pady=10, sticky='e')

        # Создание таблицы для отображения данных
        columns = ("Service", "Username", "Password", "Description", "Date")
        tree = ttk.Treeview(root, columns=columns, show="headings")

        tree.heading("Service", text="Service")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")
        tree.heading("Description", text="Description")
        tree.heading("Date", text="Date")

        tree.column("Service", anchor="center", stretch=False, width=150)
        tree.column("Username", anchor="center", stretch=False, width=150)
        tree.column("Password", anchor="center", stretch=False, width=150)
        tree.column("Description", anchor="center", stretch=False, width=200)
        tree.column("Date", anchor="center", stretch=False, width=100)

        tree.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='nsew')
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
        add_button.grid(row=2, column=0, padx=5, pady=5, sticky='ew')
        delete_button = ttk.Button(root, text="Delete Record", command=delete_record)
        delete_button.grid(row=2, column=2, padx=5, pady=5, sticky='ew')

        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)
    else:
        messagebox.showerror("Error", "Username not found")


if __name__ == "__main__":
    check_user()
