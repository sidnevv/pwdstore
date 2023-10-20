# Password Manager Application

This is a simple password manager application built using Python and Tkinter. The application allows users to securely store their service credentials and retrieve them when necessary. The passwords are encrypted and stored in a local SQLite database, ensuring the security of the user's sensitive information.

## Installation

1. Clone the repository to your local machine.
2. Ensure you have Python 3.x installed.
3. Install the necessary dependencies using the following command:

```
pip install -r requirements.txt
```

4. Run the application using the following command:

```
python main.py
```


## Features

- Securely store service credentials including username, password, and description.
- Generate strong and secure passwords.
- Encrypt passwords for secure storage.
- Simple and intuitive user interface built using Tkinter.
- Search functionality to easily find specific credentials.

## Dependencies

- Python 3.x
- ttkwidgets
- sqlite3
- tkinter
- pickle
- keyring
- cryptography

## Usage

Upon running the application, users will be prompted to either log in or create a new account. Once logged in, the main interface will allow users to add, view, and delete stored passwords. The application encrypts the passwords before storing them, ensuring maximum security.

## Contribution

Contributions are welcome. Feel free to open an issue or submit a pull request for any improvements or additional features you would like to add.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
