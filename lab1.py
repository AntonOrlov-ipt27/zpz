import hashlib
import json
import os
import tkinter as tk
import tkinter.messagebox as mb
import re

import winreg
import hashlib
import rsa
import sys

ui = None
current_user = None
fail_count = 0

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
    
first_password = hash_password("")   
   
class App(tk.Tk):
    def __init__(self, key):
        tk.Tk.__init__(self)

        self.key = key  # сохраняем ключ
        self.page = None

        # Меню
        about_menu = tk.Menu(self, tearoff=0)
        about_menu.add_command(label="Про програму", command=lambda: mb.showinfo(
            "Info", "Автор: ФБ-22 Орлов Антон\nВаріант №6"))
        menu = tk.Menu(self)
        menu.add_cascade(label="Довідка", menu=about_menu)
        self.config(menu=menu)

        self.switch_page(LoginPage)
        self.geometry("600x300")

        # Обработчик закрытия окна
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

    def switch_page(self, page_class):
        new_page = page_class(self)
        if self.page is not None:
            self.page.destroy()
        self.page = new_page
        self.page.pack()

    def on_exit(self):
        encrypt_file_on_exit(self.key)
        self.destroy()

class LoginPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)

        tk.Label(self, text="username").pack()
        self.username = tk.Entry(self)
        self.username.pack()

        tk.Label(self, text="password").pack()
        self.password = tk.Entry(self, show="*")
        self.password.pack()

        tk.Button(self, text="logIn", command=self.login).pack()

    def login(self):
        global fail_count
        username = self.username.get()
        password = self.password.get()
        hashed_password = hash_password(password)
        
        if username in ui:
            if ui[username]["password"] == hashed_password:
                if ui[username]["ban"]:
                    mb.showinfo("Info", "Користувач заблокований")
                    return
                
                global current_user
                current_user = username
                fail_count = 0
                if current_user == "admin":
                    self.master.switch_page(AdminPage)
                else:
                    self.master.switch_page(UserPage)
            else:
                fail_count += 1
                if fail_count >= 3:
                    mb.showinfo("Info", "Три невірні спроби. Завершення роботи.")
                    self.master.destroy()
                    self.master.quit()
                else:
                    mb.showinfo("Info", "Невірний пароль")
        else:
            mb.showinfo("Info", "Користувача не існує")

class AdminPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        tk.Frame.configure(self)
        tk.Label(self, text="Admin Menu", font=('Times', 20, "bold")).pack(side="top", fill="x", pady=7)
        tk.Button(self, text="Change password", command=lambda: master.switch_page(ChangePasswordPage)).pack()
        tk.Button(self, text="User list", command=lambda: master.switch_page(UserListPage)).pack()
        tk.Button(self, text="Add User", command=lambda: master.switch_page(AddUserPage)).pack()

        tk.Button(self, text="Logout", command=lambda: master.switch_page(LoginPage)).pack()


class UserPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        tk.Frame.configure(self)
        tk.Label(self, text="User menu", font=('Times', 20, "bold")).pack(side="top", fill="x", pady=7)
        tk.Button(self, text="Change password", command=lambda: master.switch_page(ChangePasswordPage)).pack()
        tk.Button(self, text="Logout", command=lambda: master.switch_page(LoginPage)).pack()

class UserListPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.master = master
        self.user_labels = {}
        
        for user in ui:
            frame = tk.Frame(self)
            frame.pack()
            
            label_text = f"{user} {self.get_status(user)}"
            label = tk.Label(frame, text=label_text)
            label.pack(side=tk.LEFT)
            self.user_labels[user] = label
            
            tk.Button(frame, text="Ban", command=lambda u=user: self.set_ban(u, True)).pack(side=tk.LEFT)
            tk.Button(frame, text="Unban", command=lambda u=user: self.set_ban(u, False)).pack(side=tk.LEFT)
            tk.Button(frame, text="Restrict", command=lambda u=user: self.set_restrict(u, True)).pack(side=tk.LEFT)
            tk.Button(frame, text="Unrestrict", command=lambda u=user: self.set_restrict(u, False)).pack(side=tk.LEFT)
            
        tk.Button(self, text="Back", command=lambda: master.switch_page(AdminPage)).pack()
    
    def get_status(self, user):
        status = []
        if ui[user]["ban"]:
            status.append("banned")
        if ui[user]["restrict"]:
            status.append("restricted")
        return " ".join(status)

    def update_label(self, user):
        self.user_labels[user].config(text=f"{user} {self.get_status(user)}")

    def set_ban(self, user, state):
        ui[user]["ban"] = state
        self.save_ui()
        self.update_label(user)
    
    def set_restrict(self, user, state):
        ui[user]["restrict"] = state
        self.save_ui()
        self.update_label(user)
    
    def save_ui(self):
        with open("users.json", 'w') as ui_file:
            ui_file.write(json.dumps(ui))

class AddUserPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        tk.Label(self, text="Unique username").pack()
        self.username = tk.Entry(self)
        self.username.pack()

        tk.Button(self, text="Add user", command=self.add_user).pack()

        tk.Button(self, text="Back", command=lambda: master.switch_page(AdminPage)).pack()

    def add_user(self):
        username = self.username.get()
        user = ui.get(username)
        if user:
            mb.showinfo("Info", "Користувач вже існує")
        else:
            ui[username] = {"password": first_password, "restrict": False, "ban": False}
            with open("users.json", 'w') as ui_file:
                ui_file.write(json.dumps(ui))

class ChangePasswordPage(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)

        tk.Label(self, text="old pass").pack()
        self.old_pass = tk.Entry(self, show="*")
        self.old_pass.pack()

        tk.Label(self, text="new pass").pack()
        self.new_pass = tk.Entry(self, show="*")
        self.new_pass.pack()

        tk.Label(self, text="new pass2").pack()
        self.new_pass2 = tk.Entry(self, show="*")
        self.new_pass2.pack()

        tk.Button(self, text="Save", command=self.save).pack()
        tk.Button(self, text="Back", command=self.back).pack()

    def save(self):
        user = ui[current_user]
        old_pass = self.old_pass.get()
        hashed_old_pass = hash_password(old_pass)
        
        if user["password"] == hashed_old_pass:
            new_pass = self.new_pass.get()
            new_pass2 = self.new_pass2.get()
    
            if new_pass != new_pass2:
                mb.showinfo("Info", "Паролі не співпадають")
                return
    
            if user["restrict"]:
                pattern = r'^(?=.*[a-zA-Z])(?=.*[А-яЇїЄєҐґ])(?=.*\d).+$'
                if not re.match(pattern, new_pass):
                    mb.showinfo("Info", "Пароль повинен містити латинські літери, кириличні літери та цифри")
                    return
    
            user["password"] = hash_password(new_pass)
            with open("users.json", 'w') as ui_file:
                json.dump(ui, ui_file)
    
            if current_user == "admin":
                self.master.switch_page(AdminPage)
            else:
                self.master.switch_page(UserPage)
        else:
            mb.showinfo("Info", "Старий пароль невірний")

    def back(self):
        if current_user == "admin":
            self.master.switch_page(AdminPage)
        else:
            self.master.switch_page(UserPage)
        
REG_PATH = r"Software\Orlov"

def get_system_info():
    username = os.getlogin()
    computer_name = os.getenv('COMPUTERNAME')
    windows_dir = os.getenv('WINDIR')
    system_root = os.getenv('SystemRoot')
    mouse_buttons = os.getenv("NUMBER_OF_MOUSE_BUTTONS")
    screen_width = str(os.get_terminal_size().columns) if os.name != 'nt' else str(os.system('wmic desktopmonitor get screenwidth'))
    disks = ','.join([d for d in os.popen("wmic logicaldisk get name").read().split()[1:]])
    disk_info = os.popen("wmic logicaldisk get size").read().split()[1]
    sys_data = f"{username}{computer_name}{windows_dir}{system_root}{mouse_buttons}{screen_width}{disks}{disk_info}".encode()
    return hashlib.sha256(sys_data).digest()

def get_registry_value(name):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
        value, _ = winreg.QueryValueEx(key, name)
        return value

def verify_signature():
    pubkey_pem = get_registry_value("PublicKey")
    signature = get_registry_value("Signature")

    if not pubkey_pem or not signature:
        print("Error: The public key or signature is missing from the registry.")
        sys.exit(1)
    system_hash = get_system_info()

    try:
        pubkey = rsa.PublicKey.load_pkcs1(pubkey_pem)
        rsa.verify(system_hash, signature, pubkey)
        print("[+] Signature Verified!")
    except rsa.VerificationError:
        print("[-] Error: Signature does not match. Unable to launch.")
        sys.exit(1)

#NEW
import hashlib
import base64
import os
import secrets
import tkinter as tk
import tkinter.messagebox as mb
import tkinter.simpledialog as sd
import winreg
import win32crypt
import ctypes
import atexit
import sys
import time

# Константы
REG_PATH = r"Software\Orlov"
PASS_KEY_NAME = "PassphraseHash"
SALT_KEY_NAME = "Salt"
JSON_FILE = "users.json"
ENC_FILE = "users.enc"


def store_registry_value(name, value):
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def get_registry_value(name):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
        value, _ = winreg.QueryValueEx(key, name)
        return value


def initialize_passphrase():
    if not os.path.exists(ENC_FILE):  # Первый запуск
        root = tk.Tk()
        root.withdraw()
        passphrase = sd.askstring("Setup", "Введите кодовую фразу:", show="*")
        if not passphrase:
            mb.showerror("Ошибка", "Кодовая фраза не указана.")
            sys.exit(1)

        salt = secrets.token_bytes(16)
        key = hashlib.sha256(passphrase.encode() + salt).digest()
        store_registry_value(PASS_KEY_NAME, base64.b64encode(key).decode())
        store_registry_value(SALT_KEY_NAME, base64.b64encode(salt).decode())
        print("[+] Кодовая фраза установлена.")
        return key


def verify_passphrase():
    try:
        stored_hash = base64.b64decode(get_registry_value(PASS_KEY_NAME))
        salt = base64.b64decode(get_registry_value(SALT_KEY_NAME))
    except Exception:
        mb.showerror("Ошибка", "Кодовая фраза не настроена.")
        sys.exit(1)

    root = tk.Tk()
    root.withdraw()
    passphrase = sd.askstring("Проверка", "Введите кодовую фразу:", show="*")
    if not passphrase:
        mb.showerror("Ошибка", "Кодовая фраза не указана.")
        sys.exit(1)

    key = hashlib.sha256(passphrase.encode() + salt).digest()
    if key != stored_hash:
        mb.showerror("Ошибка", "Неверная кодовая фраза.")
        sys.exit(1)
    return key  # Возвращаем сессионный ключ


def encrypt_file_on_exit(key: bytes):
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "rb") as f:
            data = f.read()

        # Шифруем данные с помощью CryptProtectData
        encrypted_blob = win32crypt.CryptProtectData(
            data,  # Данные для шифрования (прямо байты)
            None,  # Название данных, None для простоты
            key,   # Секретный ключ (entropy)
            None,  # Reserved (None)
            None,  # CRYPTPROTECT_PROMPTSTRUCT (None)
            0      # Флаги (обычно 0)
        )

        # Записываем зашифрованные данные в файл
        with open(ENC_FILE, "wb") as ef:
            ef.write(encrypted_blob)  
        os.remove(JSON_FILE)
        print("[*] Данные зашифрованы при выходе.")

def decrypt_file_on_start(key: bytes):
    if os.path.exists(ENC_FILE):
        with open(ENC_FILE, "rb") as ef:
            encrypted_data = ef.read()

        # Расшифровываем данные с помощью CryptUnprotectData
        decrypted_data = win32crypt.CryptUnprotectData(
            encrypted_data,  # Данные для расшифровки (прямо байты)
            key,   # Секретный ключ (entropy)
            None,  # Reserved (None)
            None,  # CRYPTPROTECT_PROMPTSTRUCT (None)
            0      # Флаги (обычно 0)
        )[1]  # Второй элемент результата содержит расшифрованные данные

        # Записываем расшифрованные данные в файл
        with open(JSON_FILE, "wb") as f:
            f.write(decrypted_data)
        print("[*] Данные расшифрованы при запуске.")

if __name__ == "__main__":
    verify_signature()  # 1. Проверка сигнатуры

    # 2. Проверка кодовой фразы
    key = initialize_passphrase()
    if key is None:
        key = verify_passphrase()

    # 3. Работа с файлами
    if os.path.exists(ENC_FILE) and os.access(ENC_FILE, os.R_OK):
        # Есть users.enc — расшифровываем
        decrypt_file_on_start(key)
        os.remove(ENC_FILE)
        print("[*] Зашифрованный файл удалён, данные сохранены как users.json.")

    elif not os.path.exists(JSON_FILE) or not os.access(JSON_FILE, os.R_OK):
        # Нет ни .json, ни .enc — создаём новый users.json
        ui = {"admin": {"password": first_password, "restrict": False, "ban": False}}
        time.sleep(1)
        with open(JSON_FILE, 'w') as ui_file:
            json.dump(ui, ui_file)
        print("[*] Новый users.json был создан.")
        
    with open("users.json", "r") as f:
    ui = json.load(f)
    # 4. Запуск GUI
    app = App(key)
    app.mainloop()
