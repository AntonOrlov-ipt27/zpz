import hashlib
import json
import os
import tkinter as tk
import tkinter.messagebox as mb
import re
import winreg
import hashlib
import platform
import rsa
import sys

ui = None
current_user = None
fail_count = 0

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
    
first_password = hash_password("")   

if os.path.isfile("users.json") and os.access("users.json", os.R_OK):
    ui = json.load(open("users.json"))
else:
    with open("users.json", 'w') as ui_file:
        ui = {"admin": {"password": first_password, "restrict": False, "ban": False}}
        ui_file.write(json.dumps(ui))
    
class App(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)

        self.page = None
        about_menu = tk.Menu(self, tearoff=0)
        about_menu.add_command(label="Про програму", command=lambda: mb.showinfo("Info", "Автор: ФБ-22 Орлов Антон"
                                                                                         "\nВаріант №6"))
        menu = tk.Menu(self)
        menu.add_cascade(label="Довідка", menu=about_menu)
        self.config(menu=menu)
        self.switch_page(LoginPage)
        self.geometry("600x300")

    def switch_page(self, page_class):
        new_page = page_class(self)
        if self.page is not None:
            self.page.destroy()
        self.page = new_page
        self.page.pack()

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
    """Получает имя пользователя и хеширует его"""
    username = os.getlogin()
    return hashlib.sha256(username.encode()).digest()

def get_registry_value(name):
    """Получает значение из реестра"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None

def verify_signature():
    """Проверяет подпись, используя имя пользователя"""
    pubkey_pem = get_registry_value("PublicKey")
    signature = get_registry_value("Signature")

    if not pubkey_pem or not signature:
        print("Ошибка: Публичный ключ или подпись отсутствуют в реестре.")
        sys.exit(1)

    system_hash = get_system_info()  # Теперь это хеш имени пользователя

    try:
        pubkey = rsa.PublicKey.load_pkcs1(pubkey_pem)  
        rsa.verify(system_hash, signature, pubkey)
        print("[+] Подпись верна, запуск разрешен.")
    except rsa.VerificationError:
        print("Ошибка: Подпись не совпадает. Запуск невозможен.")
        sys.exit(1)

if __name__ == "__main__":
    verify_signature()
    print("[*] Запуск приложения...")
    app = App()
    app.mainloop()
