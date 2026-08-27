import os
import subprocess

import questionary
from prompt_toolkit.key_binding.key_bindings import Binding
from questionary import Choice

from models import CreateUserFieldGroup, FieldGroup, LoginFieldGroup, Menu
from services.client import Client


class TerminalUI:
    #Could create hook to generate values as needed.
    MENU_CONFIG = {
        "root_menu": {
            "title": "ezpass",
            "choices": [
                {"title": "Login", "action": "login"},
                {"title": "Create User", "action": "create_user"},
                {"title": "Delete User", "action": "delete_user"}
            ]
        },
        "user_menu": {
            "title": "ezpass/user",
            "choices": [
                {"title": "View", "action": "view_passwords"},
                {"title": "Create", "action": "create_password"},
                {"title": "Update", "action": "update_password"},
                {"title": "Delete", "action": "delete_password"}
            ]
        }
    }
    
    NAV_CONTROLS = "            [ ← Back  ↑ Up / ↓ Down  Select → ]"
    
    def __init__(self, client: Client):
        self.client = client
        self.root_menu: Menu
        self.user_menu: Menu
        self.exit_flag = False
        
    def add_custom_bindings(self, question: questionary.Question):
        binding = Binding(
            keys=("left",),
            handler=lambda event: event.app.exit(result=None),
            eager=True,
        )
        question.application.key_bindings.bindings.insert(0, binding)
        
        return question
    
    def get_fields(self, field_group: FieldGroup) -> FieldGroup | None:
        counter = 0
        attrs = list(vars(field_group).items())
        while counter < len(vars(field_group)):
            value = self.add_custom_bindings(attrs[counter][1].event).ask()
            field = attrs[counter][1]
            if value == None and counter == 0:
                field.value = None
                return None
            elif value == None:
                field.value = None
                print("\033[1A\033[2K", end="")
                print("\033[1A\033[2K", end="")
                counter -= 1
            else:
                field.value = value
                counter += 1
        return field_group
    
    def build_display_menus(self):
        for key, values in self.MENU_CONFIG.items():
            choices = []
            for value in self.MENU_CONFIG[key]["choices"]:
                dispatch_table = self.get_dispatch_table()
                if value["action"] in dispatch_table:
                    choice = Choice(title=value["title"], value=dispatch_table[value["action"]])
                    choices.append(choice) 
            menu = Menu(title=values["title"], choices=choices)
            setattr(self, key, menu)
    
    def get_dispatch_table(self):
        return {
            "login": self.login,
            "create_user": self.create_user,
            "delete_user": self.delete_user,
            "view_passwords": self.view_passwords,
            "create_password": self.create_password,
            "update_password": self.update_password,
            "delete_password": self.delete_password
        }
    
    def build_password_menu(self, passwords: dict) -> Menu:
        choices = []
        tabs = "            "
        for password_id, value in passwords.items():
            choice = Choice(title=f"{str(password_id) + tabs}{value["name"] + tabs}{value["password"]+ tabs}{str(value["created_at"]) + tabs}", value=password_id)
            choices.append(choice)
        return Menu(title="ezpass/user/passwords", choices=choices)
    
    def login(self):
        while not self.client.is_authenticated():
            login_field_group = LoginFieldGroup()
            login_field_group = self.get_fields(login_field_group)
            if login_field_group:
                self.is_loggedin = self.client.login(login_field_group)
                return self.is_loggedin
            elif login_field_group is None:
                return
        
    def create_user(self):
        create_user_field_group = CreateUserFieldGroup()
        while True:
            create_user_field_group = self.get_fields(create_user_field_group)
            if create_user_field_group:
                self.client.create_user(create_user_field_group)
            return
  
    def delete_user(self):
        if self.login() and questionary.confirm("Are you sure you want to delete your account?:", default=False).ask():
            self.client.delete_user()
    
    def view_passwords(self):
        if self.client.is_authenticated():
            passwords = self.client.get_passwords()
            #Print pretty with rich
            print(passwords)
            return passwords
    
    def create_password(self):
        password_name = questionary.text("ID Name:").ask()
        use_recommended_params = questionary.confirm("Use recommended parameters?").ask()
        if use_recommended_params:
            self.client.create_password(password_name)
        else:
            length = questionary.text("Desired Password Length:").ask()
            include = questionary.text("Included Special Characters:").ask()
            self.client.create_password(password_name, length, include)
        
    def update_password(self):
        if self.client.is_authenticated():
            passwords = self.view_passwords()
            password_menu = self.build_password_menu(passwords)
            #can nest selects, but implement with prompt.toolkit
            if passwords:
                password_id = questionary.select(
                    message=password_menu.title,
                    choices=password_menu.choices
                ).ask()
                plaintext = questionary.text("Update", passwords[password_id]["password"]).ask()
                self.client.update_password(password_id, plaintext)
            
    
    def delete_password(self):
        if self.client.is_authenticated():
            passwords = self.view_passwords()
            password_menu = self.build_password_menu(passwords)
            #can nest selects, but implement with prompt.toolkit
            if passwords:
                password_id = questionary.select(
                    message=password_menu.title,
                    choices=password_menu.choices
                ).ask()
                self.client.delete_password(password_id)
    
    def display_root_menu(self):
        method = self.add_custom_bindings(
            questionary.select(
                message=self.root_menu.title,
                choices=self.root_menu.choices,
                instruction=self.NAV_CONTROLS
            )
        ).ask()
        if callable(method):
            method()
        else:
            self.exit_flag = True
        
    def display_user_menu(self):
        method = self.add_custom_bindings(
            questionary.select(
                message=self.user_menu.title,
                choices=self.user_menu.choices,
                instruction=self.NAV_CONTROLS
            )
        ).ask()
        if callable(method):
            method()
        else:
            self.client.logout()
        
    def run(self):
        self.build_display_menus()
        while self.exit_flag == False:
            if self.client.is_authenticated():
                self.display_user_menu()
            else:
                self.display_root_menu()
    
    def clear_terminal(self):
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)