"""Terminal UI for navigating menus, collecting input, and dispatching.password_manager actions."""

import os
import subprocess
import time

import questionary
from prompt_toolkit.key_binding.key_bindings import Binding
from questionary import Choice, Separator, Style

from ..config import CONTROL_BINDINGS, MENUS
from .models import CreateUserFieldGroup, FieldGroup, LoginFieldGroup, Menu
from ..services.password_manager import PasswordManager


class TerminalUI:
    """Interactive command-line front end built on questionary prompts."""
    
    def __init__(self, password_manager: PasswordManager):
        self.password_manager = password_manager
        self.root_menu: Menu
        self.user_menu: Menu
        self.is_loggedin = False
        self.exit_flag = False
        
    def add_custom_bindings(self, question: questionary.Question):
        """Bind the left arrow to cancel the current prompt and return None."""
        binding = Binding(
            keys=("left",),
            handler=lambda event: event.app.exit(result=None),
            eager=True,
        )
        question.application.key_bindings.bindings.insert(0, binding)
        binding = Binding(
            keys=("c-c",),
            handler=lambda event: event.app.exit(result=None),
            eager=True,
        )
        question.application.key_bindings.bindings.insert(0, binding)
        
        return question
    
    def get_fields(self, field_group: FieldGroup) -> FieldGroup | None:
        """Prompt for each field in order; left arrow moves back or cancels on the first field."""
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
                # Erase the previous prompt lines from the terminal before re-asking.
                print("\033[1A\033[2K", end="")
                print("\033[1A\033[2K", end="")
                counter -= 1
            else:
                field.value = value
                counter += 1
        return field_group
    
    def build_display_menus(self):
        """Convert MENUS entries into Menu objects wired to handler callables."""
        dispatch_table = self.get_dispatch_table()
        for key, values in MENUS.items():
            choices = []
            for value in values["choices"]:
                if value["action"] in dispatch_table:
                    choice = Choice(title=value["title"], value=dispatch_table[value["action"]])
                    choices.append(choice)
                else:
                    seperator = Separator(line=" ")
                    choices.append(seperator)
            menu = Menu(title=values["title"], choices=choices)
            setattr(self, key, menu)
    
    def get_dispatch_table(self):
        """Map menu action names to bound UI handler methods."""
        return {
            "login": self.login,
            "create_user": self.create_user,
            "delete_user": self.delete_user,
            "exit_app": self.exit_app,
            "view_passwords": self.view_passwords,
            "create_password": self.create_password,
            "update_password": self.update_password,
            "delete_password": self.delete_password
        }
    
    def build_password_menu(self, passwords: dict) -> Menu:
        """Build a selectable list of password rows for update and delete flows."""
        choices = []
        tabs = "                    "
        for password_id, value in passwords.items():
            choice = Choice(title=f"{str(password_id) + tabs}{value["name"] + tabs}{value["plaintext"]+ tabs}{str(value["created_at"]) + tabs}", value=value)
            choices.append(choice)
        return Menu(title="ezpass/user/passwords", choices=choices)
    
    def login(self):
        """Collect credentials and attempt authentication until success or cancellation."""
        self.clear_terminal()
        while not self.password_manager.is_authenticated():
            self.clear_terminal()
            login_field_group = LoginFieldGroup()
            login_field_group = self.get_fields(login_field_group)
            if login_field_group:
                self.is_loggedin = self.password_manager.login(login_field_group)
                if self.is_loggedin:
                    return True
                else:
                    self.clear_terminal()
                    questionary.print("ERROR during sign-in; username or password is incorrect.", style="red")
                    time.sleep(4)
            elif login_field_group is None:
                return
        
    def create_user(self):
        """Walk through account creation fields and submit them to the.password_manager."""
        self.clear_terminal()
        create_user_field_group = CreateUserFieldGroup()
        while True:
            create_user_field_group = self.get_fields(create_user_field_group)
            if create_user_field_group:
                self.password_manager.create_user(create_user_field_group)
            return
  
    def delete_user(self):
        """Require login, then confirm and delete the authenticated account."""
        self.password_manager.logout()
        if self.login() and questionary.confirm("Are you sure you want to delete your account?:", default=False).ask():
            self.password_manager.delete_user()
            self.clear_terminal()
            questionary.print("Your account has been deleted.", style="green")
            time.sleep(4)
        else:
            self.password_manager.logout()

    def view_passwords(self):
        """Fetch decrypted passwords from the.password_manager and print them for selection menus."""
        self.clear_terminal()
        if self.password_manager.is_authenticated():
            passwords = self.password_manager.get_passwords()
            if passwords:
                questionary.print("\n")
                for id, password in passwords.items():
                    questionary.print(f"{id}\t\t{password["name"]}\t\t\t\t{password["plaintext"]}\t\t\t\t{password["created_at"]}")
                questionary.print("\n")
                questionary.press_any_key_to_continue("Press Any Key to Continue...").ask()
                return passwords
            else:
                self.clear_terminal()
                questionary.print("Hmm... It looks like you don't have any passwords yet.")
                time.sleep(4)
    
    def create_password(self):
        """Prompt for entry metadata and delegate password generation to the.password_manager."""
        self.clear_terminal()
        password_name = self.add_custom_bindings(questionary.text("ID Name:")).ask()
        if not password_name:
            return
        use_recommended_params = questionary.confirm("Use recommended parameters?").ask()
        if use_recommended_params:
            self.password_manager.create_password(password_name)
        else:
            length = questionary.text("Desired Password Length:").ask()
            include = questionary.text("Included Special Characters:").ask()
            self.password_manager.create_password(password_name, length, include)
        
    def update_password(self):
        """Let the user pick a stored password and submit a new plaintext value."""
        self.clear_terminal()
        if self.password_manager.is_authenticated():
            passwords = self.password_manager.get_passwords()
            password_menu = self.build_password_menu(passwords)
            if passwords:
                password = self.add_custom_bindings(questionary.select(
                    message=password_menu.title,
                    choices=password_menu.choices,
                    default=None
                )).ask()
                if password["id"] in passwords:
                    plaintext = questionary.text("Update", passwords[password["id"]]["plaintext"]).ask()
                    self.password_manager.update_password(password["id"], plaintext)
            
    
    def delete_password(self):
        """Let the user pick a stored password and remove it from the vault."""
        self.clear_terminal()
        if self.password_manager.is_authenticated():
            passwords = self.password_manager.get_passwords()
            password_menu = self.build_password_menu(passwords)
            if passwords:
                password = self.add_custom_bindings(questionary.select(
                    message=password_menu.title,
                    choices=password_menu.choices,
                    default=None
                )).ask()
                if password:
                    self.password_manager.delete_password(password["id"])
    
    def exit_app(self):
        """Signal the main loop to terminate."""
        self.exit_flag = True
    
    def display_root_menu(self):
        """Show the unauthenticated menu and invoke the selected action."""
        self.clear_terminal()
        method = self.add_custom_bindings(
            questionary.select(
                message=self.root_menu.title,
                choices=self.root_menu.choices,
                instruction=CONTROL_BINDINGS,
                style=Style([
                    ("answer", "hidden")
                ])
            )
        ).ask()
        if callable(method):
            method()
        else:
            self.exit_app()
        
    def display_user_menu(self):
        """Show the authenticated vault menu and invoke the selected action."""
        self.clear_terminal()
        method = self.add_custom_bindings(
            questionary.select(
                message=self.user_menu.title,
                choices=self.user_menu.choices,
                instruction=CONTROL_BINDINGS,
                style=Style([
                    ("answer", "hidden")
                ])
            )
        ).ask()
        if callable(method):
            method()
        else:
            return self.display_root_menu()
        
    def run(self):
        """Initialize menus and loop until the user exits the application."""
        self.build_display_menus()
        while self.exit_flag == False:
            if self.password_manager.is_authenticated():
                self.user_menu.title
                self.display_user_menu()
            else:
                self.display_root_menu()
    
    def clear_terminal(self):
        """Clear the terminal screen using the platform-appropriate command."""
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)
    