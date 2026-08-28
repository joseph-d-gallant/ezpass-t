# Menu definitions map display labels to handler action names.
# Entries with action=None render as visual separators.
GLOBAL_STYLE = [
    
]

MENUS = {
    "root_menu": {
        "title": "ezpass",
        "choices": [
            {"title": "Login", "action": "login"},
            {"title": "Create User", "action": "create_user"},
            {"title": "Delete User", "action": "delete_user"},
            {"title": None, "action": None},
            {"title": "Exit", "action": "exit_app"},
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

#Update later to add other custom bindings for matching MENUs or types (text, select, prompt...)
CONTROL_BINDINGS = "            [ ← Back  ↑ Up / ↓ Down  Select → ]"