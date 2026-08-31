from questionary import Choice
from dataclasses import dataclass

@dataclass
class Menu:
    """Questionary menu definition pairing a title with selectable choices."""

    title: str
    choices: list[Choice]