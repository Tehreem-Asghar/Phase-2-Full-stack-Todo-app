from dataclasses import dataclass

@dataclass
class Task:
    """Represents a single task in the to-do list."""
    id: int
    title: str
    description: str
    is_completed: bool = False
