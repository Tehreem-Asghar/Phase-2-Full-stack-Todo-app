from typing import List
from todo_app.models.task import Task

class TaskService:
    """Manages the in-memory storage and business logic for tasks."""

    def __init__(self):
        """Initializes the TaskService with an empty list of tasks and an ID counter."""
        self._tasks: List[Task] = []
        self._next_id: int = 1

    def add_task(self, title: str, description: str) -> Task:
        """
        Creates and adds a new task to the list.

        Args:
            title: The title of the task.
            description: The description of the task.

        Returns:
            The newly created task.
        """
        if not title:
            raise ValueError("Title cannot be empty.")
            
        task = Task(id=self._next_id, title=title, description=description)
        self._tasks.append(task)
        self._next_id += 1
        return task

    def view_tasks(self) -> List[Task]:
        """
        Returns the current list of all tasks.
        """
        return self._tasks

    def update_task(self, task_id: int, title: str = None, description: str = None) -> Task:
        """
        Updates an existing task's title and/or description.

        Args:
            task_id: The ID of the task to update.
            title: The new title for the task (optional).
            description: The new description for the task (optional).

        Returns:
            The updated task.

        Raises:
            ValueError: If the task with the given ID is not found.
        """
        for task in self._tasks:
            if task.id == task_id:
                if title is not None:
                    if not title:
                        raise ValueError("Title cannot be empty.")
                    task.title = title
                if description is not None:
                    task.description = description
                return task
        raise ValueError(f"Task with ID {task_id} not found.")

    def delete_task(self, task_id: int) -> None:
        """
        Deletes a task by its ID.

        Args:
            task_id: The ID of the task to delete.

        Raises:
            ValueError: If the task with the given ID is not found.
        """
        initial_len = len(self._tasks)
        self._tasks = [task for task in self._tasks if task.id != task_id]
        if len(self._tasks) == initial_len:
            raise ValueError(f"Task with ID {task_id} not found.")

    def complete_task(self, task_id: int) -> Task:
        """
        Marks a task as completed by its ID.

        Args:
            task_id: The ID of the task to mark as complete.

        Returns:
            The completed task.

        Raises:
            ValueError: If the task with the given ID is not found.
        """
        for task in self._tasks:
            if task.id == task_id:
                task.is_completed = True
                return task
        raise ValueError(f"Task with ID {task_id} not found.")


