import unittest
from todo_app.services.task_service import TaskService
from todo_app.models.task import Task

class TestTaskService(unittest.TestCase):

    def setUp(self):
        """Set up a new TaskService instance before each test."""
        self.task_service = TaskService()

    def test_add_task_creates_task_with_correct_details(self):
        """Test that add_task creates a task with the correct title, description, and ID."""
        title = "Buy groceries"
        description = "Milk, Eggs, Bread"
        task = self.task_service.add_task(title, description)

        self.assertIsInstance(task, Task)
        self.assertEqual(task.id, 1)
        self.assertEqual(task.title, title)
        self.assertEqual(task.description, description)
        self.assertFalse(task.is_completed)

        self.assertEqual(len(self.task_service._tasks), 1)
        self.assertEqual(self.task_service._tasks[0], task)

    def test_add_task_increments_id_correctly(self):
        """Test that add_task assigns incrementing IDs to new tasks."""
        task1 = self.task_service.add_task("Task 1", "Desc 1")
        task2 = self.task_service.add_task("Task 2", "Desc 2")

        self.assertEqual(task1.id, 1)
        self.assertEqual(task2.id, 2)
        self.assertEqual(len(self.task_service._tasks), 2)

    def test_view_tasks_returns_all_tasks(self):
        """Test that view_tasks returns all tasks that have been added."""
        self.task_service.add_task("Task 1", "Desc 1")
        self.task_service.add_task("Task 2", "Desc 2")
        tasks = self.task_service.view_tasks()
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0].title, "Task 1")
        self.assertEqual(tasks[1].title, "Task 2")

    def test_view_tasks_returns_empty_list_if_no_tasks(self):
        """Test that view_tasks returns an empty list if no tasks have been added."""
        tasks = self.task_service.view_tasks()
        self.assertEqual(len(tasks), 0)
        self.assertEqual(tasks, [])

    def test_update_task_updates_details_correctly(self):
        """Test that update_task correctly updates a task's title and description."""
        task = self.task_service.add_task("Old Title", "Old Desc")
        updated_task = self.task_service.update_task(task.id, "New Title", "New Desc")

        self.assertEqual(updated_task.title, "New Title")
        self.assertEqual(updated_task.description, "New Desc")
        self.assertEqual(task.title, "New Title") # Verify internal state updated
        self.assertEqual(task.description, "New Desc") # Verify internal state updated

    def test_update_task_updates_only_title(self):
        """Test that update_task updates only the title if description is not provided."""
        task = self.task_service.add_task("Old Title", "Old Desc")
        updated_task = self.task_service.update_task(task.id, title="New Title Only")

        self.assertEqual(updated_task.title, "New Title Only")
        self.assertEqual(updated_task.description, "Old Desc") # Description should remain unchanged

    def test_update_task_updates_only_description(self):
        """Test that update_task updates only the description if title is not provided."""
        task = self.task_service.add_task("Old Title", "Old Desc")
        updated_task = self.task_service.update_task(task.id, description="New Desc Only")

        self.assertEqual(updated_task.title, "Old Title") # Title should remain unchanged
        self.assertEqual(updated_task.description, "New Desc Only")

    def test_update_task_not_found_raises_error(self):
        """Test that update_task raises ValueError if the task ID is not found."""
        self.task_service.add_task("Task", "Desc") # Add one task so list is not empty
        with self.assertRaisesRegex(ValueError, "Task with ID 999 not found."):
            self.task_service.update_task(999, "Non Existent")

    def test_update_task_with_empty_title_raises_error(self):
        """Test that update_task raises ValueError if an empty title is provided."""
        task = self.task_service.add_task("Task", "Desc")
        with self.assertRaisesRegex(ValueError, "Title cannot be empty."):
            self.task_service.update_task(task.id, "")

    def test_delete_task_removes_task_correctly(self):
        """Test that delete_task removes the specified task."""
        task1 = self.task_service.add_task("Task 1", "Desc 1")
        task2 = self.task_service.add_task("Task 2", "Desc 2")

        self.task_service.delete_task(task1.id)
        tasks = self.task_service.view_tasks()
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].id, task2.id)

    def test_delete_task_not_found_raises_error(self):
        """Test that delete_task raises ValueError if the task ID is not found."""
        self.task_service.add_task("Task 1", "Desc 1") # Ensure list is not empty
        with self.assertRaisesRegex(ValueError, "Task with ID 999 not found."):
            self.task_service.delete_task(999)

    def test_complete_task_marks_task_as_completed(self):
        """Test that complete_task sets the is_completed status to True."""
        task = self.task_service.add_task("Task to complete", "Desc")
        completed_task = self.task_service.complete_task(task.id)

        self.assertTrue(completed_task.is_completed)
        self.assertTrue(task.is_completed) # Verify internal state updated

    def test_complete_task_not_found_raises_error(self):
        """Test that complete_task raises ValueError if the task ID is not found."""
        self.task_service.add_task("Task", "Desc") # Ensure list is not empty
        with self.assertRaisesRegex(ValueError, "Task with ID 999 not found."):
            self.task_service.complete_task(999)

    def test_add_task_with_empty_title_raises_error(self):
        """Test that add_task raises ValueError if title is empty."""
        with self.assertRaisesRegex(ValueError, "Title cannot be empty."):
            self.task_service.add_task("", "Description")