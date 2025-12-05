from todo_app.services.task_service import TaskService

def display_menu():
    """Displays the main menu options to the user."""
    print("\n--- To-Do List Application ---")
    print("1. Add Task")
    print("2. View Tasks")
    print("3. Update Task")
    print("4. Delete Task")
    print("5. Mark Task as Complete")
    print("6. Exit")
    print("----------------------------")

def main():
    """Main function to run the To-Do List Application."""
    task_service = TaskService()

    while True:
        display_menu()
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            title = input("Enter task title: ").strip()
            description = input("Enter task description (optional): ").strip()
            try:
                task = task_service.add_task(title, description)
                print(f"Task '{task.title}' (ID: {task.id}) added successfully.")
            except ValueError as e:
                print(f"Error: {e}")
        elif choice == '2':
            tasks = task_service.view_tasks()
            if not tasks:
                print("No tasks to show.")
            else:
                print("\n--- Your Tasks ---")
                for task in tasks:
                    status = "Complete" if task.is_completed else "Incomplete"
                    print(f"ID: {task.id}, Title: {task.title}, Description: {task.description}, Status: {status}")
                print("------------------")
        elif choice == '3':
            try:
                task_id = int(input("Enter the ID of the task to update: ").strip())
                new_title = input("Enter new title (leave blank to keep current): ").strip()
                new_description = input("Enter new description (leave blank to keep current): ").strip()

                if not new_title and not new_description:
                    print("No update provided. Task remains unchanged.")
                    continue

                updated_task = task_service.update_task(
                    task_id,
                    new_title if new_title else None,
                    new_description if new_description else None
                )
                print(f"Task ID {updated_task.id} updated successfully.")
            except ValueError as e:
                print(f"Error: {e}")
            except Exception: # Catch non-integer input for task_id
                print("Invalid input. Please enter a valid task ID.")
        elif choice == '4':
            try:
                task_id = int(input("Enter the ID of the task to delete: ").strip())
                task_service.delete_task(task_id)
                print(f"Task ID {task_id} deleted successfully.")
            except ValueError as e:
                print(f"Error: {e}")
            except Exception: # Catch non-integer input for task_id
                print("Invalid input. Please enter a valid task ID.")
        elif choice == '5':
            try:
                task_id = int(input("Enter the ID of the task to mark as complete: ").strip())
                task_service.complete_task(task_id)
                print(f"Task ID {task_id} marked as complete.")
            except ValueError as e:
                print(f"Error: {e}")
            except Exception: # Catch non-integer input for task_id
                print("Invalid input. Please enter a valid task ID.")
        elif choice == '6':
            print("Exiting application. All tasks lost (in-memory only). Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

