// frontend/components/TaskList.tsx
import TaskItem from "./TaskItem";

interface Task {
  id: string;
  title: string;
  description?: string;
  status: string;
  user_id: string;
  created_at: string;
}

interface TaskListProps {
  tasks: Task[];
  onTaskUpdated: () => void; // Add this prop
}

export default function TaskList({ tasks, onTaskUpdated }: TaskListProps) {
  if (!tasks || tasks.length === 0) {
    return (
      <div className="text-center text-gray-500 text-lg py-12 animate-fade-in">
        <svg className="mx-auto h-12 w-12 text-gray-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
        </svg>
        <p>No tasks found. Start by creating a new one!</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {tasks.map((task) => (
        <TaskItem key={task.id} task={task} onTaskUpdated={onTaskUpdated} /> // Pass the callback
      ))}
    </div>
  );
}