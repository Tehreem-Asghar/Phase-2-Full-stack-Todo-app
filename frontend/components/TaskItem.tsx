// frontend/components/TaskItem.tsx
"use client";

import { useState, useEffect } from "react";
import { getToken } from "../lib/auth";

interface Task {
  id: string;
  title: string;
  description?: string;
  status: string;
  user_id: string;
  created_at: string;
}

interface TaskItemProps {
  task: Task;
  onTaskUpdated: () => void; // Callback to refresh task list
}

export default function TaskItem({ task, onTaskUpdated }: TaskItemProps) {
  const [currentTitle, setCurrentTitle] = useState(task.title);
  const [currentDescription, setCurrentDescription] = useState(task.description || "");
  const [currentStatus, setCurrentStatus] = useState(task.status);
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Update local state when task prop changes
  useEffect(() => {
    setCurrentTitle(task.title);
    setCurrentDescription(task.description || "");
    setCurrentStatus(task.status);
  }, [task]);

  // Status badge styling based on status
  const getStatusStyles = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-100 text-green-800 border-green-200";
      case "in-progress":
        return "bg-blue-100 text-blue-800 border-blue-200";
      case "todo":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  const handleStatusChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newStatus = e.target.value;
    setCurrentStatus(newStatus);
    await sendUpdate({ status: newStatus });
  };

  const handleEdit = () => {
    setIsEditing(true);
  };

  const handleSave = async () => {
    if (!currentTitle.trim()) {
      setError("Title cannot be empty.");
      return;
    }
    await sendUpdate({ title: currentTitle, description: currentDescription });
    setIsEditing(false);
  };

  const handleCancel = () => {
    setCurrentTitle(task.title);
    setCurrentDescription(task.description || "");
    setIsEditing(false);
    setError(null);
  };

  const handleDelete = async () => {
    if (!confirm(`Are you sure you want to delete "${task.title}"? This action cannot be undone.`)) {
      return;
    }

    setError(null);
    setIsLoading(true);
    setIsDeleting(true);

    const token = getToken();
    if (!token) {
      setError("You must be logged in to delete tasks.");
      setIsLoading(false);
      setIsDeleting(false);
      return;
    }

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/tasks/${task.id}`, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        const errorData = await response.json();
        setError(errorData.detail || "Failed to delete task.");
        setIsDeleting(false);
        return;
      }
      onTaskUpdated(); // Notify parent to re-fetch tasks
    } catch (err) {
      setError("An unexpected error occurred.");
      setIsDeleting(false);
    } finally {
      setIsLoading(false);
    }
  };

  const sendUpdate = async (updateData: { title?: string; description?: string; status?: string }) => {
    setError(null);
    setIsLoading(true);

    const token = getToken();
    if (!token) {
      setError("You must be logged in to update tasks.");
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/tasks/${task.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify(updateData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        setError(errorData.detail || "Failed to update task.");
        // Revert local state if update fails, depending on the error
        if (updateData.status) setCurrentStatus(task.status);
        if (updateData.title) setCurrentTitle(task.title);
        if (updateData.description) setCurrentDescription(task.description || "");
        return;
      }
      onTaskUpdated(); // Notify parent to re-fetch tasks
    } catch (err) {
      setError("An unexpected error occurred.");
      // Revert local state on network error
      if (updateData.status) setCurrentStatus(task.status);
      if (updateData.title) setCurrentTitle(task.title);
      if (updateData.description) setCurrentDescription(task.description || "");
    } finally {
      setIsLoading(false);
    }
  };

  // Format date
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (isDeleting) {
    return (
      <div className="overflow-hidden animate-fade-out">
        <div className="h-0 opacity-0"></div>
      </div>
    );
  }

  return (
    <div className={`bg-white rounded-xl shadow-lg border-l-4 p-5 mb-4 transition-all duration-300 hover:shadow-xl animate-fade-in ${
      currentStatus === 'completed' ? 'border-green-500' :
      currentStatus === 'in-progress' ? 'border-blue-500' :
      'border-yellow-500'
    }`}>
      <div className="flex flex-col md:flex-row justify-between items-start gap-4">
        <div className="flex-1 min-w-0">
          {isEditing ? (
            <>
              <input
                type="text"
                value={currentTitle}
                onChange={(e) => setCurrentTitle(e.target.value)}
                className="text-lg leading-6 font-semibold text-gray-900 w-full mb-2 p-2 border-2 border-blue-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                disabled={isLoading}
                placeholder="Task title..."
              />
              <textarea
                value={currentDescription}
                onChange={(e) => setCurrentDescription(e.target.value)}
                className="mt-2 w-full p-2 border-2 border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                rows={3}
                disabled={isLoading}
                placeholder="Task description..."
              />
            </>
          ) : (
            <>
              <h3 className="text-lg font-semibold text-gray-900 mb-2 break-words">{currentTitle}</h3>
              {currentDescription && (
                <p className="text-gray-600 mb-3 break-words">{currentDescription}</p>
              )}
            </>
          )}

          <div className="flex flex-wrap items-center gap-3 mt-3">
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getStatusStyles(currentStatus)}`}>
              {currentStatus === 'in-progress' ? 'In Progress' :
               currentStatus === 'completed' ? 'Completed' :
               'To Do'}
            </span>
            <span className="text-xs text-gray-500">
              Created: {formatDate(task.created_at)}
            </span>
          </div>

          {error && (
            <p className="text-red-500 text-sm italic mt-2 animate-pulse">
              {error}
            </p>
          )}
        </div>

        <div className="flex flex-col items-end space-y-3 w-full md:w-auto">
          <div className="flex space-x-2">
            {isEditing ? (
              <div className="flex space-x-2 animate-fade-in">
                <button
                  onClick={handleSave}
                  className="bg-green-500 hover:bg-green-600 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 flex items-center hover:scale-105"
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  ) : null}
                  {isLoading ? "Saving..." : "Save"}
                </button>
                <button
                  onClick={handleCancel}
                  className="bg-gray-500 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 hover:scale-105"
                  disabled={isLoading}
                >
                  Cancel
                </button>
              </div>
            ) : (
              <div className="flex space-x-2 animate-fade-in">
                <button
                  onClick={handleEdit}
                  className="bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 flex items-center hover:scale-105"
                >
                  <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                  </svg>
                  Edit
                </button>
                <button
                  onClick={handleDelete}
                  className="bg-red-500 hover:bg-red-600 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 flex items-center hover:scale-105"
                  disabled={isLoading}
                >
                  <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                  </svg>
                  Delete
                </button>
              </div>
            )}
          </div>

          <div className="w-full md:w-auto">
            <label htmlFor={`status-${task.id}`} className="sr-only">Task Status</label>
            <select
              id={`status-${task.id}`}
              name="status"
              value={currentStatus}
              onChange={handleStatusChange}
              disabled={isLoading || isEditing}
              className="block w-full py-2 px-3 border border-gray-300 bg-white rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200"
            >
              <option value="todo">To Do</option>
              <option value="in-progress">In Progress</option>
              <option value="completed">Completed</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}