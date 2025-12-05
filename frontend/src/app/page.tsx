// frontend/src/app/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Navbar from "../../components/Navbar";
import TaskForm from "../../components/TaskForm";
import TaskList from "../../components/TaskList";
import TaskFilter from "../../components/TaskFilter";
import { getToken } from "../../lib/auth";

interface Task {
  id: string;
  title: string;
  description?: string;
  status: string;
  user_id: string;
  created_at: string;
}

export default function DashboardPage() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [sort, setSort] = useState<string>("created_at"); // New state for sort
  const router = useRouter();

  const fetchTasks = useCallback(async () => {
    setError(null);
    setLoading(true);
    const token = getToken();

    if (!token) {
      router.push("/login");
      return;
    }

    try {
      // Include filter and sort parameters in API call
      const response = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/tasks/?filter=${filter}&sort=${sort}`, {
        headers: {
          "Authorization": `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          router.push("/login");
          return; // Exit early if unauthorized
        }
        const errorData = await response.json();
        setError(errorData.detail || "Failed to fetch tasks.");
        setTasks([]);
        return;
      }

      const data = await response.json();
      setTasks(data);
    } catch (err) {
      setError("An unexpected error occurred while fetching tasks.");
      setTasks([]);
    } finally {
      setLoading(false);
    }
  }, [filter, sort, router]); // Dependencies on filter, sort, and router

  useEffect(() => {
    const token = getToken();
    if (!token) {
      router.push("/login");
      return;
    }
    fetchTasks();
  }, [fetchTasks, router]);

  const handleFilterChange = (newFilter: string) => {
    setFilter(newFilter);
  };

  const handleSortChange = (newSort: string) => { // New handler for sort change
    setSort(newSort);
  };

  // Check if user is authenticated before rendering content
  const token = getToken();
  if (!token) {
    return null; // Render nothing while redirecting
  }

  // Calculate task statistics
  const totalTasks = tasks.length;
  const completedTasks = tasks.filter(task => task.status === 'completed').length;
  const inProgressTasks = tasks.filter(task => task.status === 'in-progress').length;
  const todoTasks = tasks.filter(task => task.status === 'todo').length;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <Navbar />
      <main className="container mx-auto px-4 py-8">
        <div className="text-center mb-12 animate-fade-in-up">
          <h1 className="text-4xl md:text-5xl font-bold bg-gradient-to-r from-blue-600 to-indigo-700 bg-clip-text text-transparent mb-4">
            Your Task Dashboard
          </h1>
          <p className="text-gray-600 text-lg max-w-2xl mx-auto">
            Manage your tasks efficiently and stay organized with our intuitive todo application
          </p>
        </div>

        {/* Stats Section */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8 animate-fade-in-up">
          <div className="bg-white rounded-xl p-6 shadow-lg border border-blue-100 hover:shadow-xl transition-shadow duration-300">
            <h3 className="text-2xl font-bold text-blue-600">{totalTasks}</h3>
            <p className="text-gray-600">Total Tasks</p>
          </div>
          <div className="bg-white rounded-xl p-6 shadow-lg border border-green-100 hover:shadow-xl transition-shadow duration-300">
            <h3 className="text-2xl font-bold text-green-600">{completedTasks}</h3>
            <p className="text-gray-600">Completed</p>
          </div>
          <div className="bg-white rounded-xl p-6 shadow-lg border border-yellow-100 hover:shadow-xl transition-shadow duration-300">
            <h3 className="text-2xl font-bold text-yellow-600">{todoTasks}</h3>
            <p className="text-gray-600">To Do</p>
          </div>
          <div className="bg-white rounded-xl p-6 shadow-lg border border-blue-200 hover:shadow-xl transition-shadow duration-300">
            <h3 className="text-2xl font-bold text-blue-500">{inProgressTasks}</h3>
            <p className="text-gray-600">In Progress</p>
          </div>
        </div>

        {error && (
          <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-6 rounded-lg animate-pulse">
            <p className="text-red-700">{error}</p>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-1 animate-fade-in-left">
            <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-shadow duration-300">
              <h2 className="text-2xl font-bold text-gray-800 mb-4 flex items-center">
                <svg className="w-6 h-6 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                </svg>
                Create New Task
              </h2>
              <TaskForm onTaskCreated={fetchTasks} />
            </div>
          </div>

          <div className="lg:col-span-2 animate-fade-in-right">
            <div className="bg-white rounded-2xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-shadow duration-300">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-800 mb-4 md:mb-0">Your Tasks</h2>
                <TaskFilter
                  onFilterChange={handleFilterChange}
                  currentFilter={filter}
                  onSortChange={handleSortChange}
                  currentSort={sort}
                />
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mb-4"></div>
                  <p className="text-gray-600">Loading your tasks...</p>
                </div>
              ) : tasks.length === 0 ? (
                <div className="text-center py-12">
                  <div className="mb-4">
                    <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                  </div>
                  <h3 className="mt-2 text-lg font-medium text-gray-900">No tasks yet</h3>
                  <p className="mt-1 text-gray-500">Get started by creating your first task.</p>
                </div>
              ) : (
                <TaskList tasks={tasks} onTaskUpdated={fetchTasks} />
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
