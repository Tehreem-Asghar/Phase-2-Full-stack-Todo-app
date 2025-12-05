// frontend/components/TaskFilter.tsx
"use client";

interface TaskFilterProps {
  onFilterChange: (filter: string) => void;
  currentFilter: string;
  onSortChange: (sort: string) => void; // New prop for sort change
  currentSort: string; // New prop for current sort
}

export default function TaskFilter({ onFilterChange, currentFilter, onSortChange, currentSort }: TaskFilterProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-4">
      <div className="flex flex-wrap gap-2">
        {(['all', 'todo', 'in-progress', 'completed']).map((filter) => (
          <button
            key={filter}
            onClick={() => onFilterChange(filter)}
            className={`px-4 py-2 rounded-full text-sm font-medium transition-all duration-200 transform hover:scale-105 ${
              currentFilter === filter
                ? 'bg-blue-500 text-white shadow-md'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            {filter === 'in-progress' ? 'In Progress' :
             filter === 'all' ? 'All Tasks' :
             filter.charAt(0).toUpperCase() + filter.slice(1)}
          </button>
        ))}
      </div>

      <div className="flex items-center">
        <label htmlFor="task-sort" className="text-sm font-medium text-gray-700 mr-2">
          Sort:
        </label>
        <select
          id="task-sort"
          name="task-sort"
          className="py-2 px-3 border border-gray-300 bg-white rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200"
          value={currentSort}
          onChange={(e) => onSortChange(e.target.value)}
        >
          <option value="created_at">Date Created</option>
          <option value="title">Title</option>
        </select>
      </div>
    </div>
  );
}