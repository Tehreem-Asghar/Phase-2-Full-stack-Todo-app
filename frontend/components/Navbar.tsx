// frontend/components/Navbar.tsx
// "use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { removeToken } from "../lib/auth"; // Assuming auth.ts is in frontend/lib/

export default function Navbar() {
  const router = useRouter();

  const handleLogout = () => {
    removeToken();
    // Invalidate the token cookie on the client side
    document.cookie = "access_token=; Max-Age=-99999999;";
    router.push("/login");
  };

  return (
    <nav className="bg-gradient-to-r from-blue-600 to-indigo-700 shadow-lg py-4">
      <div className="container mx-auto flex justify-between items-center px-4">
        <div className="flex items-center animate-fade-in-left">
          <Link href="/" className="text-white text-2xl font-bold flex items-center">
            <svg className="w-8 h-8 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
            </svg>
            TaskMaster
          </Link>
        </div>

        <div className="animate-fade-in-right">
          <button
            onClick={handleLogout}
            className="bg-white bg-opacity-20 hover:bg-opacity-30 font-bold text-blue-600 font-medium py-2 px-4 rounded-lg transition-all duration-200 flex items-center hover:scale-105"
          >
            <svg className="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
            </svg>
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
}
