// Sidebar.jsx — Left navigation rail
import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  {
    to: "/", label: "Dashboard",
    icon: (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z"/>
      </svg>
    )
  },
  {
    to: "/threats", label: "Threat Feed",
    icon: (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
      </svg>
    )
  },
  {
    to: "/alerts", label: "Alerts",
    icon: (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0"/>
      </svg>
    )
  },
  {
    to: "/keywords", label: "Keywords",
    icon: (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z"/>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 6h.008v.008H6V6z"/>
      </svg>
    )
  },
];

export default function Sidebar({ user, onLogout }) {
  return (
    <aside className="w-56 flex flex-col bg-gray-900 border-r border-gray-800 py-5 px-3 shrink-0">
      {/* Brand */}
      <div className="flex items-center gap-2 px-2 mb-8">
        <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center shrink-0">
          <svg width="14" height="14" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
            <circle cx="11" cy="11" r="8"/><path strokeLinecap="round" d="m21 21-4.35-4.35"/>
          </svg>
        </div>
        <span className="text-sm font-medium text-gray-200 leading-tight">Dark Intel</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5">
        {NAV_ITEMS.map(({ to, label, icon }) => (
          <NavLink key={to} to={to} end={to === "/"}
                   className={({ isActive }) =>
                     `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors
                      ${isActive
                        ? "bg-indigo-600/20 text-indigo-300"
                        : "text-gray-500 hover:text-gray-200 hover:bg-gray-800"}`
                   }>
            {icon}
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User footer */}
      <div className="border-t border-gray-800 pt-4 mt-4 px-2">
        <p className="text-xs text-gray-400 font-medium truncate">{user?.username}</p>
        <p className="text-xs text-gray-600 truncate">{user?.email}</p>
        <button onClick={onLogout}
                className="mt-3 text-xs text-gray-600 hover:text-gray-400 transition-colors">
          Sign out
        </button>
      </div>
    </aside>
  );
}
