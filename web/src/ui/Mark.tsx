export function Mark() {
  return (
    <svg aria-hidden="true" className="h-11 w-11 text-[var(--ink)]" viewBox="0 0 48 48">
      <rect
        fill="none"
        height="32"
        rx="10"
        stroke="currentColor"
        strokeWidth="2"
        width="18"
        x="15"
        y="8"
      />
      <path d="M19 12h10" stroke="currentColor" strokeWidth="2" />
      <path
        d="M24 18v7M24 22l-6 7M24 22l6 7"
        fill="none"
        stroke="var(--violet)"
        strokeLinecap="round"
        strokeWidth="2"
      />
    </svg>
  );
}
