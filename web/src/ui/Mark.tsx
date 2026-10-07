/** Reproof's mark: a release tag joined to a fix commit inside a seal, the same picture as the ancestry ribbon. */
export function Mark({ size = 40, className = "" }: { size?: number; className?: string }) {
  return (
    <svg aria-hidden="true" className={className} height={size} viewBox="0 0 48 48" width={size}>
      <rect fill="var(--ink)" height="38" rx="10" width="38" x="7" y="7" />
      <rect fill="var(--card)" height="38" rx="10" stroke="var(--ink)" strokeWidth="3" width="38" x="3" y="3" />
      <path d="M11.5 29.5h16" stroke="var(--ink)" strokeLinecap="round" strokeWidth="3" />
      <path
        d="M24 21.5h9.5a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H24l-5-8z"
        fill="var(--amber)"
        stroke="var(--ink)"
        strokeLinejoin="round"
        strokeWidth="2.5"
      />
      <circle cx="30" cy="29.5" fill="var(--ink)" r="1.8" />
      <circle cx="11.5" cy="29.5" fill="var(--proof)" r="5" stroke="var(--ink)" strokeWidth="2.5" />
      <path
        d="M14 14.5l3 3 5.5-6"
        fill="none"
        stroke="var(--proof)"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="3"
      />
    </svg>
  );
}
