import type { ButtonHTMLAttributes, ReactNode } from "react";

type Props = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "className"> & {
  children: ReactNode;
  /** A glyph that means something, such as the run triangle. Hidden from assistive technology. */
  icon?: ReactNode;
  variant?: "primary" | "secondary";
};

/** A plain command button: the label says exactly what happens. */
export function Button({ children, icon, variant = "primary", type, ...rest }: Props) {
  return (
    <button className={`btn btn-${variant}`} type={type ?? "button"} {...rest}>
      {icon ? (
        <span aria-hidden="true" className="btn-icon">
          {icon}
        </span>
      ) : null}
      <span>{children}</span>
    </button>
  );
}
