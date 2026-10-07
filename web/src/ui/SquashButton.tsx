import type { ButtonHTMLAttributes, ReactNode } from "react";

type Common = {
  children: ReactNode;
  icon?: ReactNode;
  variant?: "primary" | "secondary";
  onInk?: boolean;
  className?: string;
};

type LinkProps = Common & { href: string };
type ButtonProps = Common & Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "className"> & { href?: never };

function classes({ variant = "primary", onInk = false, className = "" }: Common): string {
  return ["squash", `squash-${variant}`, onInk ? "squash-on-ink" : "", className].filter(Boolean).join(" ");
}

function Inner({ children, icon }: { children: ReactNode; icon: ReactNode }) {
  return (
    <>
      <span className="squash-label">{children}</span>
      <span aria-hidden="true" className="squash-icon">
        {icon}
      </span>
    </>
  );
}

/** The squash button: the pill squashes and springs back on hover, and the label and icon tilt apart. */
export function SquashButton(props: LinkProps | ButtonProps) {
  const icon = props.icon ?? "→";
  if ("href" in props && typeof props.href === "string") {
    return (
      <a className={classes(props)} href={props.href}>
        <Inner icon={icon}>{props.children}</Inner>
      </a>
    );
  }
  const { children, icon: _icon, variant: _variant, onInk: _onInk, className: _className, type, ...rest } =
    props as ButtonProps;
  void _icon;
  void _variant;
  void _onInk;
  void _className;
  return (
    <button className={classes(props)} type={type ?? "button"} {...rest}>
      <Inner icon={icon}>{children}</Inner>
    </button>
  );
}
