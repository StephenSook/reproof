"use client";

import { useRef, type ButtonHTMLAttributes, type ReactNode, type RefObject } from "react";
import { wobble } from "@/ui/motion/motion";

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

function Inner({ children, icon, glyph }: { children: ReactNode; icon: ReactNode; glyph: RefObject<HTMLSpanElement | null> }) {
  return (
    <>
      <span className="squash-label">{children}</span>
      <span aria-hidden="true" className="squash-icon">
        <span className="squash-glyph" ref={glyph}>
          {icon}
        </span>
      </span>
    </>
  );
}

/**
 * The squash button: the pill squashes and springs back on hover (CSS), the label and icon tilt apart, and
 * the icon wobbles back on an elastic when the pointer or keyboard focus arrives (GSAP).
 */
export function SquashButton(props: LinkProps | ButtonProps) {
  const glyph = useRef<HTMLSpanElement>(null);
  const icon = props.icon ?? "→";
  const bounce = () => wobble(glyph.current);
  if ("href" in props && typeof props.href === "string") {
    return (
      <a className={classes(props)} href={props.href} onFocus={bounce} onPointerEnter={bounce}>
        <Inner glyph={glyph} icon={icon}>
          {props.children}
        </Inner>
      </a>
    );
  }
  const {
    children,
    icon: _icon,
    variant: _variant,
    onInk: _onInk,
    className: _className,
    type,
    onFocus,
    onPointerEnter,
    ...rest
  } = props as ButtonProps;
  void _icon;
  void _variant;
  void _onInk;
  void _className;
  return (
    <button
      className={classes(props)}
      onFocus={(event) => {
        bounce();
        onFocus?.(event);
      }}
      onPointerEnter={(event) => {
        if (!event.currentTarget.disabled) bounce();
        onPointerEnter?.(event);
      }}
      type={type ?? "button"}
      {...rest}
    >
      <Inner glyph={glyph} icon={icon}>
        {children}
      </Inner>
    </button>
  );
}
