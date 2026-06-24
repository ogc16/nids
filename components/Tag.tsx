'use client';

export function Tag({ variant, children }: { variant?: string; children: React.ReactNode }) {
  return <span className={`tag ${variant || ''}`.trim()}>{children}</span>;
}
