'use client';

import { useEffect } from 'react';

export function Toast({ message, type = 'success', onClose }: {
  message: string;
  type?: 'success' | 'error' | 'info';
  onClose?: () => void;
}) {
  useEffect(() => {
    if (onClose) {
      const timer = setTimeout(onClose, 3000);
      return () => clearTimeout(timer);
    }
  }, [onClose]);

  return (
    <div className={`toast toast-${type}`} style={{ position: 'static', marginBottom: 16 }}>
      {message}
    </div>
  );
}
