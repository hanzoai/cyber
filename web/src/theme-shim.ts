import { useScheme, write } from '@hanzo/appearance';

export function useThemeSetting() {
  const resolved = useScheme() === 'light' ? 'light' : 'dark';
  return {
    current: resolved,
    resolvedTheme: resolved,
    set: (theme: string) => {
      if (theme === 'light' || theme === 'dark' || theme === 'system') {
        write({ theme });
      }
    },
    toggle: () => {
      write({ theme: resolved === 'dark' ? 'light' : 'dark' });
    },
  };
}

export function useRootTheme() {
  const { resolvedTheme, set } = useThemeSetting();
  return [resolvedTheme, set] as const;
}

export function NextThemeProvider({ children }: { children?: unknown }) {
  return children ?? null;
}
