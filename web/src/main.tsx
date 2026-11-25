import '@hanzo/design/tokens/fonts.css';
import '@hanzo/design/tokens/colors.css';
import '@hanzo/design/tokens/typography.css';
import '@hanzo/design/tokens/spacing.css';
import '@hanzo/design/tokens/radius.css';
import '@hanzo/design/tokens/elevation.css';
import '@hanzo/design/tokens/motion.css';
import '@hanzo/design/tokens/z.css';
import '@hanzo/design/tokens/base.css';
import '@hanzo/ui/theme.css';
import '@hanzo/ui/glass.css';
import '@hanzo/font/css';
import '@hanzo/ui/styles/motion.css';
import '@hanzo/ui/styles/document.css';
import './app.css';

import { StrictMode, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { useScheme } from '@hanzo/appearance';
import { GuiProvider, Theme } from '@hanzo/gui';
import config from '../gui.config.ts';
import { App } from './App.tsx';

function Root() {
  const scheme = useScheme() === 'light' ? 'light' : 'dark';

  useEffect(() => {
    document.documentElement.dataset.theme = scheme;
    document.documentElement.classList.remove('dark', 'light', 't_dark', 't_light');
    document.documentElement.classList.add(scheme, `t_${scheme}`);
  }, [scheme]);

  return (
    <GuiProvider config={config} defaultTheme={scheme}>
      <Theme name={scheme}>
        <App />
      </Theme>
    </GuiProvider>
  );
}

const root = document.querySelector('#root');
if (!root) throw new Error('root element missing');

createRoot(root as HTMLElement).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
