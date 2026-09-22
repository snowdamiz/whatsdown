import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useEffect, useState } from 'react';
import { View } from 'react-native';
import App from './App';
import { StartupScreen } from './StartupScreen';
import { palettes, type ColorScheme } from './appearance';
import { loadAppearance, saveAppearance } from './appearance-store.web';
import { SCROLLBAR_WIDTH } from './desktop-layout';
import { installScrollbars } from './scrollbars';
import { setDatabasePath } from './storage.web';
import { AppearanceProvider, WindowsChromeContext, useTheme, type Appearance } from './theme';
import { control, cubicBezier, duration, easing, radius, space } from './tokens';
import { isDevelopmentBuild } from './transport.web';
import { chrome, IconButton } from './ui';

const windowsHost = /Windows/.test(navigator.userAgent);

// What the web view needs to behave like a window rather than a page: the
// arrow cursor over controls, no stray text selection, fields that show
// focus through their own styling rather than the browser's ring, thin
// overlay scrollbars over the app's own surfaces, and glass controls that
// respond under the pointer (see glass.web.tsx).
//
// The document's own colours follow the scheme in effect. Until the app has
// set `data-theme`, that is whatever the window reports, which the desktop
// shell has already set from the saved choice. Glass brightens under the
// pointer over dark content and darkens over light, as a lit pane would.
const documentVars = (scheme: ColorScheme, hover: number, active: number) => `
    color-scheme: ${scheme};
    --canvas: ${palettes[scheme].canvas};
    --scrollbar-thumb: ${palettes[scheme].scrollThumb};
    --glass-hover: brightness(${hover});
    --glass-active: brightness(${active});
`;
const lightDocument = documentVars('light', 0.96, 0.92);
const desktopStyles = `
  @property --scrollbar-color {
    syntax: '<color>';
    inherits: true;
    initial-value: transparent;
  }
  * { --scrollbar-color: transparent; }
  html { ${documentVars('dark', 1.22, 1.4)} }
  @media (prefers-color-scheme: light) {
    html:not([data-theme]) { ${lightDocument} }
  }
  html[data-theme="light"] { ${lightDocument} }
  html, body, #root { background: var(--canvas); }
  body {
    cursor: default;
    -webkit-user-select: none;
    user-select: none;
    overscroll-behavior: none;
    -webkit-font-smoothing: antialiased;
  }
  input, textarea { -webkit-user-select: text; user-select: text; }
  input:focus, textarea:focus, input:focus-visible, textarea:focus-visible { outline: none; }
  [role="button"], [role="tab"] { cursor: default !important; }
  [data-glass="interactive"] { transition: filter ${duration.quick}ms ${cubicBezier(easing.out)}; }
  [data-glass="interactive"]:hover { filter: var(--glass-hover); }
  [data-glass="interactive"]:active { filter: var(--glass-active); }
  @media (prefers-reduced-motion: no-preference) {
    [role="tablist"] > [role="tab"], [data-testid="segment-thumb"], [data-testid="segment-dot"] {
      transition-property: width, margin-right, transform, opacity;
      transition-duration: ${duration.settle}ms;
      transition-timing-function: ${cubicBezier(easing.out)};
    }
  }
  ::-webkit-scrollbar { width: ${SCROLLBAR_WIDTH}px; height: ${SCROLLBAR_WIDTH}px; }
  ::-webkit-scrollbar-track, ::-webkit-scrollbar-corner { background: transparent; }
  ::-webkit-scrollbar-thumb {
    background: var(--scrollbar-color);
    border: 2px solid transparent;
    border-radius: ${radius.xs}px;
    background-clip: padding-box;
  }
`;

const style = document.createElement('style');
style.textContent = desktopStyles;
document.head.appendChild(style);

// Hands the resolved scheme to the document so its own chrome (background,
// scrollbars, form controls) matches the app's.
function DocumentTheme() {
  const { scheme } = useTheme();
  useEffect(() => {
    document.documentElement.dataset.theme = scheme;
  }, [scheme]);
  return null;
}

function WindowsWindowControls() {
  const { colors } = useTheme();
  const [maximized, setMaximized] = useState(false);
  const [error, setError] = useState('');
  const reportError = () => setError('Couldn’t update the window. Try again.');
  useEffect(() => {
    const update = () => { void getCurrentWindow().isMaximized().then(setMaximized).catch(reportError); };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);
  const act = async (action: 'minimize' | 'toggleMaximize' | 'close') => {
    setError('');
    try {
      const appWindow = getCurrentWindow();
      await appWindow[action]();
      if (action === 'toggleMaximize') setMaximized(await appWindow.isMaximized());
    } catch { reportError(); }
  };
  return <>
    <div role="group" aria-label="Window controls"
      style={{ position: 'absolute', top: (chrome.header - control.xs) / 2, right: space[4], zIndex: 10, display: 'flex', gap: space[1] }}>
      <IconButton name="minimize" label="Minimize window" variant="tonal" size={control.xs} onPress={() => void act('minimize')} />
      <IconButton name={maximized ? 'restore' : 'maximize'} label={maximized ? 'Restore window' : 'Maximize window'}
        variant="tonal" size={control.xs} onPress={() => void act('toggleMaximize')} />
      <IconButton name="close" label="Close window" variant="tonal" size={control.xs} onPress={() => void act('close')} />
    </div>
    {error ? <div role="alert" style={{ position: 'absolute', top: chrome.header, right: 8, zIndex: 10,
      color: colors.danger, background: colors.canvas, padding: 8 }}>{error}</div> : null}
  </>;
}

type Boot = { appearance: Appearance } | { error: string } | null;

export default function Root() {
  const [boot, setBoot] = useState<Boot>(null);
  const [windowsPreview, setWindowsPreview] = useState(false);
  // An erased account restarts the app, so nothing of it stays in memory.
  const [session, setSession] = useState<{ generation: number; notice?: string }>({ generation: 0 });
  const preview = isDevelopmentBuild() && windowsPreview;
  const windowsUI = windowsHost || preview;
  const toggleWindowsPreview = async (enabled: boolean) => {
    if (!isDevelopmentBuild()) return;
    const appWindow = getCurrentWindow();
    await appWindow.setDecorations(!(windowsHost || enabled));
    // Restoring decorations clears macOS's full-size content-view style.
    if (!enabled && /Mac/.test(navigator.userAgent)) await appWindow.setTitleBarStyle('overlay');
    setWindowsPreview(enabled);
  };
  useEffect(() => installScrollbars(document), []);
  useEffect(() => {
    Promise.all([invoke<string>('database_path'), loadAppearance()])
      .then(([path, appearance]) => {
        setDatabasePath(path);
        setBoot({ appearance });
      })
      .catch(() => setBoot({ error: 'Open Morse in the installed desktop app.' }));
  }, []);
  if (boot && 'appearance' in boot) {
    return (
      <AppearanceProvider load={() => boot.appearance} save={saveAppearance}>
        <DocumentTheme />
        <WindowsChromeContext.Provider value={windowsUI}>
          <View style={{ flex: 1 }}>
            <App key={session.generation} notice={session.notice} windowsPreview={preview}
              onWindowsPreviewChange={toggleWindowsPreview}
              onAccountErased={(notice) => setSession(({ generation }) => ({ generation: generation + 1, notice }))} />
            {windowsUI ? <WindowsWindowControls /> : null}
          </View>
        </WindowsChromeContext.Provider>
      </AppearanceProvider>
    );
  }
  return <View style={{ flex: 1 }}>
    <StartupScreen error={boot?.error} />
    {windowsUI ? <WindowsWindowControls /> : null}
  </View>;
}
