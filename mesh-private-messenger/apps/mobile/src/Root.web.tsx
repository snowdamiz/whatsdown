import { DesktopAppGate } from './DesktopAppGate';
import { createDesktopOwnerTransport } from './desktop-native-transport';
import { useEffect, useState } from 'react';
import { View } from 'react-native';
import App from './App';
import { DesktopUpdates } from './DesktopUpdates';
import { StartupScreen } from './StartupScreen';
import { palettes, type ColorScheme } from './appearance';
import { loadAppearance, saveAppearance } from './appearance-store.web';
import { SCROLLBAR_WIDTH } from './desktop-layout';
import { installScrollbars } from './scrollbars';
import { AppearanceProvider, WindowsChromeContext, useTheme, type Appearance } from './theme';
import { cubicBezier, duration, easing, radius } from './tokens';
import { isDevelopmentBuild } from './transport.web';
import { t } from './i18n';
import { LanguageProvider } from './language';

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

type Boot = { appearance: Appearance } | { error: string } | null;

function ProtectedDesktopRoot() {
  const [transport] = useState(createDesktopOwnerTransport);
  const [boot, setBoot] = useState<Boot>(null);
  const [session, setSession] = useState<{ generation: number; notice?: string }>({ generation: 0 });
  useEffect(() => installScrollbars(document), []);
  useEffect(() => {
    let active = true;
    void loadAppearance().then(appearance => { if (active) setBoot({ appearance }); },
      () => { if (active) setBoot({ error: t('Open Morse in the installed desktop app.') }); });
    return () => { active = false; };
  }, []);
  if (!boot || 'error' in boot) return <LanguageProvider>
    <View style={{ flex: 1 }}><StartupScreen error={boot?.error} /></View>
  </LanguageProvider>;
  return <LanguageProvider>
    <AppearanceProvider load={() => boot.appearance} save={saveAppearance}>
      <DocumentTheme />
      <WindowsChromeContext.Provider value={false}>
        <View style={{ flex: 1 }}>
          <DesktopAppGate key={session.generation} transport={transport}
            pending={<StartupScreen />} failed={<StartupScreen error={t('Couldn’t open Morse. Close the app and try again.')} />}>
            {services => <App services={services} environment={{ kind: 'desktop' }} notice={session.notice}
              updates={isDevelopmentBuild() ? undefined : <DesktopUpdates />}
              onAccountErased={notice => setSession(({ generation }) => ({ generation: generation + 1, notice }))} />}
          </DesktopAppGate>
        </View>
      </WindowsChromeContext.Provider>
    </AppearanceProvider>
  </LanguageProvider>;
}

export default function Root() {
  return <ProtectedDesktopRoot />;
}
