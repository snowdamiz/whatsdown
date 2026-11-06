import { isDesktopOwner } from './desktop-lock-protocol.ts';

// Native installs this grant into the loaded WK document. Capturing it once
// keeps a delayed React bind tied to its original document across navigation.
export function captureDesktopDocument(): Promise<string> {
  const read = () => Reflect.get(window, '__MORSE_DOCUMENT__');
  const initial: unknown = read();
  if (isDesktopOwner(initial)) return Promise.resolve(initial);
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timeout); window.removeEventListener('morse-document-ready', ready); };
    const ready = () => {
      const value: unknown = read();
      cleanup();
      if (isDesktopOwner(value)) resolve(value); else reject(Error('desktop_document_unavailable'));
    };
    const timeout = setTimeout(() => { cleanup(); reject(Error('desktop_document_unavailable')); }, 10_000);
    window.addEventListener('morse-document-ready', ready);
    if (read() !== undefined) ready();
  });
}
