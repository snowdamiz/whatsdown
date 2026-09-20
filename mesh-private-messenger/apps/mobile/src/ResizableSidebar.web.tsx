import { useId, useRef, useState, type ReactNode } from 'react';
import { View, useWindowDimensions, type StyleProp, type ViewStyle } from 'react-native';
import { SIDEBAR_INSET, SIDEBAR_MAX_WIDTH, SIDEBAR_MIN_WIDTH, sidebarWidth } from './desktop-layout';

export function ResizableSidebar({ children, style }: { children: ReactNode; style: StyleProp<ViewStyle> }) {
  const id = useId();
  const { width: windowWidth } = useWindowDimensions();
  const [preferredWidth, setPreferredWidth] = useState<number>();
  const dragOffset = useRef<number | null>(null);
  const width = sidebarWidth(windowWidth, preferredWidth);
  const maximum = sidebarWidth(windowWidth, SIDEBAR_MAX_WIDTH);

  return (
    <View style={{ width, flexShrink: 0, margin: SIDEBAR_INSET }}>
      <View nativeID={id} style={[style, { flex: 1 }]}>{children}</View>
      <div
        role="separator"
        aria-label="Resize sidebar"
        aria-orientation="vertical"
        aria-controls={id}
        aria-valuemin={SIDEBAR_MIN_WIDTH}
        aria-valuemax={maximum}
        aria-valuenow={width}
        tabIndex={0}
        style={{ position: 'absolute', top: 0, bottom: 0, right: -8, width: 8, cursor: 'col-resize', touchAction: 'none' }}
        onPointerDown={(event) => {
          if (event.button !== 0 || !event.isPrimary) return;
          event.preventDefault();
          dragOffset.current = event.clientX - width;
          event.currentTarget.setPointerCapture(event.pointerId);
        }}
        onPointerMove={(event) => {
          if (dragOffset.current === null || !event.currentTarget.hasPointerCapture(event.pointerId)) return;
          setPreferredWidth(sidebarWidth(windowWidth, event.clientX - dragOffset.current));
        }}
        onPointerUp={(event) => {
          event.currentTarget.releasePointerCapture(event.pointerId);
          dragOffset.current = null;
        }}
        onLostPointerCapture={() => { dragOffset.current = null; }}
        onKeyDown={(event) => {
          let next: number;
          switch (event.key) {
            case 'ArrowLeft': next = width - 10; break;
            case 'ArrowRight': next = width + 10; break;
            case 'Home': next = SIDEBAR_MIN_WIDTH; break;
            case 'End': next = maximum; break;
            default: return;
          }
          event.preventDefault();
          setPreferredWidth(sidebarWidth(windowWidth, next));
        }}
      />
    </View>
  );
}
