// A sheet on iPhone is the system's own: SwiftUI presents it sized to what it
// holds, with its grabber, its swipe to dismiss, a backdrop that fades in and
// out as the sheet moves, and Liquid Glass where iOS draws it. sheet.tsx is
// what other phones get.

import { BottomSheet } from "@expo/ui/community/bottom-sheet";
import { useEffect, type ReactNode } from "react";
import { StyleSheet, View, useWindowDimensions, type StyleProp, type ViewStyle } from "react-native";

import { space } from "./theme";

export type SheetProps = {
  visible: boolean;
  label: string;
  onClose: () => void;
  // Called once the sheet is on screen, for a field that focuses then.
  onShown?: () => void;
  children: ReactNode;
  style?: StyleProp<ViewStyle>;
};

export function Sheet({ visible, label, onClose, onShown, children, style }: SheetProps) {
  const { height } = useWindowDimensions();
  return (
    // Fitted to its content: the system measures what is inside and sizes the
    // sheet to it, up to most of the screen, where a long list scrolls.
    <BottomSheet index={visible ? 0 : -1} onClose={onClose} enableDynamicSizing enablePanDownToClose>
      <View
        role="dialog"
        accessibilityViewIsModal
        accessibilityLabel={label}
        style={[styles.content, { maxHeight: height * 0.88 }, style]}
      >
        {visible ? <Shown onShown={onShown} /> : null}
        {children}
      </View>
    </BottomSheet>
  );
}

// Mounts as the sheet is presented.
function Shown({ onShown }: { onShown?: () => void }) {
  useEffect(() => onShown?.(), []);
  return null;
}

const styles = StyleSheet.create({
  // The system's grabber sits above; the sheet keeps the home indicator's
  // inset below on its own.
  content: { paddingTop: space[3], paddingBottom: space[4] },
});
