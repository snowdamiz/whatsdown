// The desktop has a hardware keyboard and nothing to make room for, so the
// phone's keyboard-tracking views are plain views here (see keyboard.tsx).

import type { ReactNode } from "react";
import { ScrollView, View, type ScrollViewProps, type ViewProps } from "react-native";

export function KeyboardProvider({ children }: { children: ReactNode }) {
  return children;
}

export function KeyboardAvoidingView({
  behavior: _behavior,
  automaticOffset: _automaticOffset,
  keyboardVerticalOffset: _offset,
  enabled: _enabled,
  ...props
}: ViewProps & {
  behavior?: string;
  automaticOffset?: boolean;
  keyboardVerticalOffset?: number;
  enabled?: boolean;
}) {
  return <View {...props} />;
}

export function KeyboardAwareScrollView({
  bottomOffset: _bottomOffset,
  ...props
}: ScrollViewProps & { bottomOffset?: number }) {
  return <ScrollView {...props} />;
}
