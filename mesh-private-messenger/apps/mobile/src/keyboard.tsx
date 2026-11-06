// How screens make room for the software keyboard on a phone.
//
// React Native's own avoiding view hears of an Android keyboard only once it
// has finished opening, so the pane jumped after it instead of rising with
// it. These track the keyboard's own animation, frame by frame, on both
// platforms. The desktop has no software keyboard (keyboard.web.tsx).

import {
  KeyboardAwareScrollView as NativeKeyboardAwareScrollView,
  type KeyboardAwareScrollViewProps,
} from "react-native-keyboard-controller";

import { scrollIndicators } from "./scroll";

export { KeyboardAvoidingView, KeyboardProvider } from "react-native-keyboard-controller";

// A form that scrolls its focused field into view, without indicators as
// the app's other scrolling screens (see scroll.tsx).
export function KeyboardAwareScrollView(props: KeyboardAwareScrollViewProps) {
  return <NativeKeyboardAwareScrollView {...scrollIndicators} {...props} />;
}
