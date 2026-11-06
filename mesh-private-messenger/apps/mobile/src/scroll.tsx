// The app's scrolling containers. A phone scrolls without indicators, as its
// own apps do; the desktop window keeps the scrollbars Root.web.tsx styles.
// A screen can still ask for an indicator by passing the prop itself.

import type { Ref } from "react";
import {
  FlatList as NativeFlatList,
  ScrollView as NativeScrollView,
  type FlatListProps,
  type ScrollViewInstance,
  type ScrollViewProps,
} from "react-native";

import { isDesktop } from "./theme";

export const scrollIndicators = {
  showsVerticalScrollIndicator: isDesktop,
  showsHorizontalScrollIndicator: isDesktop,
};

export function ScrollView(props: ScrollViewProps & { ref?: Ref<ScrollViewInstance> }) {
  return <NativeScrollView {...scrollIndicators} {...props} />;
}

export function FlatList<ItemT>(props: FlatListProps<ItemT> & { ref?: Ref<NativeFlatList<ItemT>> }) {
  return <NativeFlatList {...scrollIndicators} {...props} />;
}
