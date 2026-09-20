export { fetch } from 'expo/fetch';
export const isDevelopmentBuild = (): boolean => typeof __DEV__ !== 'undefined' && __DEV__;

export async function openMailboxSocket(url: string, authorization: string): Promise<WebSocket> {
  // React Native supports upgrade headers; the DOM constructor type does not.
  const NativeWebSocket = WebSocket as new (
    url: string, protocols: string[], options: { headers: Record<string, string> },
  ) => WebSocket;
  return new NativeWebSocket(url, [], { headers: { Authorization: authorization } });
}
