import {
  BarcodeScanningResult,
  CameraView,
  useCameraPermissions,
} from "expo-camera";
import { StatusBar } from "expo-status-bar";
import { useEffect, useRef, useState } from "react";
import { encodeReaction } from "./reactions";
import { encodeReply } from "./replies";
import { encodeReceipt, messageStatus, receiptDue, type ReceiptMarks } from "./receipts";
import {
  ActivityIndicator,
  Alert,
  AppState,
  FlatList,
  KeyboardAvoidingView,
  Keyboard,
  Modal,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  View,
  useWindowDimensions,
  type TextInput,
} from "react-native";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";

import {
  group_send_export,
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  device_link_sas_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  update_conversation_export,
} from "../modules/mesh-messenger";
import {
  attachmentPreviewUri,
  listenForIncomingFiles,
  pickAttachmentFiles,
  releasePreviewUri,
  saveAttachmentFile,
} from "./attachment-io";
import {
  attachmentPreviewText,
  attachmentSelectionError,
  composerScope,
  describeAttachmentState,
  formatBytes,
  isImageAttachment,
  shouldAutoDownload,
  type AttachmentState,
} from "./attachments";
import { pickAvatar } from "./avatar-picker";
import { encodePresentation, identityName, type Presentation } from "./presentation";
import { loadPresentation, savePresentation, saveNickname } from "./presentation-store";
import { buildChatRows } from "./chat-rows";
import type { DevPreview } from "./dev-preview";
import {
  TOOLBAR_HEIGHT,
  desktopShortcut,
  sidebarSection,
  trafficLightInset,
  usesSplitLayout,
  type SidebarList,
} from "./desktop-layout";
import {
  accountRequest,
  AttachmentSummary,
  Conversation,
  decodeUtf8,
  DeviceSetSummary,
  GroupDetails,
  GroupHistoryMessage,
  GroupInvitation,
  GroupSummary,
  HistoryMessage,
  hex,
  linkRequestFromQr,
  parseConversations,
  parseHistory,
  parseProfileSummary,
  payloadFromQr,
  payloadQrValue,
  peerRequest,
  policyRequest,
  profileFromQr,
  profileQrValue,
  utf8,
  vectors,
} from "./codec";
import { formatInboxTime, friendlyError } from "./format";
import { Glass } from "./glass";
import { describeMember, describeMembers, summarizeMembers, type Person } from "./group-members";
import { historyRefreshDelay } from "./expiry";
import { createMailboxSync } from "./mailbox-sync";
import { setActiveNotificationScope, synchronizeWithNotifications } from "./message-notifications";
import { createKeyedSerialQueue } from "./single-flight";
import {
  parentScreen,
  scannerOrigin,
  transitionDirection,
  type Direction,
  type ScanMode,
  type Screen,
  type ScreenKey,
} from "./navigation";
import {
  addGroupMember,
  acceptGroupInvitation,
  declineGroupInvitation,
  inviteToGroup,
  listGroupInvitations,
  authorizeDeviceLink,
  drainOutbox,
  createGroup,
  connectMailboxStream,
  downloadAttachment,
  getGroupKeyPackage,
  GROUP_KEY_PACKAGE_LENGTH,
  inspectGroup,
  listGroups,
  loadAccountDevices,
  loadGroupHistory,
  onUndeliverable,
  registerDirectory,
  removeGroupMember,
  revokeDevice,
  sendFanout,
  sendGroupMessage,
  sendWithAttachments,
  type OutgoingAttachment,
} from "./network";
import {
  disablePushBinding,
  enablePushBinding,
  getPushStatus,
  listenForGenericWakeups,
  listenForNotificationOpens,
  listenForPushRegistrationChanges,
  recoverPushBinding,
  type PushStatus,
} from "./push";
import { createQrCollector } from "./qr";
import { databasePath } from "./storage";
import { receivedMessageKeys, unreadCount, type ReadState } from "./read-state";
import { loadNotificationPreview, loadReadReceipts, loadReadState, loadReceiptMarks, saveNotificationPreview, saveReadReceipts, saveReadState } from "./read-state-store";
import type { NotificationPreview } from "./notification-policy";
import { describeSafety } from "./safety";
import { StartupScreen } from "./StartupScreen";
import { ResizableSidebar } from "./ResizableSidebar";
import { isDevelopmentBuild } from "./transport";
import {
  isDesktop,
  themed,
  useAppFonts,
  useAppearance,
  useTheme,
  type Appearance,
} from "./theme";
import {
  AccountBar,
  Actions,
  Avatar,
  Badge,
  Button,
  Card,
  ChatHeader,
  CodeBlock,
  CodeDisplay,
  AppGlyph,
  Composer,
  composerClearance,
  ConversationRow,
  DayDivider,
  Dialog,
  DragStrip,
  EmptyState,
  FeatureRow,
  Field,
  Glow,
  GroupRow,
  Header,
  Hero,
  Icon,
  IconButton,
  LargeHeader,
  ListSeparator,
  MessageBubble,
  Notice,
  Page,
  PhotoButton,
  QrCard,
  QrLayout,
  RecipientField,
  RequestGroup,
  RequestRow,
  Reticle,
  Reveal,
  Row,
  RowGroup,
  SafetyNumber,
  ScreenTransition,
  Section,
  Segmented,
  SegmentedControl,
  SidebarChrome,
  SidebarEmptyState,
  StatusPill,
  TabBar,
  Toggle,
  useFreshKeys,
  chrome,
  heroAvatarSize,
  layout,
  type BubbleAttachment,
  type ComposerAttachment,
  type IconName,
} from "./ui";

type HomeItem =
  | { kind: "requests"; key: string; items: Conversation[] }
  | { kind: "chat"; key: string; item: Conversation };

// A file waiting in a composer, with the thread it was staged for.
type StagedAttachment = { id: string; scope: string; file: OutgoingAttachment; previewUri?: string };

// How much decrypted attachment data the session keeps at hand.
const ATTACHMENT_CACHE_LIMIT = 64 * 1_048_576;

type Route = { screen: Screen; direction: Direction };

// Keyboard shortcuts continue to follow the host during a UI preview.
const userAgent = Platform.OS === "web" ? navigator.userAgent : "";
const macDesktop = isDesktop && /Mac/.test(userAgent);

// `short` is what a segment has room for beside a phone row's title.
const disappearingOptions = [
  { label: "Off", value: 0 },
  { label: "1 minute", short: "1m", value: 60 },
  { label: "1 hour", short: "1h", value: 3_600 },
  { label: "1 day", short: "1d", value: 86_400 },
];

const notificationPreviewOptions: { value: NotificationPreview; label: string; short: string }[] = [
  { value: "full", label: "Name and message", short: "All" },
  { value: "sender", label: "Name only", short: "Name" },
  { value: "none", label: "No name or message", short: "None" },
];

const appearanceOptions: { value: Appearance; label: string; icon: IconName }[] = [
  { value: "system", label: "Match system", icon: "contrast" },
  { value: "light", label: "Light", icon: "sun" },
  { value: "dark", label: "Dark", icon: "moon" },
];

const tabs = [
  { key: "home", title: "Chats", icon: "chat" },
  { key: "groups", title: "Groups", icon: "groups" },
  { key: "settings", title: "You", icon: "person" },
] as const;


const reloadByDatabase = createKeyedSerialQueue<string>();

const pushSummary = (pushStatus: PushStatus): string =>
  pushStatus === "enabled"
    ? "Messages and mentions enabled"
    : pushStatus === "disabled"
      ? "Notifications off"
      : pushStatus === "pending-bind"
        ? "Turning on once the notification service is reachable"
        : "Turning off; cleanup retries until registration is removed";

export default function App({ windowsPreview = false, onWindowsPreviewChange }: {
  windowsPreview?: boolean;
  onWindowsPreviewChange?: (enabled: boolean) => Promise<void>;
}) {
  const previewWindows = isDesktop && isDevelopmentBuild() && windowsPreview;
  const lightsInset = isDesktop && !previewWindows ? trafficLightInset(userAgent) : 0;
  const [changingWindowsUI, setChangingWindowsUI] = useState(false);
  const { width } = useWindowDimensions();
  const { colors, type, scheme, size, control } = useTheme();
  const styles = useStyles();
  const { appearance, setAppearance } = useAppearance();
  // The status bar's glyphs are the opposite of the canvas behind them.
  const statusBar = scheme === "dark" ? "light" : "dark";
  const [pastedCode, setPastedCode] = useState("");
  const [pendingRevoke, setPendingRevoke] = useState<Uint8Array | null>(null);
  const fontsReady = useAppFonts();
  const [initialLoading, setInitialLoading] = useState(true);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [qrCollector] = useState(createQrCollector);
  const [profile, setProfile] = useState<Uint8Array | null>(null);
  const [route, setRoute] = useState<Route>({ screen: "home", direction: "lateral" });
  const screen = route.screen;
  // The desktop sidebar keeps showing whichever list the open screen came
  // from, and stays put while the pane shows account screens.
  const [sidebarList, setSidebarList] = useState<SidebarList>("chats");
  const setScreen = (next: Screen) => {
    setRoute((current) => ({
      screen: next,
      direction: transitionDirection(current.screen, next),
    }));
    // The scanner belongs to the section that opened it, which is already showing.
    if (next === "scanner") return;
    const section = sidebarSection(next, next);
    if (section !== "you") setSidebarList(section);
  };
  // Every desktop window is wide enough for the sidebar-plus-pane layout;
  // onboarding still uses the whole window.
  const split = usesSplitLayout(Platform.OS, width) && profile !== null;
  const [storedConversations, setConversations] = useState<Conversation[]>([]);
  const [previews, setPreviews] = useState<Record<string, HistoryMessage[]>>({});
  const [groupPreviews, setGroupPreviews] = useState<Record<string, GroupHistoryMessage[]>>({});
  const [readState, setReadState] = useState<ReadState>({});
  const [readAccount, setReadAccount] = useState<string | null>(null);
  const [previewReadState, setPreviewReadState] = useState<ReadState>({});
  // Off until the choice has loaded: an unreadable preference must not leak reading.
  const [readReceipts, setReadReceipts] = useState(false);
  const [notificationPreview, setNotificationPreview] = useState<NotificationPreview>("full");
  // What each chat's other side has acknowledged, kept by the sync that received the receipts.
  const [receiptMarks, setReceiptMarks] = useState<Record<string, ReceiptMarks>>({});
  const [foreground, setForeground] = useState(() => Platform.OS === "web"
    ? document.visibilityState === "visible" && document.hasFocus()
    : AppState.currentState === "active" || AppState.currentState === null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [storedHistory, setHistory] = useState<HistoryMessage[]>([]);
  // Which conversation the loaded history belongs to, so a freshly opened
  // thread never shows another thread's messages or animates old ones in.
  const [storedHistoryFor, setHistoryFor] = useState<string | null>(null);
  const [storedGroups, setGroups] = useState<GroupSummary[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<Uint8Array | null>(
    null,
  );
  const [storedGroupDetails, setGroupDetails] = useState<GroupDetails | null>(null);
  const [storedGroupHistory, setGroupHistory] = useState<GroupHistoryMessage[]>([]);
  const [storedGroupHistoryFor, setGroupHistoryFor] = useState<string | null>(null);
  const [syncError, setSyncError] = useState("");
  // The mailbox reports the same failure on every retry of an outage, so a
  // dismissed message stays dismissed while that outage lasts. Reconnecting
  // clears the slate: a later outage, or a different failure, shows again.
  const [dismissedSyncError, setDismissedSyncError] = useState("");
  const shownSyncError = syncError === dismissedSyncError ? "" : syncError;
  const mailboxSync = useRef<ReturnType<typeof createMailboxSync> | null>(null);
  // The composer floats over the thread; the list pads its end to match.
  const [composerHeight, setComposerHeight] = useState(0);
  const [groupComposer, setGroupComposer] = useState("");
  const [groupUsername, setGroupUsername] = useState("");
  const [storedGroupInvitations, setGroupInvitations] = useState<GroupInvitation[]>([]);
  const [groupKeyPackage, setGroupKeyPackage] = useState<Uint8Array | null>(
    null,
  );
  const [groupPackageOrigin, setGroupPackageOrigin] = useState<Screen>("groups");
  const [scannedGroupPackage, setScannedGroupPackage] =
    useState<Uint8Array | null>(null);
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [nameEditor, setNameEditor] = useState<{ key: string; value: string } | null>(null);
  const [nameError, setNameError] = useState("");
  const editingNickname = nameEditor?.key.startsWith("nickname/") ?? false;
  const nameEditorTitle = editingNickname ? "Private nickname" : "Display name";
  const [pickingPhoto, setPickingPhoto] = useState(false);
  const [accountAvatar, setAccountAvatar] = useState<string>();
  const [presentations, setPresentations] = useState<Record<string, Presentation | undefined>>({});
  const [groupDraftName, setGroupDraftName] = useState("");
  const [groupDraftAvatar, setGroupDraftAvatar] = useState<string>();
  // The members dialog over the open group's thread, and whether the way it
  // led to the group's details was to invite someone.
  const [membersOpen, setMembersOpen] = useState(false);
  const [focusInvite, setFocusInvite] = useState(false);
  const pendingCreatedGroup = useRef<Uint8Array | null>(null);
  const advertisedGroups = useRef(new Map<string, number>());
  const [contactUsername, setContactUsername] = useState("");
  const [firstMessage, setFirstMessage] = useState("");
  // Submitting the recipient moves on to the message without a tap.
  const firstMessageInput = useRef<TextInput>(null);
  const [composer, setComposer] = useState("");
  // The message being answered stays with the thread whose composer took it,
  // so a reply can never follow you into another thread. A quote that is
  // pressed scrolls the thread to its original, which flashes once.
  const [replying, setReplying] = useState<{ scope: string; target: string } | null>(null);
  const thread = useRef<Pick<FlatList, "scrollToIndex" | "scrollToOffset"> | null>(null);
  const [flashKey, setFlashKey] = useState<string | null>(null);
  // The file staged in a composer, and whether one is being dragged over the
  // window. Downloads are remembered by object so a picture is fetched once
  // and a file's state survives scrolling its bubble away.
  const [staged, setStaged] = useState<StagedAttachment[]>([]);
  const stagedRef = useRef(staged);
  const stagedSerial = useRef(0);
  const [dropping, setDropping] = useState(false);
  const [attachmentStates, setAttachmentStates] = useState<Record<string, AttachmentState>>({});
  const attachmentBytes = useRef(new Map<string, Uint8Array>());
  const downloading = useRef(new Set<string>());
  const [scannedProfile, setScannedProfile] = useState<Uint8Array | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("contact");
  const [scannedLinkRequest, setScannedLinkRequest] =
    useState<Uint8Array | null>(null);
  const [linkRequest, setLinkRequest] = useState<Uint8Array | null>(null);
  const [linkAuthorization, setLinkAuthorization] = useState<Uint8Array | null>(
    null,
  );
  const [linkSas, setLinkSas] = useState("");
  const [deviceSet, setDeviceSet] = useState<Uint8Array | null>(null);
  const [devices, setDevices] = useState<DeviceSetSummary | null>(null);
  const [busy, setBusy] = useState(true);
  const [status, setStatus] = useState("Opening encrypted storage…");
  const [error, setError] = useState("");
  const [pushStatus, setPushStatus] = useState<PushStatus>("disabled");
  const [pushBusy, setPushBusy] = useState(false);
  const [pushError, setPushError] = useState("");
  const [notificationTarget, setNotificationTarget] = useState<string | null>(null);
  const [devPreview, setDevPreview] = useState<DevPreview | null>(null);
  const preview = isDevelopmentBuild() ? devPreview : null;
  const conversations = preview?.conversations ?? storedConversations;
  const groups = preview?.groups ?? storedGroups;
  const groupInvitations = preview ? [] : storedGroupInvitations;

  const selected = conversations.find(
    (conversation) => conversation.conversationId.join(".") === selectedId,
  );
  const selectedGroup = groups.find(
    (group) => selectedGroupId && hex(group.groupId) === hex(selectedGroupId),
  );
  const historyFor = preview ? (selected ? hex(selected.conversationId) : null) : storedHistoryFor;
  const history = preview ? (preview.histories[historyFor ?? ""] ?? []) : storedHistory;
  const groupHistoryFor = preview ? (selectedGroup ? hex(selectedGroup.groupId) : null) : storedGroupHistoryFor;
  const groupHistory = preview ? (preview.groupHistories[groupHistoryFor ?? ""] ?? []) : storedGroupHistory;
  const groupDetails = preview ? (preview.groupDetails[groupHistoryFor ?? ""] ?? null) : storedGroupDetails;
  const accountId = profile ? hex(parseProfileSummary(profile).accountId) : null;

  useEffect(() => {
    setActiveNotificationScope(foreground && !preview && !membersOpen
      ? screen === "chat" && selected ? `chat/${hex(selected.conversationId)}`
        : screen === "group" && selectedGroupId ? `group/${hex(selectedGroupId)}` : null
      : null, readReceipts);
    return () => setActiveNotificationScope(null);
  }, [foreground, preview, membersOpen, screen, selected, selectedGroupId, readReceipts]);

  useEffect(() => listenForNotificationOpens(setNotificationTarget), []);
  useEffect(() => {
    if (!notificationTarget || preview) return;
    const chat = conversations.find((item) => notificationTarget === `chat/${hex(item.conversationId)}`);
    const group = groups.find((item) => notificationTarget === `group/${hex(item.groupId)}`);
    if (chat) openConversation(chat);
    else if (group) { setSelectedGroupId(group.groupId); setScreen("group"); }
    else return;
    setNotificationTarget(null);
  }, [notificationTarget, conversations, groups, preview]);

  useEffect(() => {
    if (!accountId) return;
    let current = true;
    // The journals are sealed in the database, so they come back a moment later
    // than the choices kept beside it. Unread counts wait for them.
    void (async () => {
      try {
        const [read, marks] = await Promise.all([loadReadState(accountId), loadReceiptMarks(accountId)]);
        if (!current) return;
        setReadState(read);
        setReceiptMarks(marks);
        setReadReceipts(loadReadReceipts(accountId));
        setNotificationPreview(loadNotificationPreview(accountId));
      } catch {
        if (!current) return;
        setReadState({});
        setReadReceipts(false);
        setError("Couldn’t load read status on this device.");
      }
      if (current) setReadAccount(accountId);
    })();
    return () => { current = false; };
  }, [accountId]);

  useEffect(() => {
    if (Platform.OS === "web") {
      const update = () => setForeground(document.visibilityState === "visible" && document.hasFocus());
      document.addEventListener("visibilitychange", update);
      window.addEventListener("focus", update);
      window.addEventListener("blur", update);
      return () => {
        document.removeEventListener("visibilitychange", update);
        window.removeEventListener("focus", update);
        window.removeEventListener("blur", update);
      };
    }
    const listener = AppState.addEventListener("change", (state) => setForeground(state === "active"));
    return () => listener.remove();
  }, []);

  // The outbox drops an envelope the service will never accept so it cannot hold
  // up everything queued behind it. Say so: the message would otherwise read as sent.
  useEffect(() => onUndeliverable(({ status }) => setError(status === 410
    ? "A message couldn’t reach one of the recipient’s devices because it is no longer registered."
    : "A message waited more than 30 days to send and has expired.")), []);

  // Only a loaded, visible conversation counts as opened. A selected chat in
  // settings, its details screen, or an unfocused window stays unread.
  useEffect(() => {
    if (!foreground || !accountId || readAccount !== accountId || membersOpen) return;
    const scope = screen === "chat" && selected && historyFor === hex(selected.conversationId)
      ? `chat/${historyFor}`
      : screen === "group" && selectedGroupId && groupHistoryFor === hex(selectedGroupId)
        ? `group/${groupHistoryFor}` : null;
    if (!scope) return;
    const keys = receivedMessageKeys(screen === "chat" ? history : groupHistory, accountId);
    const current = preview ? previewReadState : readState;
    if (!unreadCount(keys, current[scope])) return;
    const next = { ...current, [scope]: keys };
    if (preview) setPreviewReadState(next);
    else {
      setReadState(next);
      saveReadState(accountId, next)
        .catch(() => setError("Read status couldn’t be saved. Unread badges may return after restarting."));
      // One cumulative receipt for what was just read. Best effort: the next covers a lost one.
      const through = screen === "chat" && selected && readReceipts && !selected.blocked && !selected.requestPending
        ? receiptDue(history, 2) : undefined;
      if (through) {
        void sendFanout(databasePath, selected!.username, encodeReceipt(2, through), selected!.peerAccountId)
          .catch(() => undefined);
      }
    }
  }, [foreground, accountId, readAccount, membersOpen, screen, selected, selectedGroupId,
    historyFor, groupHistoryFor, history, groupHistory, preview, previewReadState, readState, readReceipts]);

  const read = preview ? previewReadState : readState;
  // Until the sealed journal is back, nothing is known to be unread: better no
  // badge for a moment than every chat flashing as new.
  const readKnown = preview !== null || readAccount === accountId;
  const chatUnread = (conversation: Conversation) => conversation.blocked || !readKnown ? 0 : unreadCount(
    receivedMessageKeys((preview?.histories ?? previews)[hex(conversation.conversationId)] ?? []),
    read[`chat/${hex(conversation.conversationId)}`],
  );
  const groupUnread = (group: GroupSummary) => !readKnown ? 0 : unreadCount(
    receivedMessageKeys((preview?.groupHistories ?? groupPreviews)[hex(group.groupId)] ?? [], accountId ?? undefined),
    read[`group/${hex(group.groupId)}`],
  );

  function toggleDevPreview(enabled: boolean): void {
    if (!isDevelopmentBuild() || busy) return;
    let nextPreview: DevPreview | null = null;
    // Keep build constants beside require so Metro excludes the fixtures from releases.
    if (__DEV__ || (process.env.EXPO_OS === "web" && process.env.EXPO_PUBLIC_DESKTOP_DEVELOPMENT === "true")) {
      if (enabled) nextPreview = (require("./dev-preview") as typeof import("./dev-preview")).createDevPreview();
    }
    setDevPreview(nextPreview);
    setPreviewReadState(nextPreview?.readState ?? {});
    setSelectedId(null);
    setSelectedGroupId(null);
    setComposer("");
    setGroupComposer("");
    setError("");
  }

  async function refreshPresentations(keys: string[]): Promise<void> {
    const allKeys = keys.flatMap((key) => key.startsWith("user/") ? [key, `nickname/${key.slice(5)}`] : [key]);
    const entries = await Promise.all([...new Set(allKeys)].map(async (key) => [key, await loadPresentation(databasePath, key)] as const));
    setPresentations((previous) => ({ ...previous, ...Object.fromEntries(entries) }));
  }

  const presentationOf = (key: string) => preview?.presentations[key] ?? presentations[key];
  const contactName = (contact: Conversation) => identityName(contact.username,
    presentationOf(`user/${hex(contact.peerAccountId)}`), presentationOf(`nickname/${hex(contact.peerAccountId)}`))!;
  const groupName = (id: Uint8Array) => presentationOf(`group/${hex(id)}`)?.name ?? `Group ${hex(id).slice(0, 6)}`;
  const groupAvatar = (id: Uint8Array) => presentationOf(`group/${hex(id)}`)?.avatar;

  function rememberPreview(
    conversation: Conversation,
    messages: HistoryMessage[],
  ): void {
    const key = hex(conversation.conversationId);
    setPreviews((previous) => ({ ...previous, [key]: messages }));
  }

  async function refreshPreviews(list: Conversation[]): Promise<void> {
    await Promise.all(
      list.map(async (conversation) => {
        try {
          const encoded = await load_history_export(
            peerRequest(databasePath, conversation.peerAccountId),
          );
          rememberPreview(conversation, parseHistory(encoded));
        } catch {
          // A conversation without readable history simply shows no preview.
        }
      }),
    );
  }

  async function refreshConversations(): Promise<Conversation[]> {
    const encoded = await list_conversations_export(utf8(databasePath));
    const next = parseConversations(encoded);
    setConversations(next);
    await Promise.all([refreshPreviews(next), refreshPresentations([...next.map((item) => `user/${hex(item.peerAccountId)}`), ...(profile ? [`user/${hex(parseProfileSummary(profile).accountId)}`] : [])])]);
    return next;
  }

  useEffect(() => {
    if (preview || !selected) return;
    const conversation = selected;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const encoded = await load_history_export(peerRequest(databasePath, conversation.peerAccountId));
        if (cancelled) return;
        const messages = parseHistory(encoded);
        setHistory(messages);
        setHistoryFor(hex(conversation.conversationId));
        rememberPreview(conversation, messages);
        const delay = historyRefreshDelay(messages, Date.now());
        if (delay !== undefined) timer = setTimeout(() => void load(), delay);
      } catch (caught) {
        if (!cancelled) setError(friendlyError(caught));
      }
    }
    void load();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [selected, preview]);

  async function refreshGroups(): Promise<GroupSummary[]> {
    const [next, invitations] = await Promise.all([
      listGroups(databasePath), listGroupInvitations(databasePath),
    ]);
    setGroups(next);
    setGroupInvitations(invitations);
    await Promise.all([
      refreshPresentations(next.map((group) => `group/${hex(group.groupId)}`)),
      ...next.map(async (group) => {
        try {
          const messages = await loadGroupHistory(databasePath, group.groupId);
          setGroupPreviews((previous) => ({ ...previous, [hex(group.groupId)]: messages }));
        } catch {
          // Keep the last known count if this group's history is unavailable.
        }
      }),
    ]);
    // Announce identities after joining or changing membership; empty messages stay out of history.
    for (const group of next) {
      const key = hex(group.groupId);
      if (group.memberCount > 1 && advertisedGroups.current.get(key) !== group.epoch) {
        await group_send_export(vectors(utf8(databasePath), group.groupId, utf8("")));
        advertisedGroups.current.set(key, group.epoch);
        await drainOutbox(databasePath);
      }
    }
    return next;
  }

  function refreshLocalData(): Promise<void> {
    return reloadByDatabase(databasePath, async () => {
      try { if (accountId) setReceiptMarks(await loadReceiptMarks(accountId)); }
      catch { /* Keep the last known marks. */ }
      const results = await Promise.allSettled([refreshConversations(), refreshGroups()]);
      const failure = results.find((result) => result.status === "rejected");
      if (failure?.status === "rejected") throw failure.reason;
    });
  }

  useEffect(() => {
    if (preview || !selectedGroup) return;
    let cancelled = false;
    void Promise.all([
      inspectGroup(databasePath, selectedGroup.groupId),
      loadGroupHistory(databasePath, selectedGroup.groupId),
    ]).then(async ([details, messages]) => {
      if (cancelled) return;
      setGroupDetails(details);
      setGroupHistory(messages);
      setGroupHistoryFor(hex(selectedGroup.groupId));
      setGroupPreviews((previous) => ({ ...previous, [hex(selectedGroup.groupId)]: messages }));
      await refreshPresentations([...details.members.map((member) => `user/${hex(member.accountId)}`), ...messages.map((message) => `user/${hex(message.senderAccountId)}`)]);
    }).catch((caught) => {
      if (!cancelled) setError(friendlyError(caught));
    });
    return () => { cancelled = true; };
  }, [selectedGroup, preview]);

  async function refreshDevices(
    currentProfile: Uint8Array,
  ): Promise<DeviceSetSummary> {
    const loaded = await loadAccountDevices(databasePath, currentProfile);
    setDeviceSet(loaded.wire);
    setDevices(loaded.summary);
    return loaded.summary;
  }

  async function updatePush(work: () => Promise<PushStatus>): Promise<void> {
    if (preview) return;
    setPushBusy(true);
    setPushError("");
    try {
      setPushStatus(await work());
    } catch (caught) {
      setPushError(friendlyError(caught));
      try {
        setPushStatus(await getPushStatus(databasePath));
      } catch {
        // Keep the last Mesh-derived status when encrypted storage is unavailable.
      }
    } finally {
      setPushBusy(false);
    }
  }

  function recoverPush(): void {
    void updatePush(() => recoverPushBinding(databasePath));
  }

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const loaded = await load_profile_export(utf8(databasePath));
        if (cancelled) return;
        setProfile(loaded);
        await refreshPresentations([`user/${hex(parseProfileSummary(loaded).accountId)}`]);
        await refreshLocalData();
        setStatus("Welcome back");
      } catch {
        if (!cancelled) setStatus("Choose a username to get started");
      } finally {
        if (!cancelled) {
          setBusy(false);
          setInitialLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!profile) return undefined;
    const sync = createMailboxSync(
      () => connectMailboxStream(databasePath),
      async () => {
        try {
          await synchronizeWithNotifications(databasePath);
          const currentDevices = await refreshDevices(profile);
          if (currentDevices.changed) {
            setError("The devices on your account changed. Check your linked devices.");
          }
        } finally {
          // Native writes may have committed even if delivery or acknowledgement failed.
          await refreshLocalData();
        }
      },
      (caught) => {
        setSyncError(caught ? friendlyError(caught) : "");
        if (!caught) setDismissedSyncError("");
      },
    );
    mailboxSync.current = sync;
    const removePushListeners = listenForGenericWakeups(sync.invalidate);
    const appState = AppState.addEventListener("change", (state) => {
      if (state !== "active") setActiveNotificationScope(null);
      sync.setActive(Platform.OS === "web" || state === "active");
    });
    sync.setActive(Platform.OS === "web" || AppState.currentState === "active" || AppState.currentState === null);
    return () => {
      mailboxSync.current = null;
      sync.dispose();
      removePushListeners();
      appState.remove();
    };
  }, [profile]);

  useEffect(() => {
    if (!profile) return undefined;
    const removeRegistrationListener =
      listenForPushRegistrationChanges(recoverPush);
    const appState = AppState.addEventListener("change", (state) => {
      if (state === "active") recoverPush();
    });
    recoverPush();
    return () => {
      removeRegistrationListener();
      appState.remove();
    };
  }, [profile]);

  async function perform(
    label: string,
    work: () => Promise<void>,
  ): Promise<void> {
    if (preview) {
      setError("Sample preview is read-only. Turn it off in You → Development to make changes.");
      return;
    }
    setBusy(true);
    setError("");
    setStatus(label);
    try {
      await work();
    } catch (caught) {
      qrCollector.reset();
      setError(friendlyError(caught));
    } finally {
      if (profile) mailboxSync.current?.invalidate();
      try {
        if (profile) await refreshLocalData();
      } catch (caught) {
        setError(friendlyError(caught));
      }
      setBusy(false);
    }
  }

  function openConversation(conversation: Conversation): void {
    const nextId = conversation.conversationId.join(".");
    if (nextId !== selectedId) {
      setHistory([]);
      setHistoryFor(null);
    }
    setSelectedId(nextId);
    setScreen("chat");
  }

  // Arriving in the app for the first time always reads as moving forward,
  // whatever screen the onboarding flow happened to be on.
  const enterApp = () => setRoute({ screen: "home", direction: "forward" });

  function createAccount(): void {
    const normalized = username.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(normalized)) {
      setError("Use 3–32 lowercase letters, numbers, or underscores.");
      return;
    }
    const presentation = { name: displayName.trim() || normalized, avatar: accountAvatar };
    try { encodePresentation(presentation); }
    catch (caught) { setError(friendlyError(caught)); return; }
    void perform("Creating your account…", async () => {
      const created = await create_account_export(
        accountRequest(databasePath, normalized),
      );
      setProfile(created);
      enterApp();
      const key = `user/${hex(parseProfileSummary(created).accountId)}`;
      const saved = await savePresentation(databasePath, key, presentation);
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      await registerDirectory(databasePath);
      await refreshDevices(created);
      setUsername("");
      setDisplayName("");
      setStatus("Account created");
    });
  }

  function startWithProfile(contact: Uint8Array, body: string): void {
    if (!body.trim() && !stagedFor("new-chat").length) {
      setError("Write a first message.");
      return;
    }
    void perform("Sending…", async () => {
      const peer = parseProfileSummary(contact);
      let changed = false;
      await sendWithAttachment("new-chat", async (attachment) => {
        changed = await sendFanout(databasePath, peer.username, body.trim(), peer.accountId, attachment);
      });
      setFirstMessage("");
      setScannedProfile(null);
      noteSent(peer.username, changed);
      setScreen("home");
    });
  }

  function startByUsername(): void {
    const target = contactUsername.trim().toLowerCase();
    void perform("Sending…", async () => {
      let changed = false;
      await sendWithAttachment("new-chat", async (attachment) => {
        changed = await sendFanout(databasePath, target, firstMessage.trim(), undefined, attachment);
      });
      Keyboard.dismiss();
      setContactUsername("");
      setFirstMessage("");
      setScreen("home");
      noteSent(target, changed);
    });
  }

  function sendMessage(): void {
    if (!selected) return;
    const scope = `chat/${selected.conversationId.join(".")}`;
    if (!composer.trim() && !stagedFor(scope).length) return;
    void perform("Sending…", async () => {
      let changed = false;
      await sendWithAttachment(scope, async (attachment) => {
        changed = await sendFanout(databasePath, selected.username, outgoingBody(composer.trim()), selected.peerAccountId, attachment);
      });
      setComposer("");
      setReplying(null);
      noteSent(selected.username, changed);
    });
  }

  function reactToMessage(message: HistoryMessage | GroupHistoryMessage, emoji: string): void {
    if (busy || !message.messageId) return;
    const group = "senderAccountId" in message;
    if (group ? !selectedGroupId || (selectedGroup?.memberCount ?? 0) < 2
      : !selected || selected.blocked || selected.requestPending) return;
    void perform("Sending reaction…", async () => {
      const body = encodeReaction(hex(message.messageId!), emoji);
      if (group) await sendGroupMessage(databasePath, selectedGroupId!, body);
      else {
        const changed = await sendFanout(databasePath, selected!.username, body, selected!.peerAccountId);
        noteSent(selected!.username, changed);
      }
      setStatus("Reaction sent");
    });
  }

  // A message is on its way; if the other side's devices changed since the
  // last one, that is worth a warning in words a person can act on.
  function noteSent(username: string, devicesChanged: boolean): void {
    setStatus("Sent");
    if (devicesChanged)
      setError(`@${username}’s devices changed. Compare safety numbers again before you trust this conversation.`);
  }

  // Staged files stay with the composer that accepted them.
  const openScope = composerScope(screen, selectedId, selectedGroupId ? hex(selectedGroupId) : null);
  // What the open composer answers, while that message is still in the thread:
  // once it expires, the reply bar goes and the words are sent on their own.
  const replyTarget = replying && replying.scope === openScope
    ? [...history, ...groupHistory].find((message) => message.messageId && hex(message.messageId) === replying.target)
    : undefined;
  const outgoingBody = (text: string): string => replyTarget ? encodeReply(replying!.target, text) : text;

  function showOriginal(rows: readonly { key: string }[], target: string): void {
    const index = rows.findIndex((row) => row.key === target);
    if (index < 0) return;
    thread.current?.scrollToIndex({ index, viewPosition: 0.5, animated: true });
    setFlashKey(target);
  }
  // A row that has never been drawn has no measured place yet: go to where it
  // should be, then to the row itself once the list has drawn it.
  function retryShowOriginal({ index, averageItemLength }: { index: number; averageItemLength: number }): void {
    thread.current?.scrollToOffset({ offset: index * averageItemLength, animated: true });
    setTimeout(() => thread.current?.scrollToIndex({ index, viewPosition: 0.5, animated: true }), 250);
  }
  useEffect(() => {
    if (!flashKey) return;
    const timer = setTimeout(() => setFlashKey(null), 1400);
    return () => clearTimeout(timer);
  }, [flashKey]);
  const stagedFor = (scope: string | null): StagedAttachment[] =>
    stagedRef.current.filter((entry) => entry.scope === scope);

  function updateStaged(entries: StagedAttachment[]): void {
    stagedRef.current = entries;
    setStaged(entries);
  }

  function stageAttachments(scope: string | null, files: OutgoingAttachment[]): void {
    if (scope === null || !files.length || busy) return;
    if (preview) {
      setError("Sample preview is read-only. Turn it off in You → Development to make changes.");
      return;
    }
    const limit = attachmentSelectionError(files.map((file) => file.bytes.length), stagedFor(scope).length);
    if (limit) { setError(limit); return; }
    const entries: StagedAttachment[] = [];
    try {
      for (const file of files) {
        const id = `staged-${stagedSerial.current++}`;
        const previewUri = isImageAttachment(file.mimeType) ? attachmentPreviewUri(id, file.mimeType, file.bytes) : undefined;
        entries.push({ id, scope, file, previewUri });
      }
    } catch (caught) {
      for (const entry of entries) if (entry.previewUri) releasePreviewUri(entry.previewUri);
      setError(friendlyError(caught));
      return;
    }
    setError("");
    updateStaged([...stagedRef.current, ...entries]);
  }

  function unstageAttachment(id: string): void {
    const entry = stagedRef.current.find((entry) => entry.id === id);
    if (entry?.previewUri) releasePreviewUri(entry.previewUri);
    updateStaged(stagedRef.current.filter((entry) => entry.id !== id));
  }

  function attachFile(scope: string | null): void {
    if (scope === null || busy) return;
    pickAttachmentFiles().then(
      (files) => stageAttachments(scope, files),
      (caught) => setError(friendlyError(caught)),
    );
  }

  const composerAttachments = (scope: string | null): ComposerAttachment[] =>
    staged.filter((entry) => entry.scope === scope).map((entry) => ({
      id: entry.id,
      filename: entry.file.filename,
      size: formatBytes(entry.file.bytes.length),
      previewUri: entry.previewUri,
    }));

  useEffect(() => listenForIncomingFiles({
    onDragging: setDropping,
    onFiles: (files) => stageAttachments(openScope, files),
    onError: setError,
  }));

  async function sendWithAttachment(scope: string, send: (attachment?: Uint8Array) => Promise<void>): Promise<void> {
    const entries = stagedFor(scope);
    const uploaded = await sendWithAttachments(databasePath, entries.map((entry) => entry.file), async (reference) => {
      setStatus("Sending…");
      await send(reference);
    }, (completed, total) => setStatus(`Uploading… ${Math.round(completed / total * 100)}%`));
    uploaded.forEach((file, index) => {
      const entry = entries[index]!;
      const key = hex(file.objectId);
      rememberBytes(key, entry.file.bytes);
      setAttachmentState(key, { status: "ready", previewUri: entry.previewUri });
    });
    updateStaged(stagedRef.current.filter((entry) => !entries.includes(entry)));
  }

  function setAttachmentState(key: string, state: AttachmentState): void {
    setAttachmentStates((previous) => ({ ...previous, [key]: state }));
  }

  // Decrypted files stay in memory for the session, oldest out first once
  // they add up; a picture already written to its preview keeps showing.
  function rememberBytes(key: string, bytes: Uint8Array): void {
    const cache = attachmentBytes.current;
    cache.delete(key);
    cache.set(key, bytes);
    let total = 0;
    for (const value of cache.values()) total += value.length;
    for (const [oldest, value] of cache) {
      if (total <= ATTACHMENT_CACHE_LIMIT || oldest === key) break;
      cache.delete(oldest);
      total -= value.length;
    }
  }

  const attachmentState = (attachment: AttachmentSummary): AttachmentState | undefined =>
    attachmentStates[hex(attachment.objectId)] ??
    (attachment.expiresAt < Date.now() ? { status: "error", message: "Expired" } : undefined);

  // Fetches and decrypts a file once; a tap on it then writes it where the
  // person chooses. A second tap while it is on its way does nothing.
  function openAttachment(attachment: AttachmentSummary, save: boolean): void {
    const key = hex(attachment.objectId);
    if (downloading.current.has(key)) return;
    // A picture whose bytes have since left the cache keeps its preview.
    const current = attachmentStates[key];
    let previewUri = current?.previewUri;
    void (async () => {
      try {
        let bytes = attachmentBytes.current.get(key);
        if (!bytes) {
          downloading.current.add(key);
          setAttachmentState(key, { status: "downloading", completed: 0, total: attachment.chunkCount, previewUri });
          try {
            bytes = await downloadAttachment(databasePath, attachment, (completed, total) =>
              setAttachmentState(key, { status: "downloading", completed, total, previewUri }),
            );
          } finally {
            downloading.current.delete(key);
          }
          rememberBytes(key, bytes);
          if (previewUri === undefined && isImageAttachment(attachment.mimeType)) {
            previewUri = attachmentPreviewUri(key, attachment.mimeType, bytes);
          }
          setAttachmentState(key, { status: "ready", previewUri });
        }
        if (!save) return;
        if (await saveAttachmentFile(attachment.filename, attachment.mimeType, bytes)) {
          setAttachmentState(key, { status: "saved", previewUri });
        }
      } catch (caught) {
        const message = friendlyError(caught);
        setAttachmentState(key, { status: "error", message, previewUri });
        // A fetch nobody asked for fails quietly, on its own card.
        if (save) setError(message);
      }
    })();
  }

  // What a bubble shows for its file. Pictures from people we already talk
  // with are fetched on sight; a stranger's request waits for a tap.
  function bubbleAttachment(attachment: AttachmentSummary, trusted: boolean): BubbleAttachment {
    const state = attachmentState(attachment);
    const image = isImageAttachment(attachment.mimeType);
    return {
      id: hex(attachment.objectId),
      filename: attachment.filename || (image ? "Photo" : "Attachment"),
      image,
      status: describeAttachmentState(attachment, state),
      busy: state?.status === "downloading",
      previewUri: state?.previewUri,
      onPress: () => openAttachment(attachment, true),
      onAppear: trusted && state === undefined && shouldAutoDownload(attachment)
        ? () => openAttachment(attachment, false)
        : undefined,
    };
  }

  function applyPolicy(
    conversation: Conversation,
    action: number,
    value: number,
    status: string,
  ): void {
    void perform("Saving…", async () => {
      await update_conversation_export(
        policyRequest(databasePath, conversation.peerAccountId, action, value),
      );
      setStatus(status);
    });
  }

  function updatePolicy(action: number, value = 0): void {
    if (!selected) return;
    applyPolicy(selected, action, value, "Saved");
  }

  function acceptRequest(conversation: Conversation): void {
    applyPolicy(conversation, 1, 0, `You can now reply to @${conversation.username}`);
  }

  function openScanner(mode: ScanMode): void {
    qrCollector.reset();
    setScanMode(mode);
    setScannedProfile(null);
    setScannedLinkRequest(null);
    setScannedGroupPackage(null);
    setError("");
    setScreen("scanner");
  }

  function beginDeviceLink(): void {
    void perform("Getting ready to link…", async () => {
      const request = await create_link_request_export(utf8(databasePath));
      const sas = decodeUtf8(await device_link_sas_export(request));
      setLinkRequest(request);
      setLinkSas(sas);
      setScreen("link-device");
      setStatus("This code expires in ten minutes");
    });
  }

  function openDevices(): void {
    if (!profile) return;
    void perform("Checking your devices…", async () => {
      await refreshDevices(profile);
      setScreen("devices");
      setStatus("Devices up to date");
    });
  }

  function openGroup(group: GroupSummary): void {
    if (!selectedGroupId || hex(selectedGroupId) !== hex(group.groupId)) {
      setGroupDetails(null);
      setGroupHistory([]);
      setGroupHistoryFor(null);
    }
    setSelectedGroupId(group.groupId);
    setScreen("group");
  }

  function createNewGroup(): void {
    if (preview) { setError("Turn off sample preview to create a group."); return; }
    setGroupDraftName("");
    setGroupDraftAvatar(undefined);
    pendingCreatedGroup.current = null;
    go("new-group");
  }

  function finishGroupCreation(): void {
    try { encodePresentation({ name: groupDraftName, avatar: groupDraftAvatar }); }
    catch (caught) { setError(friendlyError(caught)); return; }
    void perform("Creating your group…", async () => {
      const groupId = pendingCreatedGroup.current ?? await createGroup(databasePath);
      pendingCreatedGroup.current = groupId;
      const key = `group/${hex(groupId)}`;
      const saved = await savePresentation(databasePath, key, { name: groupDraftName, avatar: groupDraftAvatar });
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      setSelectedGroupId(groupId);
      setGroupDetails(null);
      setGroupHistory([]);
      setGroupHistoryFor(null);
      pendingCreatedGroup.current = null;
      setScreen("group-info");
      setStatus("Group created. Invite someone to get started.");
    });
  }

  function updateAvatar(key: string, name: string, avatar?: string): void {
    void perform("Saving photo…", async () => {
      const saved = await savePresentation(databasePath, key, { name, avatar });
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      if (key.startsWith("user/")) advertisedGroups.current.clear();
      else advertisedGroups.current.delete(key.slice(6));
      setStatus("Photo saved");
    });
  }

  function editName(key: string, value: string): void {
    setNameError("");
    setNameEditor({ key, value });
  }

  function saveName(): void {
    if (!nameEditor || busy || preview) return;
    const { key, value } = nameEditor;
    const nickname = key.startsWith("nickname/");
    const presentation = { ...presentationOf(key), name: value.trim() || ownUsername };
    try { if (!nickname || value.trim()) encodePresentation(presentation); }
    catch (caught) { setNameError(friendlyError(caught)); return; }
    void perform("Saving name…", async () => {
      try {
        const saved = nickname
          ? await saveNickname(databasePath, key, value)
          : await savePresentation(databasePath, key, presentation);
        setPresentations((previous) => ({ ...previous, [key]: saved }));
        if (!nickname) advertisedGroups.current.clear();
        setNameEditor(null);
        setStatus("Name saved");
      } catch (caught) {
        setNameError(friendlyError(caught));
      }
    });
  }

  function pickPhoto(onChange: (value: string) => void): void {
    setPickingPhoto(true);
    void pickAvatar()
      .then((value) => { if (value) onChange(value); })
      .catch((caught) => setError(friendlyError(caught)))
      .finally(() => setPickingPhoto(false));
  }

  // The picture of an identity as the control for changing it. Sample
  // content is read-only, so there it is only a picture.
  function renderPhotoButton(
    name: string,
    avatar: string | undefined,
    onChange: (value: string) => void,
    { group = false, size = heroAvatarSize, seed }: { group?: boolean; size?: number; seed?: string } = {},
  ) {
    return (
      <PhotoButton
        name={name || (group ? "New group" : "You")}
        uri={avatar}
        colorSeed={seed}
        group={group}
        size={size}
        editable={preview === null}
        disabled={busy}
        busy={pickingPhoto}
        onPress={() => pickPhoto(onChange)}
      />
    );
  }

  function renderRemovePhoto(onRemove: () => void) {
    return (
      <Button
        label="Remove photo"
        variant="ghost"
        size="sm"
        disabled={busy || pickingPhoto || preview !== null}
        onPress={onRemove}
      />
    );
  }

  // The picture beside the way to clear it, for a form that edits a photo in place.
  function renderPhotoEditor(name: string, avatar: string | undefined, onChange: (value: string | undefined) => void, group = false) {
    return (
      <View style={styles.photoEditor}>
        {renderPhotoButton(name, avatar, onChange, { group, size: size.avatar["2xl"] })}
        {avatar ? renderRemovePhoto(() => onChange(undefined)) : null}
      </View>
    );
  }

  // Naming a group is composed like the identity it creates: the picture
  // first, large and tappable, then the name beneath it. On desktop the form
  // sits as a narrow sheet in the pane.
  function renderNewGroup() {
    return (
      <Page header={<Header title="New group" onBack={() => go("groups")} backLabel="Cancel" />}>
        <ScrollView
          contentContainerStyle={[layout.content, styles.newGroup]}
          keyboardShouldPersistTaps="handled"
        >
          <View style={styles.newGroupPhoto}>
            {renderPhotoButton(groupDraftName, groupDraftAvatar, setGroupDraftAvatar, { group: true })}
            {groupDraftAvatar ? renderRemovePhoto(() => setGroupDraftAvatar(undefined)) : null}
          </View>
          <Field
            label="Group name"
            value={groupDraftName}
            onChangeText={setGroupDraftName}
            placeholder="Weekend walks"
            maxLength={96}
            autoFocus
            hint="Shown to everyone you invite. You can change both later in group details."
          />
          <Actions>
            <Button
              label="Create group"
              onPress={finishGroupCreation}
              disabled={busy || pickingPhoto || !groupDraftName.trim()}
            />
          </Actions>
          <Text style={[type.footnote, styles.newGroupNote]}>You’ll invite people next.</Text>
        </ScrollView>
      </Page>
    );
  }

  function showGroupKeyPackage(): void {
    void perform("Preparing your code…", async () => {
      setGroupKeyPackage(await getGroupKeyPackage(databasePath));
      if (isDesktop && screen !== "group-package") setGroupPackageOrigin(screen);
      setScreen("group-package");
      setStatus("Show this code to a group member");
    });
  }

  function inviteByUsername(): void {
    if (!selectedGroupId) return;
    const target = groupUsername.trim().toLowerCase().replace(/^@/, "");
    if (!/^[a-z0-9._-]{1,64}$/.test(target)) {
      setError("Enter their exact username.");
      return;
    }
    void perform("Sending invitation…", async () => {
      await inviteToGroup(databasePath, selectedGroupId, target);
      setGroupUsername("");
      setStatus(`Invitation sent to @${target}`);
    });
  }

  function answerGroupInvitation(invitation: GroupInvitation, accept: boolean): void {
    void perform(accept ? "Accepting invitation…" : "Declining invitation…", async () => {
      if (accept) await acceptGroupInvitation(databasePath, invitation);
      else await declineGroupInvitation(databasePath, invitation.reference);
      setStatus(accept ? "Accepted. You’ll join when the inviter is next online." : "Invitation declined");
    });
  }

  function scanGroupKeyPackage(): void {
    const target = groupUsername.trim().toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(target)) {
      setError("Enter their exact username before scanning their code.");
      return;
    }
    openScanner("group-key-package");
  }

  function sendGroupText(): void {
    if (!selectedGroupId) return;
    const scope = `group/${hex(selectedGroupId)}`;
    if (!groupComposer.trim() && !stagedFor(scope).length) return;
    void perform("Sending…", async () => {
      await sendWithAttachment(scope, (attachment) =>
        sendGroupMessage(databasePath, selectedGroupId, outgoingBody(groupComposer.trim()), attachment),
      );
      setGroupComposer("");
      setReplying(null);
      setStatus("Sent");
    });
  }

  // Removing a person removes every device they are in the group with.
  function removeFromGroup(person: Person, name: string): void {
    if (!selectedGroupId) return;
    void perform(`Removing ${name} from the group…`, async () => {
      for (const deviceId of person.deviceIds) {
        await removeGroupMember(databasePath, selectedGroupId, person.accountId, deviceId);
      }
      setStatus(`${name} removed from the group`);
    });
  }

  function authorizeScannedDevice(): void {
    if (!profile || !scannedLinkRequest) return;
    void perform("Approving the new device…", async () => {
      const loaded = await loadAccountDevices(databasePath, profile);
      const authorization = await authorizeDeviceLink(
        databasePath,
        loaded.wire,
        scannedLinkRequest,
      );
      setLinkAuthorization(authorization);
      setScreen("link-authorization");
      setStatus("Device approved");
    });
  }

  function confirmRevoke(deviceId: Uint8Array): void {
    if (Platform.OS === "web") { setPendingRevoke(deviceId); return; }
    Alert.alert(
      "Remove this device?",
      "It will permanently lose access to your account and future messages.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Remove device",
          style: "destructive",
          onPress: () => revokeLinkedDevice(deviceId),
        },
      ],
    );
  }

  function revokeLinkedDevice(deviceId: Uint8Array): void {
    if (!profile || !deviceSet) return;
    void perform("Removing the device…", async () => {
      await revokeDevice(databasePath, deviceSet, deviceId);
      await refreshDevices(profile);
      setStatus("Device removed");
    });
  }

  function onQrScanned(result: Pick<BarcodeScanningResult, "data">): void {
    if (scannedProfile || scannedLinkRequest || scannedGroupPackage) return;
    let data: string;
    try {
      const assembled = qrCollector.scan(result.data);
      if (assembled === null) return;
      data = assembled;
    } catch (caught) {
      qrCollector.reset();
      setError(friendlyError(caught));
      return;
    }
    if (scanMode === "contact") {
      try {
        const contact = profileFromQr(data);
        parseProfileSummary(contact);
        setScannedProfile(contact);
        setError("");
      } catch (caught) {
        qrCollector.reset();
        setError(friendlyError(caught));
      }
    } else if (scanMode === "link-request") {
      void perform("Checking the code…", async () => {
        const request = linkRequestFromQr(data);
        const sas = decodeUtf8(await device_link_sas_export(request));
        setScannedLinkRequest(request);
        setLinkSas(sas);
        setStatus("Compare this code on both devices");
      });
    } else if (scanMode === "link-authorization") {
      setScreen("link-device");
      void perform("Finishing the link…", async () => {
        const authorization = payloadFromQr(data, "link-authorization", 20_864);
        const linkedProfile = await complete_device_link_export(
          vectors(utf8(databasePath), authorization),
        );
        setProfile(linkedProfile);
        await registerDirectory(databasePath);
        await refreshDevices(linkedProfile);
        setLinkRequest(null);
        setLinkSas("");
        enterApp();
        setStatus("This device is linked");
      });
    } else {
      const groupId = selectedGroupId;
      const target = groupUsername.trim().toLowerCase();
      if (!groupId || !target) {
        setError(
          "Choose a group and enter the exact username before scanning.",
        );
        return;
      }
      void perform(
        `Adding @${target} to the group…`,
        async () => {
          const keyPackage = payloadFromQr(
            data,
            "group-key-package",
            GROUP_KEY_PACKAGE_LENGTH,
          );
          setScannedGroupPackage(keyPackage);
          try {
            await addGroupMember(databasePath, groupId, target, keyPackage);
            setGroupUsername("");
            setScreen("group");
            setStatus(`@${target} added to the group`);
          } finally {
            qrCollector.reset();
            setScannedGroupPackage(null);
          }
        },
      );
    }
  }

  const ownProfile = profile ? parseProfileSummary(profile) : null;
  const ownId = ownProfile ? hex(ownProfile.accountId) : undefined;
  const ownUsername = ownProfile?.username ?? "";
  const ownName = (ownId && presentationOf(`user/${ownId}`)?.name) || ownUsername;
  const ownAvatar = ownId ? presentationOf(`user/${ownId}`)?.avatar : undefined;
  const creatorId = groupDetails?.members.find((member) => member.leaf === 0)?.accountId;
  const isGroupCreator = Boolean(creatorId && (preview ? groupDetails?.members.find((member) => member.leaf === 0)?.local : ownProfile && hex(creatorId) === hex(ownProfile.accountId)));
  function senderIdentity(accountId: Uint8Array | string, local = false) {
    const id = typeof accountId === "string" ? accountId : hex(accountId);
    const stored = presentationOf(`user/${id}`);
    const contact = conversations.find((item) => hex(item.peerAccountId) === id);
    const invitation = groupInvitations.find((item) => hex(item.accountId) === id);
    const member = groupDetails?.members.find((item) => hex(item.accountId) === id);
    const own = local || id === (ownProfile && hex(ownProfile.accountId));
    const username = own ? ownUsername : contact?.username ?? invitation?.username ?? member?.username ?? null;
    const name = identityName(username, stored, own ? undefined : presentationOf(`nickname/${id}`));
    return { name: name ?? `Member ${id.slice(0, 6)}`, username, accountId: id,
      avatar: own ? ownAvatar : stored?.avatar, creator: Boolean(creatorId && hex(creatorId) === id),
      // Your private thread with them, when there is one.
      conversation: own ? undefined : contact };
  }
  type Identity = ReturnType<typeof senderIdentity>;

  // A private word with someone from a group: their thread if you have one,
  // otherwise a new message already addressed to them.
  function messageMember(identity: Identity): void {
    setMembersOpen(false);
    if (identity.conversation) {
      openConversation(identity.conversation);
      return;
    }
    if (!identity.username) return;
    setContactUsername(identity.username);
    go("new-chat");
  }

  // Group details with the invitation field ready to type into.
  function inviteSomeone(): void {
    setFocusInvite(true);
    go("group-info");
  }
  const groupRequestCount = groupInvitations.filter((item) => item.state === 1).length;
  const chatBadgeCount = conversations.reduce((total, item) => total + (item.requestPending ? 1 : chatUnread(item)), 0);
  const groupBadgeCount = groupRequestCount + groups.reduce((total, item) => total + groupUnread(item), 0);
  const mainScreen = profile && ["home", "groups", "settings"].includes(screen);
  const chatRows = buildChatRows(history, (message) => hex(message.messageId)).reverse();
  const chatScope =
    selected && historyFor === hex(selected.conversationId) ? historyFor : null;
  const isFreshMessage = useFreshKeys(
    chatRows.map((row) => row.key),
    chatScope,
  );
  const groupRows = buildChatRows(
    groupHistory,
    (message, index) => message.messageId ? hex(message.messageId) : `${message.epoch}-${hex(message.senderDeviceId)}-${index}`,
    Date.now(),
    (message) => hex(message.senderAccountId),
  ).reverse();
  const groupScope =
    selectedGroupId && groupHistoryFor === hex(selectedGroupId) ? groupHistoryFor : null;
  const isFreshGroupMessage = useFreshKeys(
    groupRows.map((row) => row.key),
    groupScope,
  );
  const previewOf = (conversation: Conversation) =>
    (preview?.histories ?? previews)[hex(conversation.conversationId)]?.at(-1);
  const sortedConversations = [...conversations].sort(
    (a, b) => (previewOf(b)?.timestamp ?? 0) - (previewOf(a)?.timestamp ?? 0),
  );
  const pendingRequests = sortedConversations.filter((item) => item.requestPending);
  const homeItems: HomeItem[] = [
    ...(pendingRequests.length
      ? [{ kind: "requests", key: "requests", items: pendingRequests } as const]
      : []),
    ...sortedConversations
      .filter((item) => !item.requestPending)
      .map((item) => ({ kind: "chat", key: hex(item.conversationId), item }) as const),
  ];
  const go = (next: Screen) => {
    Keyboard.dismiss();
    setError("");
    setMembersOpen(false);
    if (next !== "group-info") setFocusInvite(false);
    setScreen(next);
  };
  const backToScannerOrigin = () => go(scannerOrigin(scanMode));
  // Where dismissing the current screen leads. Root screens stay put.
  const dismissTarget = (): Screen | null =>
    screen === "scanner" ? scannerOrigin(scanMode) : parentScreen(screen, isDesktop ? groupPackageOrigin : undefined);
  // With the list already on screen beside the pane, a back button to it
  // would only repeat the sidebar; deeper screens keep theirs.
  const backTo = (target: Screen, label?: string) =>
    split && (target === "home" || target === "groups")
      ? {}
      : { onBack: () => go(target), backLabel: label };
  // Before there is an account, a desktop screen spans the whole window: its
  // header starts after the window buttons and its content sits like a sheet.
  const sheet = isDesktop && !split;
  const sheetHeader = { inset: sheet ? lightsInset : 0 };
  const sheetContent = sheet ? layout.sheet : null;

  useEffect(() => {
    if (!split) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      // A dialog owns the keyboard while it is open.
      if (pendingRevoke !== null || document.querySelector('[aria-modal="true"]')) return;
      const shortcut = desktopShortcut(event, macDesktop);
      if (!shortcut) return;
      if (membersOpen) {
        if (shortcut !== "back") return;
        event.preventDefault();
        setMembersOpen(false);
        return;
      }
      if (shortcut === "back") {
        const target = dismissTarget();
        if (!target) return;
        event.preventDefault();
        go(target);
        return;
      }
      event.preventDefault();
      if (shortcut === "new-chat") go("new-chat");
      else if (shortcut === "settings") go("settings");
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  });

  function previewText(conversation: Conversation): string {
    if (conversation.blocked) return "Blocked";
    const last = previewOf(conversation);
    if (last) {
      const text = attachmentPreviewText(last);
      return last.direction === "sent" ? `You: ${text}` : text;
    }
    if (conversation.requestPending) return "Wants to start a conversation";
    return "Encrypted conversation";
  }

  // The state of a conversation worth a glyph beside its name, matching the
  // ones its row in the list carries. Everything is encrypted, so the
  // ordinary case shows nothing; a pending request has its banner in the thread.
  function conversationMark(conversation: Conversation) {
    if (conversation.blocked)
      return { icon: "block", color: colors.text3, label: "Blocked" } as const;
    if (conversation.keyChanged)
      return { icon: "warning", color: colors.warning, label: "Safety number changed" } as const;
    if (conversation.verified)
      return { icon: "shield", color: colors.success, label: "Safety number verified" } as const;
    return undefined;
  }

  function renderOnboarding() {
    return (
      <ScrollView
        contentContainerStyle={[styles.onboarding, isDesktop && styles.onboardingDesktop]}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        <Reveal>
          <AppGlyph size={isDesktop ? size.mark.sm : size.mark.md} />
        </Reveal>
        <Reveal delay={60} style={styles.heroBlock}>
          <Text accessibilityRole="header" style={type.largeTitle}>
            Private messaging,{"\n"}made simple.
          </Text>
          <Text style={type.body}>
            Pick a username and start talking. No phone number, no contact
            upload. Your private keys stay protected on your devices.
          </Text>
        </Reveal>
        <Reveal delay={120} style={styles.features}>
          <FeatureRow
            icon="lock"
            title="End-to-end encrypted"
            body="Only you and the people you write to can read your messages."
          />
          <FeatureRow
            icon="person"
            title="Just a username"
            body="Share your username without sharing your phone number."
          />
          <FeatureRow
            icon="shield"
            title="Verify your contacts"
            body="Compare safety numbers to rule out anyone in the middle."
          />
        </Reveal>
        {/* A phone pins the form to the bottom; a desktop window centres the whole column. */}
        {isDesktop ? null : <View style={layout.flex} />}
        <Reveal delay={180} style={layout.stackLoose}>
          {renderPhotoEditor(displayName || username, accountAvatar, setAccountAvatar)}
          <Field
            label="Choose your username"
            value={username}
            onChangeText={setUsername}
            placeholder="your_name"
            prefix="@"
            hint="3–32 lowercase letters, numbers, or underscores."
          />
          <Field
            label="Display name (optional)"
            value={displayName}
            onChangeText={setDisplayName}
            placeholder="What people call you"
            maxLength={96}
            hint="Shown to people you message. You can change it later."
          />
          <Actions>
            <Button label="Create account" disabled={busy || pickingPhoto} onPress={createAccount} />
            <Button
              label="Link an existing account"
              onPress={beginDeviceLink}
              variant="ghost"
            />
          </Actions>
        </Reveal>
      </ScrollView>
    );
  }

  function renderLinkDevice(request: Uint8Array) {
    return (
      <Page
        header={
          <Header
            title="Link this device"
            onBack={() => go("home")}
            backLabel="Cancel"
            {...sheetHeader}
          />
        }
      >
        <ScrollView contentContainerStyle={[layout.content, sheetContent]}>
          <QrLayout
            intro={
              <View style={layout.stack}>
                <Text style={type.title}>Bring your account along.</Text>
                <Text style={type.body}>
                  On your trusted device, open You → Linked devices and scan this
                  code.
                </Text>
              </View>
            }
            qr={<QrCard value={payloadQrValue("link-request", request)} />}
            details={
              <CodeBlock
                label="Match this code on both devices"
                value={linkSas}
                note="The request expires in 10 minutes."
              />
            }
            actions={
              <Actions>
                <Button
                  label={Platform.OS === "web" ? "Enter the approval code" : "Scan the approval code"}
                  icon="scan"
                  onPress={() => openScanner("link-authorization")}
                />
              </Actions>
            }
          />
        </ScrollView>
      </Page>
    );
  }

  function renderScanner() {
    return (
      <Page
        header={
          <Header
            title={Platform.OS === "web" ? "Enter a code" : "Scan a code"}
            onBack={backToScannerOrigin}
            backLabel="Cancel"
            {...sheetHeader}
          />
        }
      >
        {scannedProfile ? (
          <ScrollView
            contentContainerStyle={[layout.content, sheetContent]}
            keyboardShouldPersistTaps="handled"
          >
            <Hero
              name={parseProfileSummary(scannedProfile).username}
              colorSeed={hex(parseProfileSummary(scannedProfile).accountId)}
              title={`@${parseProfileSummary(scannedProfile).username}`}
              badge={<Badge label="Contact code captured" icon="check" />}
            />
            <Notice text="Compare safety numbers together after connecting." />
            <Field
              label="First message"
              multiline
              value={firstMessage}
              onChangeText={setFirstMessage}
              placeholder="Say hello…"
            />
            <Actions>
              <Button
                label="Send message request"
                disabled={!firstMessage.trim()}
                onPress={() => startWithProfile(scannedProfile, firstMessage)}
              />
              <Button
                label="Scan again"
                onPress={() => openScanner("contact")}
                variant="ghost"
              />
            </Actions>
          </ScrollView>
        ) : scannedLinkRequest ? (
          <ScrollView contentContainerStyle={[layout.content, sheetContent]}>
            <View style={layout.stack}>
              <Text style={type.title}>Do these codes match?</Text>
              <Text style={type.body}>
                Check the code shown on the new device before giving it access
                to your account.
              </Text>
            </View>
            {isDesktop ? (
              <CodeBlock label="The new device should show" value={linkSas} />
            ) : (
              <Card tone="accent" style={layout.center}>
                <CodeDisplay value={linkSas} />
              </Card>
            )}
            <Actions>
              <Button
                label="Authorize this device"
                icon="check"
                onPress={authorizeScannedDevice}
              />
              <Button
                label={Platform.OS === "web" ? "Reject and enter another code" : "Reject and scan again"}
                onPress={() => openScanner("link-request")}
                variant="ghost"
              />
            </Actions>
          </ScrollView>
        ) : Platform.OS === "web" ? (
          // Desktop has no camera, and reaches people by username, so the only
          // codes it reads are the ones that link devices: pasted as text.
          <ScrollView contentContainerStyle={[layout.content, sheetContent]}>
            <View style={layout.stack}>
              <Text style={type.title}>Paste the code from the other device</Text>
              <Text style={type.body}>
                On the other device, choose Show text code under the code, copy it, and paste
                it here.
              </Text>
            </View>
            <Field
              label="Device code"
              placeholder="Paste the code here"
              value={pastedCode}
              onChangeText={setPastedCode}
              multiline
            />
            <Actions>
              <Button
                label="Read code"
                disabled={!pastedCode.trim()}
                onPress={() => {
                  onQrScanned({ data: pastedCode.trim() });
                  setPastedCode("");
                }}
              />
            </Actions>
          </ScrollView>
        ) : !cameraPermission?.granted ? (
          <EmptyState
            icon="camera"
            title="Camera access"
            body="Camera frames never leave your device."
            action={
              <Button
                label="Allow camera"
                onPress={() => void requestCameraPermission()}
              />
            }
          />
        ) : (
          <View style={styles.camera}>
            <CameraView
              barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
              onBarcodeScanned={onQrScanned}
              style={StyleSheet.absoluteFill}
            />
            <Reticle hint="Hold the code inside the frame" />
          </View>
        )}
      </Page>
    );
  }

  // A new message is addressed in the middle of the screen, not in a header
  // row: the empty thread says what will happen to the first message, and the
  // recipient field sits under it as the one thing to fill in before writing.
  // A phone also offers the camera for a friend's contact code; the desktop
  // reaches people by username alone. Arriving with the recipient already
  // named, as from a group's member list, the message is the thing to write.
  function renderNewChat() {
    const addressed = contactUsername.trim().length > 0;
    return (
      <Page header={<Header title="New message" {...backTo("home")} />}>
        <ScrollView
          contentContainerStyle={[layout.centredScreen, { paddingBottom: composerHeight }]}
          keyboardShouldPersistTaps="handled"
        >
          <EmptyState
            icon="compose"
            title="Start a private conversation."
            body="Only they can accept your first message."
            action={
              Platform.OS === "web" ? undefined : (
                <Button
                  label="Scan a contact code"
                  icon="scan"
                  variant="ghost"
                  onPress={() => openScanner("contact")}
                />
              )
            }
          >
            <RecipientField
              value={contactUsername}
              onChangeText={setContactUsername}
              onSubmitEditing={() => firstMessageInput.current?.focus()}
              autoFocus={!addressed}
            />
          </EmptyState>
        </ScrollView>
        <Composer
          label="First message"
          sendLabel="Send message request"
          value={firstMessage}
          onChangeText={setFirstMessage}
          onSend={startByUsername}
          disabled={busy}
          sendDisabled={!addressed}
          placeholder="Write a message…"
          onHeightChange={setComposerHeight}
          inputRef={firstMessageInput}
          autoFocus={addressed}
          attachments={composerAttachments("new-chat")}
          onAttach={() => attachFile("new-chat")}
          onRemoveAttachment={unstageAttachment}
          dropping={dropping}
        />
      </Page>
    );
  }

  function renderAccount(currentProfile: Uint8Array) {
    return (
      <Page header={<Header title="My QR code" onBack={() => go("settings")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <QrLayout
            intro={
              <Hero
                name={ownName}
                avatar={ownAvatar}
                colorSeed={ownId}
                title={ownName}
                subtitle={`@${ownUsername} · Have a friend scan this to connect.`}
              />
            }
            qr={
              <QrCard
                value={profileQrValue(currentProfile)}
                caption="Only your public contact details are shared"
              />
            }
            details={
              <Notice text="Keep the whole code in view while it cycles. Verify safety numbers together after connecting." />
            }
          />
        </ScrollView>
      </Page>
    );
  }

  // The screen opens on who you are, as the people you message see it: the
  // photo (which is also how it is changed), the handle, and the ways to
  // share or clear them. Settings proper follow in groups.
  function renderSettings() {
    const activeDevices = devices?.devices.filter((device) => device.active).length;
    const setOwnPhoto = (avatar: string | undefined) => {
      if (ownId) updateAvatar(`user/${ownId}`, ownName, avatar);
    };
    const theme = appearanceOptions.find((option) => option.value === appearance);
    return (
      <Page header={<LargeHeader title="You" />}>
        <ScrollView contentContainerStyle={layout.contentTight}>
          <Hero
            name={ownName}
            leading={renderPhotoButton(ownName, ownAvatar, setOwnPhoto, { seed: ownId })}
            title={ownName}
            subtitle={`@${ownUsername} · People you message see this name and photo.`}
            actions={
              <>
                <Button
                  label="My QR code"
                  icon="qr"
                  variant="secondary"
                  size="sm"
                  onPress={() => go("account")}
                />
                {ownAvatar ? renderRemovePhoto(() => setOwnPhoto(undefined)) : null}
              </>
            }
          />
          <Section
            title="Account"
          >
            <RowGroup>
              <Row
                icon="person"
                title="Display name"
                subtitle={ownName}
                onPress={preview ? undefined : () => {
                  if (ownProfile) editName(`user/${hex(ownProfile.accountId)}`, ownName === ownUsername ? "" : ownName);
                }}
              />
              <Row
                icon="device"
                title="Linked devices"
                subtitle={
                  activeDevices
                    ? `${activeDevices} active ${activeDevices === 1 ? "device" : "devices"}`
                    : "Manage account access"
                }
                onPress={openDevices}
              />
              <Row
                icon="bell"
                title="Notifications"
                subtitle={pushError || pushSummary(pushStatus)}
                tone={pushStatus === "enabled" ? "muted" : "danger"}
                trailing={
                  <Toggle
                    label="Notifications"
                    value={pushStatus === "enabled" || pushStatus === "pending-bind"}
                    disabled={pushBusy || preview !== null}
                    // Flipping a switch stuck turning off retries the cleanup.
                    onValueChange={() =>
                      void updatePush(() =>
                        pushStatus === "pending-unbind"
                          ? recoverPushBinding(databasePath)
                          : pushStatus !== "disabled"
                            ? disablePushBinding(databasePath)
                            : enablePushBinding(databasePath),
                      )
                    }
                  />
                }
              />
              <Row
                icon="bell"
                title="Notifications show"
                subtitle={notificationPreviewOptions.find((option) => option.value === notificationPreview)?.label}
                trailing={
                  <Segmented
                    label="Notifications show"
                    options={notificationPreviewOptions}
                    value={notificationPreview}
                    onSelect={(chosen) => {
                      setNotificationPreview(chosen);
                      try { if (accountId) saveNotificationPreview(accountId, chosen); }
                      catch { setError("That choice couldn’t be saved. It applies until you restart."); }
                    }}
                  />
                }
              />
              <Row
                icon="checks"
                title="Read receipts"
                subtitle={readReceipts ? "People see when you’ve read their messages" : "Off. You won’t see theirs either"}
                trailing={
                  <Toggle
                    label="Read receipts"
                    value={readReceipts}
                    disabled={preview !== null || !accountId}
                    onValueChange={(enabled) => {
                      setReadReceipts(enabled);
                      try { if (accountId) saveReadReceipts(accountId, enabled); }
                      catch { setError("That choice couldn’t be saved. It applies until you restart."); }
                    }}
                  />
                }
              />
            </RowGroup>
          </Section>
          <Section title="Appearance">
            <RowGroup>
              <Row
                icon={theme?.icon}
                title="Theme"
                subtitle={theme?.label}
                trailing={
                  <Segmented label="Theme" options={appearanceOptions} value={appearance} onSelect={setAppearance} />
                }
              />
            </RowGroup>
          </Section>
          {isDevelopmentBuild() ? (
            <Section title="Development">
              <RowGroup>
                <Row
                  icon="chat"
                  title="Sample content"
                  subtitle="Read and unread chats and groups. Nothing is saved or sent."
                  trailing={
                    <Toggle label="Sample content" value={preview !== null} disabled={busy} onValueChange={toggleDevPreview} />
                  }
                />
                {isDesktop && onWindowsPreviewChange ? (
                  <Row
                    icon="device"
                    title="Windows UI"
                    subtitle="Preview the Windows title bar and window controls."
                    trailing={
                      <Toggle
                        label="Windows UI"
                        value={previewWindows}
                        disabled={changingWindowsUI}
                        onValueChange={async (enabled) => {
                          setChangingWindowsUI(true);
                          try { await onWindowsPreviewChange(enabled); }
                          catch { setError("Couldn’t change the window controls. Try again."); }
                          finally { setChangingWindowsUI(false); }
                        }}
                      />
                    }
                  />
                ) : null}
              </RowGroup>
            </Section>
          ) : null}
        </ScrollView>
      </Page>
    );
  }

  function renderDevices() {
    return (
      <Page header={<Header title="Linked devices" onBack={() => go("settings")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <Text style={type.body}>
            Only these devices can receive your messages. Remove any device you
            no longer trust.
          </Text>
          {devices?.changed ? (
            <Notice
              tone="warning"
              text="Your device list changed since your last review."
            />
          ) : null}
          {!devices?.canManage ? (
            <Notice text="Use your original device to link or remove other devices." />
          ) : null}
          {devices ? (
            <RowGroup>
              {devices.devices.map((device) => (
                <Row
                  key={hex(device.deviceId)}
                  icon="device"
                  tone={device.active ? (device.current ? "accent" : "muted") : "danger"}
                  title={
                    device.current
                      ? "This device"
                      : device.active
                        ? "Linked device"
                        : "Removed device"
                  }
                  subtitle={
                    device.current
                      ? "The device you’re using now"
                      : device.active
                        ? "Receives your messages"
                        : "No longer has access"
                  }
                  trailing={
                    devices.canManage && device.active && !device.current ? (
                      <Button
                        label="Remove"
                        variant="danger"
                        size="sm"
                        onPress={() => confirmRevoke(device.deviceId)}
                      />
                    ) : (
                      <Icon
                        name={device.active ? "check" : "close"}
                        color={device.active ? colors.success : colors.text3}
                        size={size.icon.lg}
                      />
                    )
                  }
                />
              ))}
            </RowGroup>
          ) : null}
          {devices?.canManage ? (
            <Actions>
              <Button
                label="Link another device"
                icon="scan"
                onPress={() => openScanner("link-request")}
              />
            </Actions>
          ) : null}
          <Text style={type.caption}>
            Removing a device is permanent. It would have to be linked again
            from scratch.
          </Text>
        </ScrollView>
      </Page>
    );
  }

  function renderLinkAuthorization(authorization: Uint8Array) {
    return (
      <Page
        header={
          <Header title="Approve the connection" onBack={() => go("devices")} backLabel="Close" />
        }
      >
        <ScrollView contentContainerStyle={layout.content}>
          <QrLayout
            intro={
              <View style={layout.stack}>
                <Text style={type.title}>One last scan.</Text>
                <Text style={type.body}>
                  Use the new device to scan this code. Only continue if the
                  codes match on both screens.
                </Text>
              </View>
            }
            qr={<QrCard value={payloadQrValue("link-authorization", authorization)} />}
            details={<CodeBlock label="Both screens should show" value={linkSas} />}
          />
        </ScrollView>
      </Page>
    );
  }

  function renderGroupPackage(keyPackage: Uint8Array) {
    return (
      <Page header={
        <Header
          title="Join a group"
          {...(isDesktop ? {} : backTo("groups"))}
          action={isDesktop ? (
            <IconButton
              name="close"
              label="Close join group"
              variant="tonal"
              size={size.avatar.xs}
              onPress={() => go(groupPackageOrigin)}
            />
          ) : undefined}
        />
      }>
        <ScrollView contentContainerStyle={layout.content}>
          <QrLayout
            intro={
              <View style={layout.stack}>
                <Text style={type.title}>You’re invited.</Text>
                <Text style={type.body}>
                  Ask a group member to scan this code from their group details to
                  add this device.
                </Text>
              </View>
            }
            qr={<QrCard value={payloadQrValue("group-key-package", keyPackage)} />}
            details={
              <Notice text="This invitation code is for this device only. Share a separate code for each linked device you want to add." />
            }
          />
        </ScrollView>
      </Page>
    );
  }

  // The group list itself, shared by the phone's Groups tab and the desktop
  // sidebar, where it marks the group open in the pane.
  function renderGroupList(sidebar: boolean) {
    const incoming = groupInvitations.filter((item) => item.state === 1 || item.state === 2);
    const openGroupId =
      sidebar && selectedGroupId && (screen === "group" || screen === "group-info")
        ? hex(selectedGroupId)
        : null;
    return (
      <FlatList
        contentContainerStyle={sidebar ? layout.sidebarList : layout.list}
        data={groups}
        keyExtractor={(group) => hex(group.groupId)}
        ListHeaderComponent={incoming.length ? (
          <View style={styles.listHeader}>
            <Section title="Invitations">
              {incoming.map((invitation) => (
                <Card key={hex(invitation.reference)}>
                  <Text style={type.headline}>{groupName(invitation.groupId)}</Text>
                  <Text style={type.body}>
                    {invitation.state === 1
                      ? `@${invitation.username} invited you. Accept to join on this device.`
                      : `Accepted. Joining when @${invitation.username} next connects.`}
                  </Text>
                  {invitation.state === 1 ? (
                    <View style={layout.row}>
                      <Button label="Accept" accessibilityLabel="Accept group invitation" size={sidebar ? "sm" : "md"} onPress={() => answerGroupInvitation(invitation, true)} />
                      <Button label="Decline" variant="ghost" size={sidebar ? "sm" : "md"} onPress={() => answerGroupInvitation(invitation, false)} />
                    </View>
                  ) : null}
                </Card>
              ))}
            </Section>
          </View>
        ) : null}
        ListEmptyComponent={sidebar ? <SidebarEmptyState title="No groups yet." /> : (
          <EmptyState
            icon="groups"
            title="No groups yet."
            body={`Ask a member to invite @${ownUsername}. Invitations appear here.`}
            action={<Button label="Start a group" onPress={createNewGroup} />}
          />
        )}
        renderItem={({ item }) => (
          <GroupRow
            name={groupName(item.groupId)}
            avatar={groupAvatar(item.groupId)}
            colorSeed={hex(item.groupId)}
            label={groupName(item.groupId)}
            subtitle={`${item.memberCount} ${item.memberCount === 1 ? "member" : "members"}`}
            unread={groupUnread(item)}
            selected={openGroupId === hex(item.groupId)}
            onPress={() => openGroup(item)}
          />
        )}
      />
    );
  }

  function renderGroups() {
    return (
      <Page
        header={
          <LargeHeader
            title="Groups"
            actions={
              <>
                <IconButton
                  label="Join with QR"
                  variant="tonal"
                  name="qr"
                  onPress={showGroupKeyPackage}
                />
                <IconButton
                  name="plus"
                  label="Create group"
                  variant="filled"
                  onPress={createNewGroup}
                />
              </>
            }
          />
        }
      >
        {renderGroupList(false)}
      </Page>
    );
  }

  // The group as the settings screen shows an account: its picture, tappable
  // by the creator to change it, over its name and who is in it; then the
  // ways to grow it, its people device by device, and the state they share.
  function renderGroupInfo(groupId: Uint8Array) {
    const name = groupName(groupId);
    const avatar = groupAvatar(groupId);
    const summary = groupDetails ? summarizeMembers(groupDetails.members) : null;
    const setGroupPhoto = (value: string | undefined) => updateAvatar(`group/${hex(groupId)}`, name, value);
    const canInvite = preview === null && groupUsername.trim().length > 0;
    const pending = [...new Map(groupInvitations
      .filter((item) => hex(item.groupId) === hex(groupId) && (item.state === 0 || item.state === 3))
      .map((item) => [hex(item.accountId), item])).values()];
    return (
      <Page header={<Header title="Group details" onBack={() => go("group")} />}>
        <ScrollView
          contentContainerStyle={layout.contentTight}
          keyboardShouldPersistTaps="handled"
        >
          <Hero
            name={name}
            avatar={avatar}
            colorSeed={hex(groupId)}
            group
            leading={isGroupCreator ? renderPhotoButton(name, avatar, setGroupPhoto, { group: true, seed: hex(groupId) }) : undefined}
            title={name}
            subtitle={summary ? describeMembers(summary) : "Loading members…"}
            actions={isGroupCreator && avatar ? renderRemovePhoto(() => setGroupPhoto(undefined)) : undefined}
          />
          <Section
            title="Invite someone"
            footer="They’ll receive an encrypted invitation and choose whether to join. Or scan the code from their Groups tab to add them right away."
          >
            <Card>
              {/* Desktop keeps the field and its actions on one line. */}
              <View style={isDesktop && styles.inviteRow}>
                <View style={isDesktop && [layout.flex, { minWidth: 180 }]}>
                  <Field
                    label="Exact username"
                    value={groupUsername}
                    onChangeText={setGroupUsername}
                    placeholder="their_name"
                    prefix="@"
                    autoFocus={focusInvite}
                  />
                </View>
                <Actions style={isDesktop ? { maxWidth: "100%" } : styles.inviteActions}>
                  <Button label="Send group invitation" disabled={!canInvite} onPress={inviteByUsername} />
                  <Button
                    label={isDesktop ? "Enter their code" : "Scan their code"}
                    icon="scan"
                    variant="ghost"
                    disabled={!canInvite}
                    onPress={scanGroupKeyPackage}
                  />
                </Actions>
              </View>
            </Card>
          </Section>
          <Section title="Members">
            {summary ? (
              <RowGroup>
                {summary.people.map((person) => {
                  const identity = senderIdentity(person.accountId, person.local);
                  const note = describeMember({ local: person.local, creator: identity.creator, conversation: identity.conversation });
                  return (
                    <Row
                      key={identity.accountId}
                      leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar.md} />}
                      title={identity.name}
                      subtitle={[note, person.devices > 1 ? `${person.devices} devices` : undefined].filter(Boolean).join(" · ") || undefined}
                      trailing={
                        person.local ? (
                          <Badge label="You" />
                        ) : identity.creator ? null : (
                          <Button
                            label="Remove"
                            accessibilityLabel={`Remove ${identity.name}`}
                            variant="secondary"
                            size="sm"
                            disabled={preview !== null}
                            onPress={() => removeFromGroup(person, identity.name)}
                          />
                        )
                      }
                    />
                  );
                })}
              </RowGroup>
            ) : (
              <Card style={layout.center}>
                <ActivityIndicator color={colors.accent} />
              </Card>
            )}
          </Section>
          {pending.length > 0 ? (
            <Section title="Invited" footer="They join once they accept.">
              <RowGroup>
                {pending.map((item) => (
                  <Row
                    key={hex(item.reference)}
                    leading={<Avatar name={`@${item.username}`} size={size.avatar.md} />}
                    title={`@${item.username}`}
                    subtitle={item.state === 3 ? "Finishing their invitation…" : "Waiting for them to accept"}
                    trailing={<Badge label={item.state === 3 ? "Joining" : "Invited"} tone={item.state === 3 ? "accent" : "muted"} />}
                  />
                ))}
              </RowGroup>
            </Section>
          ) : null}
        </ScrollView>
      </Page>
    );
  }

  // Who is in the group, a tap on its picture away: the people its devices
  // belong to, in the order they joined, each with what they are to you and
  // a way to message them on their own; then the ways to grow the group.
  function renderGroupMembers(groupId: Uint8Array) {
    const summary = groupDetails ? summarizeMembers(groupDetails.members) : null;
    const buttonSize = isDesktop ? "sm" : "md";
    return (
      <Dialog visible={membersOpen} label="Group members" onClose={() => setMembersOpen(false)}>
        <View style={styles.dialogHero}>
          <Avatar name={groupName(groupId)} uri={groupAvatar(groupId)} colorSeed={hex(groupId)} size={size.avatar["2xl"]} group />
          <Text numberOfLines={1} style={type.title2}>
            {groupName(groupId)}
          </Text>
          <Text style={type.subhead}>{summary ? describeMembers(summary) : "Loading members…"}</Text>
        </View>
        {summary ? (
          <ScrollView style={styles.memberList} contentContainerStyle={styles.memberListContent}>
            {summary.people.map((person) => {
              const identity = senderIdentity(person.accountId, person.local);
              // Someone known only by account has no name to address a message to.
              const reachable = !person.local && identity.username !== null;
              return (
                <Row
                  key={identity.accountId}
                  leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar.md} />}
                  title={identity.name}
                  subtitle={describeMember({ local: person.local, creator: identity.creator, conversation: identity.conversation })}
                  trailing={
                    person.local ? (
                      <Badge label="You" />
                    ) : reachable ? (
                      <IconButton
                        name="chat"
                        label={`Message ${identity.name}`}
                        variant="soft"
                        glass={false}
                        size={isDesktop ? control.sm : control.lg}
                        onPress={() => messageMember(identity)}
                      />
                    ) : null
                  }
                />
              );
            })}
          </ScrollView>
        ) : (
          <ActivityIndicator color={colors.accent} style={styles.memberListLoading} />
        )}
        <View style={styles.dialogActions}>
          <Button label="Invite someone" icon="plus" variant="secondary" size={buttonSize} onPress={inviteSomeone} />
          <Button label="Group details" variant="ghost" size={buttonSize} onPress={() => go("group-info")} />
        </View>
      </Dialog>
    );
  }

  function renderGroup(groupId: Uint8Array) {
    const mentionMembers = (groupDetails?.members ?? []).flatMap((member) => {
      const identity = senderIdentity(member.accountId, member.local);
      return identity.username ? [{ username: identity.username, name: identity.name }] : [];
    });
    const scope = `group/${hex(groupId)}`;
    const canReply = preview === null && (selectedGroup?.memberCount ?? 0) >= 2;
    // A quoted message is named by who this device knows sent it.
    const quoteOf = (message: Omit<GroupHistoryMessage, "reply">) => {
      const own = message.direction === "sent" || hex(message.senderAccountId) === accountId;
      const identity = senderIdentity(message.senderAccountId, own);
      return { name: own ? "You" : identity.name, accountId: identity.accountId, text: attachmentPreviewText(message) };
    };
    const answering = replyTarget && "senderAccountId" in replyTarget ? quoteOf(replyTarget) : undefined;
    return (
      <Page
        header={
          <ChatHeader
            name={groupName(groupId)}
            avatar={groupAvatar(groupId)}
            colorSeed={hex(groupId)}
            group
            {...backTo("groups", "Back to groups")}
            onAvatarPress={() => setMembersOpen(true)}
            avatarLabel="Group members"
            onInfo={() => go("group-info")}
            infoLabel="Group details"
          />
        }
      >
        {renderGroupMembers(groupId)}
        <FlatList
          ref={(list) => { thread.current = list; }}
          onScrollToIndexFailed={retryShowOriginal}
          inverted
          data={groupScope ? groupRows : []}
          contentContainerStyle={[layout.messages, { paddingTop: composerHeight + composerClearance }]}
          keyExtractor={(row) => row.key}
          ListEmptyComponent={
            <View style={styles.flipped}>
              <EmptyState
                icon="lock"
                title="Nothing here yet."
                body="Add people from group details to begin."
              />
            </View>
          }
          renderItem={({ item }) =>
            item.kind === "day" ? (
              <DayDivider label={item.label} />
            ) : (
              <MessageBubble
                body={item.message.body}
                mentionUsernames={mentionMembers.map((member) => member.username)}
                timestamp={item.message.timestamp}
                sent={item.message.direction === "sent" || (ownProfile !== null && hex(item.message.senderAccountId) === hex(ownProfile.accountId))}
                // Groups send no receipts. A linked device's message reached here, so it was sent.
                status={item.message.direction === "sent" ? messageStatus(item.message)
                  : ownProfile !== null && hex(item.message.senderAccountId) === hex(ownProfile.accountId) ? "sent" : undefined}
                tail={item.tail}
                spaced={item.spaced}
                enter={isFreshGroupMessage(item.key)}
                sender={senderIdentity(item.message.senderAccountId, item.message.direction === "sent")}
                attachments={item.message.attachments?.map((attachment) => bubbleAttachment(attachment, true))}
                reactions={item.message.reactions}
                reactionSender={accountId ?? ""}
                reactor={(sender) => senderIdentity(sender)}
                onReact={item.message.messageId ? (emoji) => reactToMessage(item.message, emoji) : undefined}
                reactionsDisabled={busy || preview !== null || (selectedGroup?.memberCount ?? 0) < 2}
                quote={item.message.reply && (item.message.reply.message
                  ? { ...quoteOf(item.message.reply.message), onPress: () => showOriginal(groupRows, item.message.reply!.target) }
                  : { text: "Original message unavailable" })}
                onReply={canReply && item.message.messageId
                  ? () => setReplying({ scope, target: hex(item.message.messageId!) }) : undefined}
                highlighted={flashKey === item.key}
              />
            )
          }
        />
        <Composer
          group
          mentionMembers={mentionMembers}
          value={groupComposer}
          onChangeText={setGroupComposer}
          onSend={sendGroupText}
          disabled={busy || preview !== null}
          placeholder={preview ? "Sample preview · read-only" : "Message · @mention someone"}
          sendDisabled={(selectedGroup?.memberCount ?? 0) < 2}
          onHeightChange={setComposerHeight}
          attachments={composerAttachments(scope)}
          onAttach={() => attachFile(scope)}
          onRemoveAttachment={unstageAttachment}
          dropping={dropping}
          reply={answering && { id: replying!.target, ...answering }}
          onCancelReply={() => setReplying(null)}
        />
      </Page>
    );
  }

  function renderChatInfo(conversation: Conversation) {
    const safety = describeSafety(conversation);
    return (
      <Page header={<Header title="Conversation details" onBack={() => go("chat")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <Hero
            name={contactName(conversation)}
            avatar={presentationOf(`user/${hex(conversation.peerAccountId)}`)?.avatar}
            colorSeed={hex(conversation.peerAccountId)}
            title={contactName(conversation)}
            subtitle={`@${conversation.username}`}
            badge={
              conversation.blocked ? (
                <Badge label="Blocked" tone="danger" icon="block" />
              ) : conversation.verified ? (
                <Badge label="Safety number verified" tone="success" icon="shield" />
              ) : null
            }
          />
          <Section title="Personalization">
            <RowGroup>
              <Row
                icon="person"
                title="Private nickname"
                subtitle={presentationOf(`nickname/${hex(conversation.peerAccountId)}`)?.name ?? "Only you see this, on this device."}
                onPress={preview ? undefined : () => editName(`nickname/${hex(conversation.peerAccountId)}`,
                  presentationOf(`nickname/${hex(conversation.peerAccountId)}`)?.name ?? "")}
              />
            </RowGroup>
          </Section>
          {/* The number is the exhibit: its state above it as a row, the way
              to act on it below, and the words about it under the card. */}
          <Section title="Security" footer={safety.note}>
            <RowGroup>
              <Row icon="shield" tone={safety.tone} title="Safety number" subtitle={safety.status} />
              {conversation.safetyNumber ? <SafetyNumber value={conversation.safetyNumber} tone={safety.tone} /> : null}
              {safety.verifiable ? (
                <Row
                  icon="check"
                  tone="success"
                  title="Mark as verified"
                  trailing={null}
                  onPress={() => updatePolicy(4)}
                />
              ) : null}
            </RowGroup>
          </Section>
          <Section
            title="Disappearing messages"
          >
            <RowGroup>
              <Row
                icon="timer"
                title="Timer"
                subtitle={disappearingOptions.find((option) => option.value === conversation.disappearingSeconds)?.label}
                trailing={
                  <Segmented
                    label="Disappear"
                    options={disappearingOptions}
                    value={conversation.disappearingSeconds}
                    onSelect={(seconds) => updatePolicy(5, seconds)}
                  />
                }
              />
            </RowGroup>
          </Section>
          <Section title="Privacy">
            <RowGroup>
              <Row
                icon="block"
                tone={conversation.blocked ? "muted" : "danger"}
                emphasis={conversation.blocked ? undefined : "danger"}
                title={conversation.blocked ? "Unblock contact" : "Block contact"}
                subtitle={
                  conversation.blocked
                    ? "You’ll receive their messages again."
                    : "They won’t be told, and their messages stop arriving."
                }
                onPress={() => updatePolicy(conversation.blocked ? 3 : 2)}
              />
            </RowGroup>
          </Section>
        </ScrollView>
      </Page>
    );
  }

  function renderChat(conversation: Conversation) {
    // Banners sit in flow under the floating header; the thread then starts
    // right below them instead of leaving room for the header a second time.
    const banners = conversation.requestPending || conversation.keyChanged || conversation.blocked;
    const scope = `chat/${conversation.conversationId.join(".")}`;
    const canReply = preview === null && !conversation.blocked && !conversation.requestPending;
    // Each side of a chat is named in its own colour, as group members are.
    const quoteOf = (message: Omit<HistoryMessage, "reply">) => ({
      name: message.direction === "sent" ? "You" : contactName(conversation),
      accountId: message.direction === "sent" ? ownId : hex(conversation.peerAccountId),
      text: attachmentPreviewText(message),
    });
    const answering = replyTarget && !("senderAccountId" in replyTarget) ? quoteOf(replyTarget) : undefined;
    return (
      <Page
        header={
          <ChatHeader
            name={contactName(conversation)}
            avatar={presentationOf(`user/${hex(conversation.peerAccountId)}`)?.avatar}
            colorSeed={hex(conversation.peerAccountId)}
            mark={conversationMark(conversation)}
            {...backTo("home", "Back to chats")}
            onInfo={() => go("chat-info")}
            infoLabel="Conversation details"
          />
        }
      >
        {banners ? (
          <View style={[styles.banners, isDesktop && layout.threadContent]}>
            {conversation.requestPending ? (
              <Card tone="accent">
                <Text style={type.headline}>Message request</Text>
                <Text style={type.body}>
                  @{conversation.username} wants to start a conversation. Accept to
                  reply, or block to never hear from them.
                </Text>
                {isDesktop ? (
                  <Actions>
                    <Button label="Accept request" onPress={() => updatePolicy(1)} />
                    <Button label="Block" variant="secondary" onPress={() => updatePolicy(2)} />
                  </Actions>
                ) : (
                  <View style={layout.row}>
                    <View style={layout.flex}>
                      <Button label="Accept request" onPress={() => updatePolicy(1)} />
                    </View>
                    <Button
                      label="Block"
                      variant="secondary"
                      onPress={() => updatePolicy(2)}
                    />
                  </View>
                )}
              </Card>
            ) : null}
            {conversation.keyChanged ? (
              <Notice
                tone="warning"
                text={`@${conversation.username}’s safety number changed. Compare it again before sending.`}
              />
            ) : null}
            {conversation.blocked ? (
              <Notice text="This contact is blocked. You can unblock them in conversation details." />
            ) : null}
          </View>
        ) : null}
        <FlatList
          ref={(list) => { thread.current = list; }}
          onScrollToIndexFailed={retryShowOriginal}
          inverted
          data={chatScope ? chatRows : []}
          contentContainerStyle={[
            layout.messages,
            { paddingTop: composerHeight + composerClearance },
            banners && styles.messagesBelowBanners,
          ]}
          keyExtractor={(row) => row.key}
          ListEmptyComponent={
            <View style={styles.flipped}>
              <EmptyState
                icon="chat"
                title="Say hello."
                body="Your messages are encrypted from the first word."
              />
            </View>
          }
          renderItem={({ item }) =>
            item.kind === "day" ? (
              <DayDivider label={item.label} />
            ) : (
              <MessageBubble
                body={item.message.body}
                timestamp={item.message.timestamp}
                sent={item.message.direction === "sent"}
                status={messageStatus(item.message, preview !== null || readReceipts,
                  preview ? undefined : receiptMarks[`chat/${hex(conversation.conversationId)}`])}
                disappearing={!!item.message.disappearingSeconds}
                reactions={item.message.reactions}
                reactionSender="sent"
                reactor={(sender) => sender === "sent"
                  ? { name: ownName, avatar: ownAvatar, accountId: ownId }
                  : {
                    name: contactName(conversation),
                    avatar: presentationOf(`user/${hex(conversation.peerAccountId)}`)?.avatar,
                    accountId: hex(conversation.peerAccountId),
                  }}
                onReact={(emoji) => reactToMessage(item.message, emoji)}
                reactionsDisabled={busy || preview !== null || conversation.blocked || conversation.requestPending}
                quote={item.message.reply && (item.message.reply.message
                  ? { ...quoteOf(item.message.reply.message), onPress: () => showOriginal(chatRows, item.message.reply!.target) }
                  : { text: "Original message unavailable" })}
                onReply={canReply ? () => setReplying({ scope, target: hex(item.message.messageId) }) : undefined}
                highlighted={flashKey === item.key}
                tail={item.tail}
                spaced={item.spaced}
                enter={isFreshMessage(item.key)}
                attachments={item.message.attachments?.map((attachment) => bubbleAttachment(
                  attachment,
                  !conversation.requestPending && !conversation.blocked,
                ))}
              />
            )
          }
        />
        <Composer
          value={composer}
          onChangeText={setComposer}
          onSend={sendMessage}
          disabled={busy || preview !== null || conversation.blocked || conversation.requestPending}
          placeholder={
            preview
              ? "Sample preview · read-only"
              : conversation.blocked
              ? "Contact blocked"
              : conversation.requestPending
                ? "Accept the request to reply"
                : "Message"
          }
          onHeightChange={setComposerHeight}
          attachments={composerAttachments(scope)}
          onAttach={() => attachFile(scope)}
          reply={answering && { id: replying!.target, ...answering }}
          onCancelReply={() => setReplying(null)}
          onRemoveAttachment={unstageAttachment}
          dropping={dropping}
        />
      </Page>
    );
  }

  // The conversation list, shared by the phone's Chats tab and the desktop
  // sidebar.
  function renderConversationList(sidebar: boolean) {
    const openId = sidebar && (screen === "chat" || screen === "chat-info") ? selectedId : null;
    return (
      <FlatList
        keyboardShouldPersistTaps="handled"
        keyboardDismissMode="on-drag"
        contentContainerStyle={sidebar ? layout.sidebarList : layout.list}
        data={homeItems}
        keyExtractor={(entry) => entry.key}
        ItemSeparatorComponent={
          sidebar
            ? null
            : ({ leadingItem }: { leadingItem: HomeItem }) =>
                leadingItem.kind === "chat" ? <ListSeparator /> : null
        }
        ListEmptyComponent={sidebar ? <SidebarEmptyState title="No chats yet." /> : (
          <EmptyState
            icon="chat"
            title="No conversations yet."
            body={
              Platform.OS === "web"
                ? "You will need their exact username."
                : "You will need their exact username, or their contact code."
            }
            action={
              <>
                <Button
                  label="New message"
                  icon="compose"
                  onPress={() => go("new-chat")}
                />
                {Platform.OS === "web" ? null : (
                  <Button
                    label="Scan a contact code"
                    variant="ghost"
                    onPress={() => openScanner("contact")}
                  />
                )}
              </>
            }
          />
        )}
        renderItem={({ item: entry }) => {
          if (entry.kind === "requests") {
            return (
              <RequestGroup count={entry.items.length}>
                {entry.items.map((request) => (
                  <RequestRow
                    key={hex(request.conversationId)}
                    name={contactName(request)}
                    avatar={presentationOf(`user/${hex(request.peerAccountId)}`)?.avatar}
                    colorSeed={hex(request.peerAccountId)}
                    preview={previewText(request)}
                    unread={chatUnread(request)}
                    onPress={() => openConversation(request)}
                    onAccept={() => acceptRequest(request)}
                  />
                ))}
              </RequestGroup>
            );
          }
          const last = previewOf(entry.item);
          return (
            <ConversationRow
              name={contactName(entry.item)}
              avatar={presentationOf(`user/${hex(entry.item.peerAccountId)}`)?.avatar}
              colorSeed={hex(entry.item.peerAccountId)}
              preview={previewText(entry.item)}
              time={last ? formatInboxTime(last.timestamp) : ""}
              unread={chatUnread(entry.item)}
              blocked={entry.item.blocked}
              verified={entry.item.verified}
              keyChanged={entry.item.keyChanged}
              selected={openId === entry.item.conversationId.join(".")}
              onPress={() => openConversation(entry.item)}
            />
          );
        }}
      />
    );
  }

  function renderHome() {
    return (
      <Page
        header={
          <LargeHeader
            title="Chats"
            actions={
              <>
                <IconButton
                  name="compose"
                  label="New conversation"
                  variant="filled"
                  onPress={() => go("new-chat")}
                />
              </>
            }
          />
        }
      >
        {renderConversationList(false)}
      </Page>
    );
  }

  // What the pane shows while the sidebar list is the selected screen.
  function renderPanePlaceholder(list: SidebarList) {
    return list === "chats" ? (
      <EmptyState
        icon="chat"
        title="Your messages"
        body="Choose a conversation from the sidebar."
        action={
          <Button label="New message" icon="compose" onPress={() => go("new-chat")} />
        }
      />
    ) : (
      <EmptyState
        icon="groups"
        title="Your groups"
        body="Choose a group from the sidebar."
        action={
          <View style={layout.row}>
            <Button label="Create group" icon="plus" onPress={createNewGroup} />
            <Button label="Join with a code" variant="ghost" onPress={showGroupKeyPackage} />
          </View>
        }
      />
    );
  }

  // The desktop sidebar: the list with the account at its foot, the list
  // switch and actions in a strip floating over its head beside the window
  // controls. The strip renders last so it paints over the scrolling rows.
  function renderSidebar() {
    const chats = sidebarList === "chats";
    return (
      <ResizableSidebar style={styles.sidebar}>
        <Glass pointerEvents="none" tint={colors.sidebarGlass} style={styles.sidebarGlass} fallback={styles.sidebarSurface} />
        <View style={layout.flex}>
          {chats ? renderConversationList(true) : renderGroupList(true)}
        </View>
        <AccountBar
          avatar={ownAvatar}
          name={ownUsername}
          colorSeed={ownId}
          active={sidebarSection(screen, scannerOrigin(scanMode)) === "you"}
          onSettings={() => go("settings")}
        />
        <SidebarChrome
          inset={lightsInset}
          tabs={
            <SegmentedControl
              segments={[
                { key: "chats", title: "Chats", icon: "chat", badge: chatBadgeCount },
                { key: "groups", title: "Groups", icon: "groups", badge: groupBadgeCount },
              ]}
              current={sidebarList}
              onSelect={(key) => go(key === "chats" ? "home" : "groups")}
            />
          }
          actions={
            chats ? (
              <IconButton
                name="compose"
                label="New conversation"
                variant="tonal"
                size={chrome.sidebarControl}
                onPress={() => go("new-chat")}
              />
            ) : (
              <>
                <IconButton
                  name="qr"
                  label="Join with a code"
                  variant="tonal"
                  size={chrome.sidebarControl}
                  onPress={showGroupKeyPackage}
                />
                <IconButton name="plus" label="Create group" variant="tonal" size={chrome.sidebarControl} onPress={createNewGroup} />
              </>
            )
          }
        />
        <View pointerEvents="none" style={styles.sidebarEdge} />
      </ResizableSidebar>
    );
  }

  function renderScreen() {
    if (!profile && screen !== "scanner" && screen !== "link-device")
      return renderOnboarding();
    if (screen === "link-device" && linkRequest) return renderLinkDevice(linkRequest);
    if (screen === "scanner") return renderScanner();
    if (screen === "new-chat") return renderNewChat();
    if (screen === "account" && profile) return renderAccount(profile);
    if (screen === "settings") return renderSettings();
    if (screen === "devices") return renderDevices();
    if (screen === "link-authorization" && linkAuthorization)
      return renderLinkAuthorization(linkAuthorization);
    if (screen === "group-package" && groupKeyPackage)
      return renderGroupPackage(groupKeyPackage);
    if (screen === "new-group") return renderNewGroup();
    if (screen === "groups") return split ? renderPanePlaceholder("groups") : renderGroups();
    if (screen === "group-info" && selectedGroupId) return renderGroupInfo(selectedGroupId);
    if (screen === "group" && selectedGroupId) return renderGroup(selectedGroupId);
    if (screen === "chat-info" && selected) return renderChatInfo(selected);
    if (screen === "chat" && selected) return renderChat(selected);
    return split ? renderPanePlaceholder("chats") : renderHome();
  }

  const ready = fontsReady && !initialLoading;
  const screenKey: ScreenKey =
    !profile && screen !== "scanner" && screen !== "link-device" ? "onboarding" : screen;
  const pane = (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      style={[layout.flex, isDesktop && screenKey === "onboarding" && styles.desktopOnboarding]}
    >
      <ScreenTransition
        screenKey={screenKey}
        direction={route.direction}
        style={layout.flex}
        pointerEvents={busy ? "none" : "auto"}
      >
        {renderScreen()}
      </ScreenTransition>
    </KeyboardAvoidingView>
  );
  // Status opens a lane of its own in the main column rather than floating
  // over it: above the screen on a phone, under the pane on the desktop.
  // Every error can be dismissed; an action's error goes first, then the
  // mailbox's.
  const statusPill = (
    <StatusPill
      text={error || (busy ? status : shownSyncError)}
      busy={busy && !error}
      error={error.length > 0 || shownSyncError.length > 0}
      onDismiss={() => (error ? setError("") : setDismissedSyncError(syncError))}
    />
  );
  const main = (
    <View style={layout.flex}>
      {isDesktop ? null : statusPill}
      {pane}
      {isDesktop ? statusPill : null}
    </View>
  );
  return (
    <SafeAreaProvider style={styles.screen}>
      {ready ? <>
      <StatusBar style={statusBar} />
      <SafeAreaView
        edges={
          mainScreen
            ? ["top", "left", "right"]
            : ["top", "left", "right", "bottom"]
        }
        style={[styles.screen, split && styles.split]}
      >
        {screenKey === "onboarding" ? <Glow /> : null}
        {/* Screens without a toolbar still need to move the window. */}
        {isDesktop && screenKey === "onboarding" ? <DragStrip /> : null}
        {split ? renderSidebar() : null}
        {main}
        {mainScreen && !split ? (
          <TabBar
            tabs={tabs.map((tab) => ({ ...tab, badge: tab.key === "home" ? chatBadgeCount : tab.key === "groups" ? groupBadgeCount : 0 }))}
            current={screen as (typeof tabs)[number]["key"]}
            onSelect={go}
          />
        ) : null}
      </SafeAreaView>
      {nameEditor ? (
        <Dialog visible label={nameEditorTitle} onClose={() => { if (!busy) setNameEditor(null); }}>
          <ScrollView contentContainerStyle={styles.nameEditor} keyboardShouldPersistTaps="handled">
            <Text accessibilityRole="header" style={[type.title2, { paddingRight: control.sm }]}>{nameEditorTitle}</Text>
            <Field
              label={nameEditorTitle}
              value={nameEditor.value}
              onChangeText={(value) => setNameEditor({ ...nameEditor, value })}
              placeholder={editingNickname ? "What you call them" : ownUsername}
              maxLength={96}
              autoFocus
              hint={editingNickname
                ? "Only you see this, on this device. Leave blank to use their shared name."
                : "Shared with your next message. Leave blank to use your username."}
            />
            {nameError ? <Notice text={nameError} tone="error" /> : null}
            <Actions>
              <Button label="Save" onPress={saveName} disabled={busy || preview !== null} />
              <Button label="Cancel" variant="ghost" disabled={busy} onPress={() => setNameEditor(null)} />
            </Actions>
          </ScrollView>
        </Dialog>
      ) : null}
      <Modal visible={pendingRevoke !== null} transparent onRequestClose={() => setPendingRevoke(null)}>
        <View style={styles.confirmOverlay}>
          <Card style={styles.confirmCard}>
            <Text style={type.title2}>Remove this device?</Text>
            <Text style={type.body}>It will permanently lose access to your account and future messages.</Text>
            <View style={styles.confirmActions}>
              <Button label="Cancel" variant="secondary" onPress={() => setPendingRevoke(null)} />
              <Button label="Remove device" variant="danger" onPress={() => {
                if (pendingRevoke) revokeLinkedDevice(pendingRevoke);
                setPendingRevoke(null);
              }} />
            </View>
          </Card>
        </View>
      </Modal>
      </> : null}
      <StartupScreen ready={ready} fontsReady={fontsReady} />
    </SafeAreaProvider>
  );
}

const useStyles = themed(({ colors, type, space, radius, size, elevation }) => StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.canvas },
  split: { flexDirection: "row" },
  // Narrow enough that a centred column clears the macOS window buttons at
  // the window's minimum width.
  desktopOnboarding: { width: "100%", maxWidth: 560, alignSelf: "center" },
  sidebar: {
    borderRadius: radius.xl,
    overflow: "hidden",
    ...elevation.glass,
  },
  // The toolbar's frost blurs whatever lies under it, the pane's own hairline
  // included, which erased the top-left corner. So the hairline is drawn
  // last, over the content, and the glass sits a pixel outside the clip to
  // keep its own edge out of sight.
  sidebarGlass: { position: "absolute", top: -1, right: -1, bottom: -1, left: -1, borderRadius: radius.xl + 1 },
  sidebarSurface: { backgroundColor: colors.sidebar },
  sidebarEdge: {
    ...StyleSheet.absoluteFill,
    borderRadius: radius.xl,
    borderWidth: 1,
    borderColor: colors.glassLine,
  },
  confirmOverlay: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.scrim,
    padding: space[6],
  },
  // An alert's measure: wide enough for a sentence, never a full pane.
  confirmCard: { maxWidth: 420, width: "100%", gap: space[4] },
  nameEditor: { paddingHorizontal: space[5], gap: space[4] },
  // A desktop alert puts its buttons in a row with the confirming action last.
  confirmActions: isDesktop
    ? { flexDirection: "row", justifyContent: "flex-end", gap: space[2], marginTop: space[1] }
    : { gap: space[2.5] },
  onboarding: {
    flexGrow: 1,
    paddingHorizontal: space[6],
    paddingTop: space[3],
    paddingBottom: space[4],
    gap: space[5],
  },
  onboardingDesktop: {
    justifyContent: "center",
    paddingTop: TOOLBAR_HEIGHT + space[4],
    paddingBottom: space[12],
    gap: space[6],
  },
  heroBlock: { gap: space[2.5] },
  features: { gap: space[4] },
  // Full bleed: the header floats over the feed and the reticle frames it.
  camera: { flex: 1, backgroundColor: colors.black },
  photoEditor: { flexDirection: "row", alignItems: "center", gap: space[3] },
  // On desktop the form is a sheet: a narrow column centred in the pane, with
  // the toolbar's height mirrored below so the centre is optical.
  newGroup: isDesktop
    ? { maxWidth: 440, justifyContent: "center", paddingBottom: chrome.header + space[3] }
    : { paddingTop: chrome.header + space[6] },
  newGroupPhoto: { alignItems: "center", gap: space[2], marginBottom: space[1] },
  newGroupNote: { textAlign: "center" },
  // The members dialog: the group's identity, its people, then the actions,
  // all sharing one margin; the rows bring their own inner padding.
  dialogHero: { alignItems: "center", gap: space[1.5], paddingHorizontal: space[5], paddingBottom: space[3] },
  memberList: { flexGrow: 0 },
  memberListContent: { paddingHorizontal: space[2] },
  memberListLoading: { paddingVertical: space[6] },
  // A sheet stacks its buttons edge to edge, the main one first; a desktop
  // dialog sets them at their natural width, trailing, as alerts do, with
  // the main one at the outer edge, so the order reverses.
  dialogActions: isDesktop
    ? { flexDirection: "row-reverse", gap: space[2], paddingHorizontal: space[5], paddingTop: space[3] }
    : { gap: space[2.5], paddingHorizontal: space[5], paddingTop: space[4] },
  inviteRow: { flexDirection: "row", flexWrap: "wrap", alignItems: "flex-end", gap: space[2] },
  inviteActions: { marginTop: space[3] },
  banners: { paddingTop: chrome.chatHeader + space[2], paddingHorizontal: space[4], gap: space[2.5] },
  messagesBelowBanners: { paddingBottom: space[2.5] },
  listHeader: { paddingHorizontal: space[2.5], paddingBottom: space[3] },
  flipped: { flex: 1, transform: [{ scaleY: -1 }] },
}));
