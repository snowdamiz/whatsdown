import {
  BarcodeScanningResult,
  CameraView,
  useCameraPermissions,
} from "expo-camera";
import { StatusBar } from "expo-status-bar";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { encodeReaction, setReaction } from "./reactions";
import {
  LEAVE_REQUEST,
  MAX_ADMINS,
  authorities,
  departures,
  encodeLeft,
  leftBy,
  communityId,
  deviceRequests,
  encodeDeviceRequest,
  encodeJoinRequest,
  fromHex,
  indexCommunities,
  joinRequests,
  mergeParts,
  pickPart,
  sameRecord,
  withRoles,
  type Community,
  type CommunityEntry,
  type Copy,
  type JoinRequest,
} from "./communities";
import { encodeReply } from "./replies";
import { encodeReceipt, messageStatus, receiptDue, type ReceiptMarks } from "./receipts";
import {
  ActivityIndicator,
  Alert,
  Clipboard,
  AppState,
  BackHandler,
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
import { SafeAreaProvider, SafeAreaView, initialWindowMetrics } from "react-native-safe-area-context";

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
  discardPreviews,
  listenForIncomingFiles,
  pickAttachmentFiles,
  releasePreviewUri,
  saveAttachmentFile,
  saveAttachmentStream,
} from "./attachment-io";
import {
  attachmentCreditCost,
  attachmentPreviewText,
  attachmentSelectionError,
  closedPreviews,
  composerScope,
  creditShortfall,
  creditSpendPrompt,
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
  FREE_ATTACHMENT_SIZE,
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
import { purgeDelay, timerLength, timerNotice, viewOnceCaution, viewOnceText } from "./ephemeral";
import { checkSafetyCode, groupTimer, openGroupViewOnce, openViewOnce, purgeExpired, safetyCode } from "./ephemeral-native";
import { SafetyCodeDialog, ViewOnceDialog, type ViewOnceOpened } from "./EphemeralDialogs";
import { AppLockRow } from "./LockGate";
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
  RemovedFromAccount,
  addGroupMember,
  forgetGroup,
  acceptGroupInvitation,
  declineGroupInvitation,
  inviteToGroup,
  listGroupInvitations,
  authorizeDeviceLink,
  drainOutbox,
  createGroup,
  connectMailboxStream,
  creditBalance,
  deleteAccount,
  downloadAttachment,
  eraseAccount,
  forgetOnProof,
  getGroupKeyPackage,
  GROUP_KEY_PACKAGE_LENGTH,
  holdsAccountKey,
  inspectGroup,
  listGroups,
  loadAccountDevices,
  loadGroupHistory,
  loadNetworkStatus,
  loadTrustDetails,
  onAccountChangedWhileAway,
  onPublicRecordChecked,
  schedulePublicRecordCheck,
  onUndeliverable,
  registerDirectory,
  type Removal,
  removeGroupMember,
  revokeDevice,
  sendFanout,
  sendGroupMessage,
  sendGroupViewOnce,
  sendViewOnce,
  setGroupTimer,
  sendWithAttachments,
  streamAttachment,
  type OutgoingAttachment,
} from "./network";
import {
  disablePushBinding,
  enablePushBinding,
  forgetPush,
  getPushStatus,
  listenForGenericWakeups,
  listenForNotificationOpens,
  listenForPushRegistrationChanges,
  recoverPushBinding,
  type PushStatus,
} from "./push";
import { createQrCollector } from "./qr";
import { databasePath } from "./storage";
import { CreditPrompts, CreditsRow, CreditsScreen, InboxPriceRow } from "./CreditsScreen";
import { BackupsRow, BackupsScreen } from "./BackupsScreen";
import { backUpIfDue } from "./backup-app-state";
import type { AppState as BackupAppState } from "./backup-model.ts";
import { installCredits } from "./credits";
import { receivedMessageKeys, unreadCount, type ReadState } from "./read-state";
import { forgetPreferences, loadDeclinedRequests, loadNotificationPreview, loadReadReceipts, loadReadState, loadReceiptMarks, saveDeclinedRequests, saveNotificationPreview, saveReadReceipts, saveReadState } from "./read-state-store";
import {
  encodeCommunityAnswer,
  encodeCommunityLink,
  encodeCommunityRequest,
  ownRequests,
  parseCommunityLink,
  unansweredRequests,
  type CommunityLink,
  type UnansweredRequest,
} from "./community-requests";
import type { NotificationPreview } from "./notification-policy";
import { describeSafety } from "./safety";
import { sessionResetNotice } from "./session-reset";
import { keyCheckedLine, profileLine, witnessNote, type NetworkStatus } from "./witnesses";
import {
  base58,
  bondCounterLine,
  checkResultLine,
  forkTarget,
  forkTargetLine,
  trustBanner,
  witnessBondLine,
  type TrustDetails,
} from "./public-record";
import { Fact, IdentityPreview, SealedChat, Steps, Strong } from "./onboarding";
import { usernameProblem } from "./username";
import { StartupScreen } from "./StartupScreen";
import { ResizableSidebar } from "./ResizableSidebar";
import { BountyNoticeCard, CollectBountiesRow, WalletScreen } from "./WalletScreen";
import { setFinderAddressSource } from "./network";
import { walletFinderAddress } from "./wallet-store";

// A fork proof names one of the wallet's bounty addresses when the person collects
// fork bounties (plan §6.3, §10); otherwise its finder field stays zero.
setFinderAddressSource(walletFinderAddress);
// Credits pay for postage, storage, busy sign-ups and large files (plan §6.10).
installCredits(databasePath);
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
  ViewOnceBubble,
  Dialog,
  DragStrip,
  EmptyState,
  Field,
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
  Tap,
  Toggle,
  useFreshKeys,
  Wallpaper,
  WallpaperFrame,
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
// A destructive action, held until it is confirmed.
type Confirmation = { title: string; body: string; action: string; run: () => void };
// Why a device erased itself, said on the screen it starts over on.
const removalNotices: Record<Removal, string> = {
  "account-deleted": "Your account was deleted on another device, so its messages and keys were erased from this one too.",
  "device-removed": "This device was removed from your account on another device, so its messages and keys were erased from it.",
  "device-left": "This device left your account, so its messages and keys were erased from it.",
};

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

export default function App({ windowsPreview = false, onWindowsPreviewChange, onAccountErased, notice, updates }: {
  windowsPreview?: boolean;
  onWindowsPreviewChange?: (enabled: boolean) => Promise<void>;
  // The desktop shell's own settings section; phones update through their store.
  updates?: ReactNode;
  // Starts the app over with nothing in memory: erasing the account empties
  // storage, not state. The notice says why, on the screen it starts over on.
  onAccountErased: (notice?: string) => void;
  notice?: string;
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
  const [pendingConfirm, setPendingConfirm] = useState<Confirmation | null>(null);
  // Where the main column and the pane inside it were laid out, so the
  // floating edges on a screen can line their doodles up with the wallpaper.
  const [mainFrame, setMainFrame] = useState({ x: 0, y: 0, height: 0 });
  const [paneOffset, setPaneOffset] = useState({ x: 0, y: 0 });
  // Set while the account is being deleted, which stops syncing and push upkeep first.
  const [leaving, setLeaving] = useState(false);
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
  // Until there is an account the pane belongs to onboarding, except while
  // it has pushed the scanner or the device-linking screen over it.
  const onboardingActive = !profile && screen !== "scanner" && screen !== "link-device" && screen !== "backups";
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
  // The witness set this build pins (Settings -> Network, safety numbers), and
  // whether this device's own account changed while it was away.
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(null);
  const [accountAway, setAccountAway] = useState(false);
  // Settings -> Network -> Details: each trust alarm's evidence and filings.
  const [trustDetails, setTrustDetails] = useState<TrustDetails[] | null>(null);
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
  // The last name the directory refused at signup.
  const [takenUsername, setTakenUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  // Onboarding is two screens — what the app is, then who you are — so
  // neither has to scroll. Moving between them steers the same transition the
  // route does, since only one of the two ever changes at a time.
  const [onboardingStep, setOnboardingStep] = useState<"welcome" | "profile">("welcome");
  const goOnboarding = (step: "welcome" | "profile") => {
    setOnboardingStep(step);
    setRoute((current) => ({
      ...current,
      direction: step === "profile" ? "forward" : "backward",
    }));
  };
  const [nameEditor, setNameEditor] = useState<{ key: string; value: string } | null>(null);
  const [nameError, setNameError] = useState("");
  const editingNickname = nameEditor?.key.startsWith("nickname/") ?? false;
  const nameEditorTitle = editingNickname ? "Private nickname" : "Display name";
  const [pickingPhoto, setPickingPhoto] = useState(false);
  const [accountAvatar, setAccountAvatar] = useState<string>();
  // Every other avatar hashes its colour from an account or group ID; before
  // an account exists there is none, and hashing the name instead repainted
  // the placeholder on every keystroke. So it draws one tone at random and
  // keeps it, while the initials go on following what is typed.
  const [avatarSeed] = useState(() => Math.random().toString(36).slice(2));
  const [presentations, setPresentations] = useState<Record<string, Presentation | undefined>>({});
  const [groupDraftName, setGroupDraftName] = useState("");
  const [groupDraftAvatar, setGroupDraftAvatar] = useState<string>();
  // A new community starts as a group whose record also lists its linked groups.
  const [draftCommunity, setDraftCommunity] = useState(false);
  const [groupDraftAbout, setGroupDraftAbout] = useState("");
  // The owner's unsaved edit of the open community's description.
  const [aboutDraft, setAboutDraft] = useState<string | null>(null);
  // Who is in each group linked to the open community, for its owner to see which requests are done.
  const [linkedMembers, setLinkedMembers] = useState<Record<string, string[]>>({});
  // Every part of the open community this device is in: who is there and what was said.
  const [communityParts, setCommunityParts] = useState<Record<string, { details: GroupDetails; messages: GroupHistoryMessage[] }>>({});
  // The person whose role the owner is changing, in a dialog over the community's details.
  const [managing, setManaging] = useState<string | null>(null);
  // A community link read from a code, waiting for this account to ask to join.
  const [scannedCommunity, setScannedCommunity] = useState<CommunityLink | null>(null);
  // Requests to join a community this admin declined, by the chat they came in.
  const [declinedRequests, setDeclinedRequests] = useState<Record<string, string[]>>({});
  // The request to join a community an admin is answering.
  const [reviewing, setReviewing] = useState<{ conversation: Conversation; request: UnansweredRequest } | null>(null);
  // Invitations this session already accepted because an approved request led to them.
  const acceptedApprovals = useRef(new Set<string>());
  // Devices this session already added to a part, so a slow welcome is not answered twice.
  const addedDevices = useRef(new Set<string>());
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
  // Disappearing and view-once messages, and safety codes (ephemeral.ts).
  const [viewOnceScope, setViewOnceScope] = useState<string | null>(null);
  const [viewing, setViewing] = useState<ViewOnceOpened | null>(null);
  const viewingOpen = useRef(false);
  const [groupTimers, setGroupTimers] = useState<Record<string, number>>({});
  const [safetyCodeOpen, setSafetyCodeOpen] = useState(false);
  const [safetyCodeValue, setSafetyCodeValue] = useState<string | null>(null);
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
  // "Restore from a backup" links this device first, then asks for the code.
  const [restoreAfterLink, setRestoreAfterLink] = useState(false);
  const [backupStart, setBackupStart] = useState<"status" | "restore" | "recover">("status");
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
        : screen === "group" && selectedGroupId ? threadScope(hex(selectedGroupId)) : null
      : null, readReceipts);
    return () => setActiveNotificationScope(null);
  }, [foreground, preview, membersOpen, screen, selected, selectedGroupId, presentations, readReceipts]);

  useEffect(() => listenForNotificationOpens(setNotificationTarget), []);
  useEffect(() => {
    if (!notificationTarget || preview) return;
    const chat = conversations.find((item) => notificationTarget === `chat/${hex(item.conversationId)}`);
    const group = groups.find((item) => notificationTarget === threadScope(hex(item.groupId)));
    if (chat) openConversation(chat);
    else if (group) openGroup(group);
    else return;
    setNotificationTarget(null);
  }, [notificationTarget, conversations, groups, preview]);

  // Backups, once they are on, are made once a day while the app is open.
  useEffect(() => {
    if (!accountId || preview) return;
    void backUpIfDue();
    const timer = setInterval(() => { void backUpIfDue(); }, 3_600_000);
    return () => clearInterval(timer);
  }, [accountId, preview]);

  // A restore brings settings and read marks with it; show them at once.
  function backupRestored(settings: BackupAppState | null): void {
    if (settings) {
      setAppearance(settings.appearance);
      setReadReceipts(settings.readReceipts);
      setNotificationPreview(settings.notificationPreview);
      setReadState(settings.readState);
      setReceiptMarks(settings.receiptMarks);
    }
    void refreshLocalData().catch(() => {});
  }

  useEffect(() => {
    if (!accountId) return;
    let current = true;
    // The journals and settings are sealed in the database, so they come back a
    // moment after the account. Unread counts wait for them.
    void (async () => {
      try {
        const [read, marks, receipts, previews] = await Promise.all([
          loadReadState(accountId),
          loadReceiptMarks(accountId),
          loadReadReceipts(accountId),
          loadNotificationPreview(accountId),
        ]);
        if (!current) return;
        setReadState(read);
        setReceiptMarks(marks);
        setReadReceipts(receipts);
        setNotificationPreview(previews);
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
        ? threadScope(groupHistoryFor) : null;
    if (!scope) return;
    // A community's thread is what its owner and admins posted across its parts.
    const keys = receivedMessageKeys(screen === "chat" ? history : selectedEntry ? communityPosts : groupHistory, accountId);
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
    historyFor, groupHistoryFor, history, groupHistory, communityParts, preview, previewReadState, readState, readReceipts]);

  const read = preview ? previewReadState : readState;
  // Until the sealed journal is back, nothing is known to be unread: better no
  // badge for a moment than every chat flashing as new.
  const readKnown = preview !== null || readAccount === accountId;
  const chatUnread = (conversation: Conversation) => conversation.blocked || !readKnown ? 0 : unreadCount(
    receivedMessageKeys((preview?.histories ?? previews)[hex(conversation.conversationId)] ?? []),
    read[`chat/${hex(conversation.conversationId)}`],
  );
  // Sample content merges a community's parts here; real ones arrive merged.
  const threadHistory = (group: GroupSummary) => {
    const entry = communityOfGroup(hex(group.groupId));
    if (preview && entry) {
      return mergeParts(entry.parts.flatMap((part) => preview.groupHistories[part] ? [{ id: part, messages: preview.groupHistories[part]! }] : []),
        authorities(entry.community));
    }
    return (preview?.groupHistories ?? groupPreviews)[threadScope(hex(group.groupId)).slice(6)] ?? [];
  };
  const groupUnread = (group: GroupSummary) => !readKnown ? 0 : unreadCount(
    receivedMessageKeys(threadHistory(group), accountId ?? undefined),
    read[threadScope(hex(group.groupId))],
  );

  function toggleDevPreview(enabled: boolean): void {
    if (!isDevelopmentBuild() || busy) return;
    let nextPreview: DevPreview | null = null;
    // Keep build constants beside require so Metro excludes the fixtures from releases.
    if (__DEV__ || (process.env.EXPO_OS === "web" && process.env.EXPO_PUBLIC_DESKTOP_DEVELOPMENT === "true")) {
      if (enabled) nextPreview = (require("./dev-preview") as typeof import("./dev-preview")).createDevPreview(Date.now(), ownProfile?.accountId);
    }
    setDevPreview(nextPreview);
    setPreviewReadState(nextPreview?.readState ?? {});
    setSelectedId(null);
    setSelectedGroupId(null);
    setComposer("");
    setGroupComposer("");
    setError("");
  }

  async function refreshPresentations(keys: string[]): Promise<Record<string, Presentation | undefined>> {
    const allKeys = keys.flatMap((key) => key.startsWith("user/") ? [key, `nickname/${key.slice(5)}`] : [key]);
    const entries = await Promise.all([...new Set(allKeys)].map(async (key) => [key, await loadPresentation(databasePath, key)] as const));
    const loaded = Object.fromEntries(entries);
    setPresentations((previous) => ({ ...previous, ...loaded }));
    return loaded;
  }

  const presentationOf = (key: string) => preview?.presentations[key] ?? presentations[key];
  const contactName = (contact: Conversation) => identityName(contact.username,
    presentationOf(`user/${hex(contact.peerAccountId)}`), presentationOf(`nickname/${hex(contact.peerAccountId)}`))!;
  // A group you are not in yet is named by the community that lists it.
  const linkedName = (id: string) => Object.values(preview?.presentations ?? presentations)
    .flatMap((item) => item?.community?.groups ?? []).find((group) => group.id === id)?.name;
  const groupName = (id: Uint8Array) => presentationOf(`group/${hex(id)}`)?.name ?? linkedName(hex(id)) ??
    communityAsks.find((ask) => ask.state === "approved" && ask.part === hex(id))?.name ?? `Group ${hex(id).slice(0, 6)}`;
  const groupAvatar = (id: Uint8Array) => presentationOf(`group/${hex(id)}`)?.avatar;
  // Communities are shown once, by their first part this device is in.
  const communityIndex = indexCommunities(groups.map((group) => hex(group.groupId)), (id) => presentationOf(`group/${id}`));
  const communityOfGroup = (id: string) => [...communityIndex.values()].find((entry) => entry.parts.includes(id));
  const selectedEntry = selectedGroupId ? communityOfGroup(hex(selectedGroupId)) : undefined;
  // A community keeps one thread, read state and notifications under its own ID,
  // whichever of its parts this device is in.
  const threadScope = (id: string) => {
    const entry = communityOfGroup(id);
    return `group/${entry ? communityId(entry.community) : id}`;
  };
  const listedGroups = groups.filter((group) => (communityOfGroup(hex(group.groupId))?.parts[0] ?? hex(group.groupId)) === hex(group.groupId));
  // A community's size is for those who run it, in its details.
  const groupSubtitle = (group: GroupSummary) => communityOfGroup(hex(group.groupId)) ? "Community"
    : `${group.memberCount} ${group.memberCount === 1 ? "member" : "members"}`;
  // A community's latest is its latest announcement, never a request hidden in a part.
  const groupLast = (group: GroupSummary) => threadHistory(group).at(-1);
  // A group's row shows its latest words as a conversation's does: yours
  // marked as yours, anyone else's by name where the name is known. A
  // community's row keeps saying what it is.
  function groupPreviewText(group: GroupSummary): string {
    const last = groupLast(group);
    if (!last || communityOfGroup(hex(group.groupId))) return groupSubtitle(group);
    const text = attachmentPreviewText(last);
    if (last.direction === "sent") return `You: ${text}`;
    const id = hex(last.senderAccountId);
    const contact = conversations.find((item) => hex(item.peerAccountId) === id);
    const name = identityName(contact?.username ?? null, presentationOf(`user/${id}`), presentationOf(`nickname/${id}`));
    return name ? `${name}: ${text}` : text;
  }
  const selectedCommunity = selectedEntry?.community;
  const communityAuthority = selectedCommunity ? authorities(selectedCommunity) : new Set<string>();
  // Sample content stands in for the parts' rosters and histories.
  const communityData: typeof communityParts = preview && selectedEntry
    ? Object.fromEntries(selectedEntry.parts.flatMap((part) => preview.groupDetails[part] && preview.groupHistories[part]
      ? [[part, { details: preview.groupDetails[part]!, messages: preview.groupHistories[part]! }]] : []))
    : communityParts;
  const communityHeard = selectedEntry ? selectedEntry.parts.flatMap((part) => communityData[part]?.messages ?? []) : [];
  const communityPosts = selectedEntry ? mergeParts(selectedEntry.parts.flatMap((part) =>
    communityData[part] ? [{ id: part, messages: communityData[part]!.messages }] : []), communityAuthority) : [];
  // Asking to join from outside travels in direct chats: what this account asked
  // to join and has not joined yet, with who it asked.
  const chatHistories = preview?.histories ?? previews;
  const communityAsks = conversations.flatMap((conversation) =>
    ownRequests(chatHistories[hex(conversation.conversationId)] ?? []).map((request) => ({ ...request, conversation })))
    .filter((request) => !communityIndex.has(request.community));
  const readCommunityLink = (value: string): CommunityLink | undefined => {
    try { return parseCommunityLink(decodeUtf8(payloadFromQr(value.trim(), "community", 1_024))); }
    catch { return undefined; }
  };

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
    const loaded = await refreshPresentations(next.map((group) => `group/${hex(group.groupId)}`));
    const histories: Record<string, GroupHistoryMessage[]> = {};
    await Promise.all(next.map(async (group) => {
      try {
        histories[hex(group.groupId)] = await loadGroupHistory(databasePath, group.groupId);
      } catch {
        // Keep the last known count if this group's history is unavailable.
      }
    }));
    // A community counts as one thread: its first part holds what every part heard.
    const index = indexCommunities(next.map((group) => hex(group.groupId)), (id) => loaded[`group/${id}`]);
    const parts = new Set([...index.values()].flatMap((entry) => entry.parts));
    const previews = Object.fromEntries(Object.entries(histories).filter(([id]) => !parts.has(id)));
    for (const entry of index.values()) {
      const held = entry.parts.filter((part) => histories[part]);
      if (held.length) previews[communityId(entry.community)] = mergeParts(held.map((part) => ({ id: part, messages: histories[part]! })), authorities(entry.community));
    }
    setGroupPreviews((previous) => ({ ...previous, ...previews }));
    // The list names whoever spoke last in each group.
    void refreshPresentations(Object.values(previews).flatMap((messages) => {
      const last = messages.at(-1);
      return last?.direction === "received" ? [`user/${hex(last.senderAccountId)}`] : [];
    })).catch(() => undefined);
    // Announce identities after joining or changing membership; empty messages stay out of history.
    for (const group of next) {
      const key = hex(group.groupId);
      if (group.memberCount > 1 && advertisedGroups.current.get(key) !== group.epoch) {
        await group_send_export(vectors(utf8(databasePath), group.groupId, utf8("")));
        advertisedGroups.current.set(key, group.epoch);
        await drainOutbox(databasePath);
      }
    }
    // Read here, not from state: a sync may run this from an earlier render.
    const own = index.size ? hex(parseProfileSummary(await load_profile_export(utf8(databasePath))).accountId) : "";
    // Leaving on one device leaves on them all: the others forget the community when they hear it.
    const forgotten = [...index.values()].filter((entry) => entry.community.owner !== own &&
      entry.parts.some((part) => leftBy(histories[part] ?? [], own))).flatMap((entry) => entry.parts);
    for (const part of forgotten) await forgetGroup(databasePath, fromHex(part));
    if (forgotten.length) setGroups(next.filter((group) => !forgotten.includes(hex(group.groupId))));
    for (const entry of index.values()) {
      if (entry.parts.some((part) => forgotten.includes(part))) continue;
      try { await maintainCommunity(own, entry, histories, loaded); }
      catch { /* The next refresh tries again. */ }
    }
    return next;
  }

  // An owner's or admin's device belongs in every part of the community, so its
  // posts reach everyone. A device missing a part asks for it, one part at a
  // time; the owner's or admin's device that joined that part first adds it.
  async function maintainCommunity(own: string, entry: CommunityEntry, histories: Record<string, GroupHistoryMessage[]>,
    records: Record<string, Presentation | undefined>): Promise<void> {
    const authority = authorities(entry.community);
    if (!authority.has(own)) return;
    const heard = entry.parts.flatMap((part) => histories[part] ?? []);
    // A change made in one part reaches the others through the devices in both.
    const newest = records[`group/${entry.parts.reduce((best, part) =>
      (records[`group/${part}`]?.revision ?? 0) > (records[`group/${best}`]?.revision ?? 0) ? part : best)}`];
    for (const part of entry.parts) {
      const record = records[`group/${part}`];
      if (!newest || !record?.community || sameRecord(record, newest)) continue;
      const roles = (value: Community) => [value.owner, ...value.admins].join();
      if (record.community.owner !== own && roles(record.community) !== roles(newest.community!)) continue;
      await savePresentation(databasePath, `group/${part}`, newest);
      advertisedGroups.current.delete(part);
    }
    const missing = entry.community.parts.find((part) => !entry.parts.includes(part));
    if (missing) {
      const request = encodeDeviceRequest(missing, await getGroupKeyPackage(databasePath));
      if (!heard.some((message) => message.direction === "sent" && message.body === request)) {
        await sendGroupMessage(databasePath, fromHex(entry.parts[0]!), request);
      }
    }
    const rosters = new Map<string, GroupDetails>();
    const roster = async (part: string) => rosters.get(part) ?? rosters.set(part, await inspectGroup(databasePath, fromHex(part))).get(part)!;
    // Someone who left is removed, device by device, by the first device there
    // allowed to: the owner's for an admin, which also ends their role.
    for (const part of entry.parts) {
      const members = (await roster(part)).members;
      for (const departure of departures(histories[part] ?? [], new Set(members.map((member) => hex(member.accountId))), authority)) {
        const admin = entry.community.admins.includes(departure.accountId);
        const remover = members.filter((member) => admin ? hex(member.accountId) === entry.community.owner : authority.has(hex(member.accountId)))
          .filter((member) => hex(member.accountId) !== departure.accountId).sort((left, right) => left.leaf - right.leaf)[0];
        if (departure.accountId === entry.community.owner || !remover?.local) continue;
        if (admin) {
          const community = withRoles(entry.community, { admins: entry.community.admins.filter((item) => item !== departure.accountId) });
          for (const held of entry.parts) {
            await savePresentation(databasePath, `group/${held}`, { ...newest!, community });
            advertisedGroups.current.delete(held);
          }
        }
        for (const member of members.filter((item) => hex(item.accountId) === departure.accountId)) {
          await removeGroupMember(databasePath, fromHex(part), member.accountId, member.deviceId);
        }
        await sendGroupMessage(databasePath, fromHex(part), encodeLeft(departure.accountId));
      }
    }
    for (const request of deviceRequests(heard, entry.community)) {
      const key = `${request.deviceId}/${hex(request.keyPackage)}`;
      if (!entry.parts.includes(request.part) || addedDevices.current.has(key)) continue;
      const members = (await roster(request.part)).members;
      const adder = members.filter((member) => authority.has(hex(member.accountId))).sort((left, right) => left.leaf - right.leaf)[0];
      if (!adder?.local || members.some((member) => hex(member.deviceId) === request.deviceId)) continue;
      let username: string | undefined;
      for (const part of entry.parts) {
        username ??= (await roster(part)).members.find((member) => hex(member.accountId) === request.accountId)?.username;
      }
      if (!username) continue;
      addedDevices.current.add(key);
      await addGroupMember(databasePath, fromHex(request.part), username, request.keyPackage);
    }
  }

  function refreshLocalData(): Promise<void> {
    return reloadByDatabase(databasePath, async () => {
      try { if (accountId) setReceiptMarks(await loadReceiptMarks(accountId)); }
      catch { /* Keep the last known marks. */ }
      try { setDeclinedRequests(await loadDeclinedRequests()); }
      catch { /* Keep the last known answers. */ }
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
      if (!presentationOf(`group/${hex(selectedGroup.groupId)}`)?.community) {
        setGroupPreviews((previous) => ({ ...previous, [hex(selectedGroup.groupId)]: messages }));
      }
      await refreshPresentations([...details.members.map((member) => `user/${hex(member.accountId)}`), ...messages.map((message) => `user/${hex(message.senderAccountId)}`)]);
    }).catch((caught) => {
      if (!cancelled) setError(friendlyError(caught));
    });
    return () => { cancelled = true; };
  }, [selectedGroup, preview]);

  // The group's disappearing-message timer, read again as its history changes,
  // since a member's change arrives as a notice in it.
  useEffect(() => {
    if (preview || !selectedGroup) return;
    let cancelled = false;
    const key = hex(selectedGroup.groupId);
    groupTimer(databasePath, selectedGroup.groupId).then(
      (seconds) => { if (!cancelled) setGroupTimers((previous) => ({ ...previous, [key]: seconds })); },
      () => undefined,
    );
    return () => { cancelled = true; };
  }, [selectedGroup, preview, groupHistory]);

  // Disappearing messages leave storage at each sync (the core does that) and on
  // this timer while the app runs, and what this device cached of their files
  // goes with them. Once something was due, the lists and threads load again.
  useEffect(() => {
    if (preview || !profile) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let due = 0;
    const run = async () => {
      let next = 0;
      try {
        const purge = await purgeExpired(databasePath);
        next = purge.next;
        forgetObjects(purge.objectIds);
        if ((due && due <= Date.now()) || purge.objectIds.length) void refreshLocalData().catch(() => undefined);
      } catch {
        // The next sync purges too; this timer tries again in a minute.
      }
      due = next;
      if (!stopped) timer = setTimeout(() => void run(), purgeDelay(next, Date.now()));
    };
    void run();
    return () => { stopped = true; clearTimeout(timer); };
  }, [preview, profile]);

  function forgetObjects(objectIds: string[]): void {
    if (!objectIds.length) return;
    for (const id of objectIds) attachmentBytes.current.delete(id);
    setAttachmentStates((previous) => {
      const next = { ...previous };
      for (const id of objectIds) {
        const uri = next[id]?.previewUri;
        if (uri) releasePreviewUri(uri);
        delete next[id];
      }
      return next;
    });
  }

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

  useEffect(() => onAccountChangedWhileAway(() => setAccountAway(true)), []);

  // The check against the public record (plan section 6.7): daily while the
  // app runs or comes back to the foreground, after a contact's keys change,
  // and when Network opens. Each finished check reloads what Network and the
  // banners show.
  useEffect(() => {
    if (!profile || leaving) return undefined;
    const reload = () => { loadNetworkStatus(databasePath).then(setNetworkStatus, () => {}); };
    const removeListener = onPublicRecordChecked(reload);
    const daily = () => { void schedulePublicRecordCheck(databasePath, "daily").catch(() => {}); };
    const appState = AppState.addEventListener("change", (state) => {
      if (state === "active") daily();
    });
    const hourly = setInterval(daily, 3_600_000);
    daily();
    return () => {
      removeListener();
      appState.remove();
      clearInterval(hourly);
    };
  }, [profile, leaving]);

  // The witness set comes from this build's config; a group needing a newer
  // build shows up after a mailbox pass, which loads it again.
  useEffect(() => {
    if (profile) loadNetworkStatus(databasePath).then(setNetworkStatus, () => {});
  }, [profile]);

  // Plan section 6.15: shown once, with the account's devices to check.
  useEffect(() => {
    if (accountAway && profile && screen !== "devices") openDevices();
  }, [accountAway]);

  useEffect(() => {
    if (!profile || leaving) return undefined;
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
          // A pass can find a group on witnesses this build does not know. An
          // older native build has no status export; its rows stay hidden.
          loadNetworkStatus(databasePath).then(setNetworkStatus, () => {});
          // Native writes may have committed even if delivery or acknowledgement failed.
          await refreshLocalData();
        }
      },
      (caught) => {
        if (caught instanceof RemovedFromAccount) {
          forgetOnProofOfRemoval(caught.statement);
          return;
        }
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
  }, [profile, leaving]);

  useEffect(() => {
    if (!profile || leaving) return undefined;
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
  }, [profile, leaving]);

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
    if (usernameProblem(normalized)) {
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
      // A name the directory refuses would leave an account no server takes,
      // and no way back to choosing another, so it is undone before anyone sees
      // it. An outage keeps the account: connecting registers it later.
      let unregistered: unknown = null;
      try {
        await registerDirectory(databasePath);
      } catch (caught) {
        if (caught instanceof Error && caught.message === "registration_refused") {
          await eraseAccount(databasePath);
          // Said at the field, which stays as typed for another try.
          setTakenUsername(normalized);
          return;
        }
        unregistered = caught;
      }
      setProfile(created);
      enterApp();
      const key = `user/${hex(parseProfileSummary(created).accountId)}`;
      const saved = await savePresentation(databasePath, key, presentation);
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      if (unregistered) throw unregistered;
      // The mailbox sync loads the device set once the witnesses countersign
      // it, seconds from now; the account is usable before then.
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
    const viewOnce = viewOnceScope === scope;
    if (viewOnce && !viewOnceSendable(scope)) return;
    void perform("Sending…", async () => {
      let changed = false;
      await sendWithAttachment(scope, async (attachment) => {
        changed = viewOnce
          ? await sendViewOnce(databasePath, selected.username, composer.trim(), selected.peerAccountId, attachment)
          : await sendFanout(databasePath, selected.username, outgoingBody(composer.trim()), selected.peerAccountId, attachment);
      }, !viewOnce);
      setComposer("");
      setReplying(null);
      if (viewOnce) setViewOnceScope(null);
      noteSent(selected.username, changed);
    });
  }

  // A view-once message is words and pictures only: a file would be saved, which
  // is the one thing view-once is for not doing.
  function viewOnceSendable(scope: string): boolean {
    if (stagedFor(scope).every((entry) => isImageAttachment(entry.file.mimeType))) return true;
    setError("Only photos can be sent view once. Remove the other files or turn view once off.");
    return false;
  }

  function toggleViewOnce(scope: string): void {
    const on = viewOnceScope !== scope;
    setViewOnceScope(on ? scope : null);
    if (on) setStatus(viewOnceCaution);
  }

  // Opening hands the content over once and deletes it from this device in the
  // same call; the pictures are decrypted for this look and deleted on close.
  function openViewOnceMessage(message: HistoryMessage | GroupHistoryMessage): void {
    if (!message.messageId || viewingOpen.current || preview) return;
    const group = "senderAccountId" in message;
    const groupId = selectedGroupId;
    const peer = selected?.peerAccountId;
    if (group ? !groupId : !peer) return;
    viewingOpen.current = true;
    setViewing({ body: "", images: [], loading: true });
    void (async () => {
      const images: string[] = [];
      try {
        const opened = group
          ? await openGroupViewOnce(databasePath, groupId!, message.messageId!)
          : await openViewOnce(databasePath, peer!, message.messageId!);
        for (const attachment of opened.attachments ?? []) {
          if (!isImageAttachment(attachment.mimeType)) continue;
          const bytes = await downloadAttachment(databasePath, attachment, () => undefined);
          images.push(attachmentPreviewUri(`once-${hex(attachment.objectId)}`, attachment.mimeType, bytes));
        }
        if (viewingOpen.current) setViewing({ body: opened.body, images, loading: false });
        else for (const uri of images) releasePreviewUri(uri);
      } catch (caught) {
        for (const uri of images) releasePreviewUri(uri);
        viewingOpen.current = false;
        setViewing(null);
        setError(friendlyError(caught));
      } finally {
        void refreshLocalData().catch(() => undefined);
      }
    })();
  }

  function closeViewOnce(): void {
    for (const uri of viewing?.images ?? []) releasePreviewUri(uri);
    viewingOpen.current = false;
    setViewing(null);
  }

  function openSafetyCode(conversation: Conversation): void {
    setSafetyCodeValue(null);
    setSafetyCodeOpen(true);
    safetyCode(databasePath, conversation.peerAccountId).then(setSafetyCodeValue, (caught) => {
      setSafetyCodeOpen(false);
      setError(friendlyError(caught));
    });
  }

  // A community's parts each carry the timer; they change one after another.
  function changeGroupTimer(groupIds: Uint8Array[], seconds: number): void {
    void perform("Changing the timer…", async () => {
      for (const groupId of groupIds) {
        await setGroupTimer(databasePath, groupId, seconds);
        setGroupTimers((previous) => ({ ...previous, [hex(groupId)]: seconds }));
      }
      await refreshLocalData();
      setStatus(seconds ? `Messages now disappear after ${timerLength(seconds)}` : "Disappearing messages are off");
    });
  }

  function reactToMessage(message: HistoryMessage | GroupHistoryMessage, emoji: string): void {
    if (busy || !message.messageId) return;
    const group = "senderAccountId" in message;
    if (group ? !selectedGroupId || (selectedGroup?.memberCount ?? 0) < 2
      : !selected || selected.blocked || selected.requestPending) return;
    if (preview) {
      // Sample content reacts in place; nothing is saved or sent.
      const react = <T extends HistoryMessage | GroupHistoryMessage>(list: T[] = []) => list.map((item) =>
        item.messageId && hex(item.messageId) === hex(message.messageId!)
          ? { ...item, reactions: setReaction(item.reactions, group ? accountId ?? "" : "sent", emoji) } : item);
      setDevPreview(group
        ? { ...preview, groupHistories: { ...preview.groupHistories, [hex(selectedGroupId!)]: react(preview.groupHistories[hex(selectedGroupId!)]) } }
        : { ...preview, histories: { ...preview.histories, [hex(selected!.conversationId)]: react(preview.histories[hex(selected!.conversationId)]) } });
      return;
    }
    void perform("Sending reaction…", async () => {
      const body = encodeReaction(hex(message.messageId!), emoji);
      // A community post is one message per part; the reaction goes to each.
      const copies = "copies" in message ? (message as { copies: Copy[] }).copies : undefined;
      if (copies) {
        for (const copy of copies) {
          if (copy.messageId) await sendGroupMessage(databasePath, fromHex(copy.part), encodeReaction(hex(copy.messageId), emoji));
        }
      } else if (group) await sendGroupMessage(databasePath, selectedGroupId!, body);
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
  // A conversation's decrypted pictures go when it closes (closedPreviews); one
  // still on its way then is not drawn.
  const previewGeneration = useRef(0);
  useEffect(() => () => {
    previewGeneration.current += 1;
    setAttachmentStates((previous) => {
      const { kept, released } = closedPreviews(previous);
      for (const uri of released) releasePreviewUri(uri);
      return kept;
    });
  }, [openScope]);
  // What the open composer answers, while that message is still in the thread:
  // once it expires, the reply bar goes and the words are sent on their own.
  const replyTarget = replying && replying.scope === openScope
    ? [...history, ...groupHistory, ...communityPosts].find((message) => message.messageId && hex(message.messageId) === replying.target)
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
    const limit = attachmentSelectionError(files.map((file) => file.size), stagedFor(scope).length);
    if (limit) { setError(limit); return; }
    // Files over 16 MB use credits: say what they use before they are staged.
    const spend = creditSpendPrompt(files);
    if (!spend) { stageNow(scope, files); return; }
    const cost = files.reduce((total, file) => total + attachmentCreditCost(file.size), 0);
    creditBalance().then((balance) => {
      const shortfall = creditShortfall(cost, balance);
      if (shortfall) {
        for (const file of files) file.release?.();
        setError(shortfall);
        return;
      }
      confirm({
        title: spend,
        body: `Files over 16 MB use 1 credit for every extra 16 MB. You have ${balance}.`,
        action: `Use ${cost === 1 ? "1 credit" : `${cost} credits`}`,
        run: () => stageNow(scope, files),
      });
    }, (caught) => setError(friendlyError(caught)));
  }

  function stageNow(scope: string, files: OutgoingAttachment[]): void {
    const entries: StagedAttachment[] = [];
    try {
      for (const file of files) {
        const id = `staged-${stagedSerial.current++}`;
        const previewUri = isImageAttachment(file.mimeType) && file.bytes ? attachmentPreviewUri(id, file.mimeType, file.bytes) : undefined;
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
    entry?.file.release?.();
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
      size: formatBytes(entry.file.size),
      previewUri: entry.previewUri,
    }));

  useEffect(() => listenForIncomingFiles({
    onDragging: setDropping,
    onFiles: (files) => stageAttachments(openScope, files),
    onError: setError,
  }));

  // `keep` is false for a view-once message, whose sender keeps nothing of it.
  async function sendWithAttachment(scope: string, send: (attachment?: Uint8Array) => Promise<void>, keep = true): Promise<void> {
    const entries = stagedFor(scope);
    const uploaded = await sendWithAttachments(databasePath, entries.map((entry) => entry.file), async (reference) => {
      setStatus("Sending…");
      await send(reference);
    }, (completed, total) => setStatus(`Uploading… ${Math.round(completed / total * 100)}%`));
    uploaded.forEach((file, index) => {
      const entry = entries[index]!;
      const key = hex(file.objectId);
      entry.file.release?.();
      if (!keep) {
        if (entry.previewUri) releasePreviewUri(entry.previewUri);
        return;
      }
      // A large file was read from disk as it went; this device fetches it again if asked.
      if (!entry.file.bytes) return;
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
  // person chooses. A second tap while it is on its way does nothing. A file
  // over 16 MB is never held whole: a tap writes it where the person picks as
  // it downloads.
  function openAttachment(attachment: AttachmentSummary, save: boolean): void {
    const key = hex(attachment.objectId);
    if (downloading.current.has(key)) return;
    if (attachment.size > FREE_ATTACHMENT_SIZE) {
      if (save) saveLargeAttachment(attachment, key);
      return;
    }
    // A picture whose bytes have since left the cache keeps its preview.
    const current = attachmentStates[key];
    let previewUri = current?.previewUri;
    const shown = previewGeneration.current;
    void (async () => {
      try {
        let bytes = attachmentBytes.current.get(key);
        const fetched = !bytes;
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
        }
        if (shown !== previewGeneration.current) {
          // Its conversation closed meanwhile: nothing is drawn, and the picture
          // comes back from memory when that conversation opens again.
          setAttachmentStates((previous) => {
            const next = { ...previous };
            delete next[key];
            return next;
          });
        } else if (previewUri === undefined && isImageAttachment(attachment.mimeType)) {
          // Just fetched, or drawn again from memory as its conversation reopens.
          previewUri = attachmentPreviewUri(key, attachment.mimeType, bytes);
          setAttachmentState(key, { status: "ready", previewUri });
        } else if (fetched) {
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

  function saveLargeAttachment(attachment: AttachmentSummary, key: string): void {
    downloading.current.add(key);
    void (async () => {
      try {
        const saved = await saveAttachmentStream(attachment.filename, attachment.mimeType, async (write) => {
          setAttachmentState(key, { status: "downloading", completed: 0, total: attachment.chunkCount });
          await streamAttachment(databasePath, attachment, write, (completed, total) =>
            setAttachmentState(key, { status: "downloading", completed, total }));
        });
        setAttachmentState(key, saved ? { status: "saved" } : { status: "ready" });
      } catch (caught) {
        const message = friendlyError(caught);
        setAttachmentState(key, { status: "error", message });
        setError(message);
      } finally {
        downloading.current.delete(key);
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
    setScannedCommunity(null);
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

  function openGroup(chosen: GroupSummary): void {
    // A community opens at its first part this device is in.
    const first = communityOfGroup(hex(chosen.groupId))?.parts[0];
    const group = groups.find((item) => hex(item.groupId) === first) ?? chosen;
    if (!selectedGroupId || hex(selectedGroupId) !== hex(group.groupId)) {
      setGroupDetails(null);
      setGroupHistory([]);
      setGroupHistoryFor(null);
      setAboutDraft(null);
    }
    setSelectedGroupId(group.groupId);
    setScreen("group");
  }

  function createNewGroup(): void {
    if (preview) { setError("Turn off sample preview to create a group."); return; }
    setGroupDraftName("");
    setGroupDraftAvatar(undefined);
    setDraftCommunity(false);
    setGroupDraftAbout("");
    pendingCreatedGroup.current = null;
    go("new-group");
  }

  function finishGroupCreation(): void {
    // A new community is its own first part, owned by whoever creates it.
    const draft = (part: string) => ({ name: groupDraftName, avatar: groupDraftAvatar,
      ...(draftCommunity && accountId ? { community: { about: groupDraftAbout, groups: [], parts: [part], owner: accountId, admins: [] } } : {}) });
    try { encodePresentation({ ...draft("0".repeat(64)), revision: 0 }); }
    catch (caught) { setError(friendlyError(caught)); return; }
    void perform(draftCommunity ? "Creating your community…" : "Creating your group…", async () => {
      const groupId = pendingCreatedGroup.current ?? await createGroup(databasePath);
      pendingCreatedGroup.current = groupId;
      const key = `group/${hex(groupId)}`;
      const saved = await savePresentation(databasePath, key, draft(hex(groupId)));
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      setSelectedGroupId(groupId);
      setGroupDetails(null);
      setGroupHistory([]);
      setGroupHistoryFor(null);
      pendingCreatedGroup.current = null;
      setScreen("group-info");
      setStatus(draftCommunity ? "Community created. Invite members, then link groups." : "Group created. Invite someone to get started.");
    });
  }

  function updateAvatar(key: string, name: string, avatar?: string): void {
    const entry = key.startsWith("group/") ? communityOfGroup(key.slice(6)) : undefined;
    void perform("Saving photo…", async () => {
      if (entry) {
        await writeCommunity(entry, { name, avatar });
        setStatus("Photo saved");
        return;
      }
      const saved = await savePresentation(databasePath, key, { ...presentationOf(key), name, avatar });
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
        name={name || (group ? "New group" : "")}
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
  function renderPhotoEditor(name: string, avatar: string | undefined, onChange: (value: string | undefined) => void, seed?: string, pictureSize: number = size.avatar["2xl"]) {
    return (
      <View style={styles.photoEditor}>
        {renderPhotoButton(name, avatar, onChange, { size: pictureSize, seed })}
        {avatar ? renderRemovePhoto(() => onChange(undefined)) : null}
      </View>
    );
  }

  // Naming a group is composed like the identity it creates: the picture
  // first, large and tappable, then the name beneath it. On desktop the form
  // sits as a narrow sheet in the pane.
  function renderNewGroup() {
    return (
      <Page header={<Header title={draftCommunity ? "New community" : "New group"} onBack={() => go("groups")} backLabel="Cancel" />}>
        <ScrollView
          contentContainerStyle={[layout.content, styles.newGroup]}
          keyboardShouldPersistTaps="handled"
        >
          <View style={styles.newGroupPhoto}>
            {renderPhotoButton(groupDraftName, groupDraftAvatar, setGroupDraftAvatar, { group: true })}
            {groupDraftAvatar ? renderRemovePhoto(() => setGroupDraftAvatar(undefined)) : null}
          </View>
          <Field
            label={draftCommunity ? "Community name" : "Group name"}
            value={groupDraftName}
            onChangeText={setGroupDraftName}
            placeholder={draftCommunity ? "Solana builders" : "Weekend walks"}
            maxLength={96}
            autoFocus
            hint="Shown to everyone you invite. You can change both later in group details."
          />
          <RowGroup>
            <Row
              icon="megaphone"
              title="Community"
              subtitle="Announcements only you post, and groups members can ask to join."
              trailing={<Toggle label="Community" value={draftCommunity} onValueChange={setDraftCommunity} />}
            />
          </RowGroup>
          {draftCommunity ? (
            <Field
              label="Description"
              value={groupDraftAbout}
              onChangeText={setGroupDraftAbout}
              placeholder="What this community is for"
              multiline
              maxLength={500}
            />
          ) : null}
          <Actions>
            <Button
              label={draftCommunity ? "Create community" : "Create group"}
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
    const entry = selectedEntry;
    if (entry && Object.values(communityData).some((part) => part.details.members.some((member) => member.username === target))) {
      setError(`@${target} is already in the community.`);
      return;
    }
    void perform("Sending invitation…", async () => {
      await inviteToGroup(databasePath, entry ? await communityPartFor(entry) : selectedGroupId, target);
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
    const text = groupComposer.trim();
    const answered = replyTarget && communityPosts.find((post) => post.messageId && hex(post.messageId) === replying!.target);
    const viewOnce = !selectedEntry && viewOnceScope === scope;
    if (viewOnce && !viewOnceSendable(scope)) return;
    if (viewOnce) {
      void perform("Sending…", async () => {
        await sendWithAttachment(scope, (attachment) => sendGroupViewOnce(databasePath, selectedGroupId, text, attachment), false);
        setGroupComposer("");
        setReplying(null);
        setViewOnceScope(null);
        setStatus("Sent");
      });
      return;
    }
    void perform("Sending…", async () => {
      await sendWithAttachment(scope, async (attachment) => {
        if (!selectedEntry) return sendGroupMessage(databasePath, selectedGroupId, outgoingBody(text), attachment);
        // An announcement goes to every part; a reply quotes each part's own copy.
        for (const part of selectedEntry.parts) {
          const copy = answered?.copies.find((item) => item.part === part && item.messageId);
          await sendGroupMessage(databasePath, fromHex(part), copy ? encodeReply(hex(copy.messageId!), text) : text, attachment);
        }
      });
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

  // The owner changes what members see of the community; the record reaches
  // them with the next message from this device, which the refresh sends.
  // Every part carries the same record. The owner or an admin writes each part
  // this device is in; members get it with the next message from this device,
  // which the refresh sends, and the other parts from devices that are there.
  async function writeCommunity(entry: CommunityEntry, change: Partial<Presentation>): Promise<void> {
    const base = presentationOf(`group/${entry.parts[0]}`);
    if (!base) throw new Error("The community is still loading.");
    for (const part of entry.parts) {
      const key = `group/${part}`;
      const saved = await savePresentation(databasePath, key, { ...base, ...change });
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      advertisedGroups.current.delete(part);
    }
  }

  function saveCommunity(community: Community, done: string): void {
    const entry = selectedEntry;
    const base = entry && presentationOf(`group/${entry.parts[0]}`);
    if (!entry || !base) return;
    try { encodePresentation({ ...base, revision: 0, community }); }
    catch (caught) { setError(friendlyError(caught)); return; }
    void perform("Saving the community…", async () => {
      await writeCommunity(entry, { community });
      setAboutDraft(null);
      setStatus(done);
    });
  }

  // A new member joins the first part with room; a full community grows a
  // part, which the owner's and admins' devices then ask to join.
  async function communityPartFor(entry: CommunityEntry): Promise<Uint8Array> {
    const pending = (part: string) => groupInvitations.filter((item) => hex(item.groupId) === part && (item.state === 0 || item.state === 3)).length;
    const room = pickPart(entry.parts.map((part) => ({
      id: part, leaves: groups.find((group) => hex(group.groupId) === part)?.memberCount ?? 64, pending: pending(part),
    })));
    if (room) return fromHex(room);
    const created = await createGroup(databasePath);
    const community = { ...entry.community, parts: [...entry.community.parts, hex(created)] };
    const base = presentationOf(`group/${entry.parts[0]}`)!;
    const key = `group/${hex(created)}`;
    const saved = await savePresentation(databasePath, key, { ...base, community });
    setPresentations((previous) => ({ ...previous, [key]: saved }));
    await writeCommunity(entry, { community });
    return created;
  }

  // Someone leaves the community from every part they are in, device by device.
  function removeFromCommunity(accountId: string, name: string): void {
    const community = selectedCommunity;
    void perform(`Removing ${name} from the community…`, async () => {
      if (community?.admins.includes(accountId)) {
        await writeCommunity(selectedEntry!, { community: withRoles(community, { admins: community.admins.filter((admin) => admin !== accountId) }) });
      }
      for (const [part, { details }] of Object.entries(communityData)) {
        for (const member of details.members.filter((item) => hex(item.accountId) === accountId)) {
          await removeGroupMember(databasePath, fromHex(part), member.accountId, member.deviceId);
        }
      }
      setStatus(`${name} removed from the community`);
    });
  }

  // Asking to join from outside is a message to whoever shared the link.
  function askToJoinCommunity(link: CommunityLink): void {
    if (link.admin === ownUsername) { setError("That’s your own community’s link."); return; }
    if (communityIndex.has(link.community)) { setError(`You’re already in ${link.name}.`); return; }
    void perform(`Asking @${link.admin}…`, async () => {
      const changed = await sendFanout(databasePath, link.admin, encodeCommunityRequest(link.community, link.name));
      setScannedCommunity(null);
      setScreen("groups");
      noteSent(link.admin, changed);
      setStatus(`Asked @${link.admin} to let you into ${link.name}`);
    });
  }

  // Approving someone accepts their message request, invites them to a part
  // with room and tells them which, so their device accepts it for them.
  function approveAsk(conversation: Conversation, request: UnansweredRequest): void {
    const entry = selectedEntry;
    if (!entry) return;
    setReviewing(null);
    void perform(`Letting @${conversation.username} in…`, async () => {
      if (conversation.requestPending) {
        await update_conversation_export(policyRequest(databasePath, conversation.peerAccountId, 1, 0));
      }
      const part = await communityPartFor(entry);
      await inviteToGroup(databasePath, part, conversation.username);
      await sendFanout(databasePath, conversation.username, encodeCommunityAnswer(request.community, hex(part)), conversation.peerAccountId);
      setStatus(`@${conversation.username} is invited`);
    });
  }

  // Declining stays on this device: a request that was never accepted can't be answered.
  function declineAsk(conversation: Conversation, request: UnansweredRequest): void {
    setReviewing(null);
    const scope = `chat/${hex(conversation.conversationId)}`;
    const next = { ...declinedRequests, [scope]: [...(declinedRequests[scope] ?? []), request.key].slice(-256) };
    setDeclinedRequests(next);
    saveDeclinedRequests(next).catch(() => setError("That couldn’t be saved. The request may come back after restarting."));
    setStatus(`Declined @${conversation.username}`);
  }

  // A community link shared in a message can be answered from that message.
  function communityLinkAction(body: string) {
    const link = /mesh:\/\/community\/[A-Za-z0-9_-]+/.exec(body)?.[0];
    const read = link ? readCommunityLink(link) : undefined;
    return read ? {
      icon: "link" as const,
      label: `Ask to join ${read.name}`,
      onPress: () => { openScanner("community"); setScannedCommunity(read); },
    } : undefined;
  }

  function copyCommunityLink(value: string): void {
    Clipboard.setString(value);
    setStatus("Link copied");
  }

  function confirmLeave(entry: CommunityEntry): void {
    confirm({
      title: "Leave this community?",
      body: "It’s removed from all your devices, and its admins remove you from it. Groups you joined through it stay.",
      action: "Leave community",
      run: () => void perform("Leaving the community…", async () => {
        for (const part of entry.parts) await sendGroupMessage(databasePath, fromHex(part), LEAVE_REQUEST);
        for (const part of entry.parts) await forgetGroup(databasePath, fromHex(part));
        setSelectedGroupId(null);
        setScreen("groups");
        setStatus("You left the community");
      }),
    });
  }

  function changeRoles(change: Partial<{ owner: string; admins: string[] }>, done: string): void {
    if (!selectedCommunity) return;
    saveCommunity(withRoles(selectedCommunity, change), done);
  }

  function confirmHandover(accountId: string, name: string): void {
    confirm({
      title: `Make ${name} the owner?`,
      body: "They take over the community’s roles, and you stay on as an admin. Only they can make you owner again.",
      action: "Make owner",
      run: () => changeRoles({ owner: accountId }, `${name} owns the community now`),
    });
  }

  function askToJoin(groupId: string): void {
    if (!selectedGroupId) return;
    const communityId = selectedGroupId;
    void perform("Asking to join…", async () => {
      await sendGroupMessage(databasePath, communityId, encodeJoinRequest(groupId));
      setStatus("Asked. The invitation appears here when an admin adds you.");
    });
  }

  function approveRequest(request: JoinRequest, username: string): void {
    const group = groups.find((item) => hex(item.groupId) === request.groupId);
    if (!group) return;
    void perform(`Inviting @${username}…`, async () => {
      await inviteToGroup(databasePath, group.groupId, username);
      setStatus(`Invitation sent to @${username}`);
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

  // The system alert asks on a phone; the desktop has its own dialog.
  function confirm(confirmation: Confirmation): void {
    if (Platform.OS === "web") { setPendingConfirm(confirmation); return; }
    Alert.alert(confirmation.title, confirmation.body, [
      { text: "Cancel", style: "cancel" },
      { text: confirmation.action, style: "destructive", onPress: confirmation.run },
    ]);
  }

  function confirmRevoke(deviceId: Uint8Array): void {
    confirm({
      title: "Remove this device?",
      body: "It permanently loses access to your account and future messages, and erases its own messages and keys the next time it’s online.",
      action: "Remove device",
      run: () => revokeLinkedDevice(deviceId),
    });
  }

  // The device that created the account deletes it everywhere. A linked device
  // holds no account key, so it leaves the account and erases only itself.
  function confirmDeleteAccount(): void {
    void holdsAccountKey(databasePath).then(
      (everywhere) => confirm(everywhere ? {
        title: "Delete your account?",
        body: "Your username, messages and keys are erased from the server, from this device, and from your linked devices as soon as they’re online. No one can reach this account again. This can’t be undone.",
        action: "Delete account",
        run: deleteAccountNow,
      } : {
        title: "Erase this device?",
        body: "This device leaves your account, and its messages and keys are erased from it. The account stays on your other devices.",
        action: "Erase device",
        run: deleteAccountNow,
      }),
      (caught) => setError(friendlyError(caught)),
    );
  }

  function deleteAccountNow(): void {
    const erased = accountId;
    setLeaving(true);
    setBusy(true);
    setError("");
    setStatus("Deleting your account…");
    void deleteAccount(databasePath).then(
      () => finishErasing(erased),
      (caught) => {
        // Nothing was erased, so the account is whole and this can be tried again.
        setError(friendlyError(caught));
        setLeaving(false);
        setBusy(false);
      },
    );
  }

  // This device is out of its account: the account was deleted, or the device
  // removed, on the device that created it. The directory hands over the signed
  // statement that did it, and only that erases this copy: a server that merely
  // claims so changes nothing.
  function forgetOnProofOfRemoval(statement: Uint8Array): void {
    const erased = accountId;
    void forgetOnProof(databasePath, statement).then(
      (removal) => {
        setLeaving(true);
        return finishErasing(erased, removalNotices[removal]);
      },
      (caught) => setSyncError(friendlyError(caught)),
    );
  }

  // The account is gone; what follows only tidies what it left on the device,
  // and nothing it does may keep the app from starting over.
  async function finishErasing(erased: string | null, reason?: string): Promise<void> {
    try {
      discardPreviews();
      if (erased) forgetPreferences(erased);
      await forgetPush(databasePath);
    } catch {
      // Tidying only: the account itself is already gone.
    } finally {
      onAccountErased(reason);
    }
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
    if (scannedProfile || scannedLinkRequest || scannedGroupPackage || scannedCommunity) return;
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
    if (scanMode === "community") {
      const link = readCommunityLink(data);
      if (link) {
        setScannedCommunity(link);
        setError("");
      } else {
        qrCollector.reset();
        setError("That isn’t a community link. Ask for the link again.");
      }
    } else if (scanMode === "contact") {
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
        // The mailbox sync loads the device set once it is countersigned.
        await registerDirectory(databasePath);
        setLinkRequest(null);
        setLinkSas("");
        enterApp();
        setStatus("This device is linked");
        if (restoreAfterLink) {
          setRestoreAfterLink(false);
          setBackupStart("restore");
          setScreen("backups");
        }
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
            const entry = communityOfGroup(hex(groupId));
            await addGroupMember(databasePath, entry ? await communityPartFor(entry) : groupId, target, keyPackage);
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
  // A community is run by its owner and admins; a plain group by its creator.
  const canManage = selectedCommunity ? Boolean(ownId && communityAuthority.has(ownId)) : isGroupCreator;
  const isOwner = Boolean(ownId && selectedCommunity?.owner === ownId);
  const partsKey = selectedEntry?.parts.join() ?? "";
  useEffect(() => {
    if (preview || !partsKey) return;
    let cancelled = false;
    void Promise.all(partsKey.split(",").map(async (part) => {
      const [details, messages] = await Promise.all([inspectGroup(databasePath, fromHex(part)), loadGroupHistory(databasePath, fromHex(part))]);
      return [part, { details, messages }] as const;
    })).then(async (entries) => {
      if (cancelled) return;
      setCommunityParts(Object.fromEntries(entries));
      await refreshPresentations(entries.flatMap(([, part]) => [
        ...part.details.members.map((member) => `user/${hex(member.accountId)}`),
        ...part.messages.map((message) => `user/${hex(message.senderAccountId)}`),
      ]));
    }).catch((caught) => {
      if (!cancelled) setError(friendlyError(caught));
    });
    return () => { cancelled = true; };
  }, [partsKey, groups, preview]);
  useEffect(() => {
    if (preview || !selectedCommunity || !canManage) return;
    let cancelled = false;
    const linked = groups.filter((group) => selectedCommunity.groups.some((item) => item.id === hex(group.groupId)));
    void Promise.all(linked.map(async (group) =>
      [hex(group.groupId), (await inspectGroup(databasePath, group.groupId)).members.map((member) => hex(member.accountId))] as const))
      .then((entries) => { if (!cancelled) setLinkedMembers(Object.fromEntries(entries)); })
      .catch(() => { /* Requests wait until their groups can be read. */ });
    return () => { cancelled = true; };
  }, [selectedCommunity, canManage, groups, preview]);
  function senderIdentity(accountId: Uint8Array | string, local = false) {
    const id = typeof accountId === "string" ? accountId : hex(accountId);
    const stored = presentationOf(`user/${id}`);
    const contact = conversations.find((item) => hex(item.peerAccountId) === id);
    const invitation = groupInvitations.find((item) => hex(item.accountId) === id);
    // A community's members are spread over its parts.
    const member = groupDetails?.members.find((item) => hex(item.accountId) === id) ??
      Object.values(communityData).flatMap((part) => part.details.members).find((item) => hex(item.accountId) === id);
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
  const groupBadgeCount = groupRequestCount + listedGroups.reduce((total, item) => total + groupUnread(item), 0);
  const mainScreen = profile && ["home", "groups", "settings"].includes(screen);
  const chatRows = buildChatRows(history, (message) => hex(message.messageId)).reverse();
  const chatScope =
    selected && historyFor === hex(selected.conversationId) ? historyFor : null;
  const isFreshMessage = useFreshKeys(
    chatRows.map((row) => row.key),
    chatScope,
  );
  const threadMessages: (GroupHistoryMessage & { copies?: Copy[] })[] = selectedCommunity ? communityPosts : groupHistory;
  const groupRows = buildChatRows(
    threadMessages,
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
  const communityRequests = selectedCommunity ? joinRequests(communityHeard, selectedCommunity) : [];
  // What an owner or admin has yet to act on: someone outside a linked group this device can invite them to.
  const linkedRosters = preview ? Object.fromEntries(Object.entries(preview.groupDetails).map(([id, details]) =>
    [id, details.members.map((member) => hex(member.accountId))])) : linkedMembers;
  const joinWaiting = selectedCommunity && canManage ? communityRequests.filter((request) => request.accountId !== ownId &&
    linkedRosters[request.groupId]?.includes(request.accountId) === false &&
    !groupInvitations.some((item) => hex(item.groupId) === request.groupId && hex(item.accountId) === request.accountId &&
      (item.state === 0 || item.state === 3))) : [];
  // Who asked, through a link this admin shared, to join the open community and is not in it yet.
  const communityMembers = new Set(Object.values(communityData).flatMap((part) => part.details.members)
    .flatMap((member) => member.username ? [member.username] : []));
  const incomingAsks = selectedCommunity && canManage ? conversations.flatMap((conversation) =>
    unansweredRequests(chatHistories[hex(conversation.conversationId)] ?? [], declinedRequests[`chat/${hex(conversation.conversationId)}`] ?? [])
      .filter((request) => request.community === communityId(selectedCommunity) && !communityMembers.has(conversation.username))
      .map((request) => ({ conversation, request }))) : [];
  // An invitation that follows an approved request is the one this account asked for.
  useEffect(() => {
    if (preview) return;
    const due = groupInvitations.filter((invitation) => invitation.state === 1 && !acceptedApprovals.current.has(hex(invitation.reference)) &&
      communityAsks.some((ask) => ask.state === "approved" && ask.part === hex(invitation.groupId) && ask.conversation.username === invitation.username));
    if (!due.length) return;
    due.forEach((invitation) => acceptedApprovals.current.add(hex(invitation.reference)));
    void perform("Joining the community…", async () => {
      for (const invitation of due) await acceptGroupInvitation(databasePath, invitation);
      setStatus("Approved. You join as soon as they’re next online.");
    });
  }, [groupInvitations, chatHistories, preview]);
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

  // Android's back gesture steps back through the app the way the on-screen
  // back button does, and leaves it only from a root screen.
  useEffect(() => {
    if (Platform.OS !== "android") return undefined;
    const subscription = BackHandler.addEventListener("hardwareBackPress", () => {
      if (membersOpen) {
        setMembersOpen(false);
        return true;
      }
      if (onboardingActive) {
        if (onboardingStep !== "profile") return false;
        goOnboarding("welcome");
        return true;
      }
      const target = dismissTarget();
      if (!target) return false;
      go(target);
      return true;
    });
    return () => subscription.remove();
  });

  useEffect(() => {
    if (!split) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      // A dialog owns the keyboard while it is open.
      if (pendingConfirm !== null || document.querySelector('[aria-modal="true"]')) return;
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

  // What the app is, before anything is asked of you: a conversation opening
  // on its own, the promise, three things worth knowing, and the way in. On a
  // phone the picture takes whatever height the words leave, so the buttons
  // stay at the foot of the screen, and the page only scrolls when large text
  // leaves no room at all. The desktop sets the picture beside the words.
  function renderWelcome() {
    return (
      <ScrollView
        contentContainerStyle={[styles.welcome, isDesktop && styles.welcomeDesktop]}
        showsVerticalScrollIndicator={false}
        bounces={false}
      >
        <SealedChat />
        <View style={styles.welcomeCopy}>
          {/* The launch screen has just shown the mark on a phone, where the
              conversation above is picture enough. */}
          {isDesktop ? (
            <Reveal>
              <AppGlyph size={size.mark.sm} />
            </Reveal>
          ) : null}
          <Reveal delay={60} style={styles.heroBlock}>
            <Text accessibilityRole="header" style={type.largeTitle}>
              Private messaging,{"\n"}made simple.
            </Text>
            <Text style={type.body}>
              Pick a username and start talking.
            </Text>
          </Reveal>
          <Reveal delay={120} style={styles.facts}>
            <Fact icon="lock">End-to-end encrypted</Fact>
            <Fact icon="person">No phone number, no contact upload</Fact>
            <Fact icon="shield">Verify contacts with safety numbers</Fact>
          </Reveal>
          {notice ? <Notice text={notice} /> : null}
          <Reveal delay={180}>
            <Actions>
              <Button label="Get started" onPress={() => goOnboarding("profile")} />
              <Button
                label="Link an existing account"
                onPress={() => { setRestoreAfterLink(false); beginDeviceLink(); }}
                variant="ghost"
              />
              <Button
                label="Restore from a backup"
                onPress={() => { setBackupStart("recover"); setScreen("backups"); }}
                variant="ghost"
              />
            </Actions>
          </Reveal>
        </View>
      </ScrollView>
    );
  }

  // Who you are: the picture, the name people find you by, and nothing else.
  // It keeps a header so the welcome screen is one tap back. The username is
  // checked as it is typed, and folded to the lowercase it will be registered
  // in, so the button only wakes for a name the directory could take.
  function renderProfileSetup() {
    const typed = username.trim();
    const problem = usernameProblem(typed);
    const taken = typed !== "" && typed === takenUsername;
    const usernameError = taken
      ? "That username is taken. Try another."
      : problem === "characters"
        ? "Use only lowercase letters, numbers, and underscores."
        : problem === "long"
          ? "Use 32 characters or fewer."
          : undefined;
    const submit = problem === null && !taken ? createAccount : undefined;
    const intro = <>
      <Text accessibilityRole="header" style={isDesktop ? type.largeTitle : [type.title, layout.centerText]}>
        Pick a username.
      </Text>
      <Text style={[type.body, !isDesktop && layout.centerText]}>
        It is how people reach you. Your private keys stay on your devices.
      </Text>
    </>;
    const form = <>
          <Reveal delay={60} style={layout.stackLoose}>
            <Field
              label="Choose your username"
              value={username}
              onChangeText={(value) => setUsername(value.replace(/^@+/, "").toLowerCase())}
              placeholder="your_name"
              prefix="@"
              maxLength={32}
              hint="3–32 lowercase letters, numbers, or underscores."
              error={usernameError}
              onSubmitEditing={submit}
            />
            <Field
              label="Display name (optional)"
              value={displayName}
              onChangeText={setDisplayName}
              placeholder="What people call you"
              maxLength={96}
              hint="Shown to people you message. You can change it later."
              onSubmitEditing={submit}
            />
          </Reveal>
          <Reveal delay={120}>
            <Actions>
              <Button label="Create account" disabled={busy || pickingPhoto || !submit} onPress={createAccount} />
            </Actions>
          </Reveal>
    </>;
    const name = displayName || username;
    return (
      <Page
        header={
          <Header
            title="Your profile"
            onBack={() => goOnboarding("welcome")}
            {...sheetHeader}
          />
        }
      >
        {/* The desktop keeps the welcome's spread, so the words stay where
            they were and the picture becomes the identity being made. */}
        {isDesktop ? (
          <ScrollView
            contentContainerStyle={[styles.welcome, styles.welcomeDesktop]}
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
          >
            <IdentityPreview
              photo={renderPhotoButton(name, accountAvatar, setAccountAvatar, { size: size.avatar["3xl"], seed: avatarSeed })}
              name={displayName.trim()}
              username={typed}
            >
              {accountAvatar ? renderRemovePhoto(() => setAccountAvatar(undefined)) : null}
            </IdentityPreview>
            <View style={styles.welcomeCopy}>
              <Reveal style={styles.heroBlock}>{intro}</Reveal>
              {form}
            </View>
          </ScrollView>
        ) : (
          <ScrollView
            contentContainerStyle={layout.content}
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
          >
            <Reveal style={styles.profileHead}>
              {renderPhotoEditor(name, accountAvatar, setAccountAvatar, avatarSeed, heroAvatarSize)}
              {intro}
            </Reveal>
            {form}
          </ScrollView>
        )}
      </Page>
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
              <View style={layout.stackLoose}>
                <Text style={type.title}>Bring your account along.</Text>
                {restoreAfterLink ? (
                  <Notice text="A backup comes back onto a device of its account. Link this one from a device that is still signed in; then you enter your recovery code." />
                ) : null}
                <Steps>
                  {[
                    <>On the device you signed up on, open <Strong>You → Linked devices</Strong> and choose <Strong>Link another device</Strong>.</>,
                    "Scan this code with it.",
                    "Check that both screens show the same code.",
                    Platform.OS === "web" ? "Enter the approval code it shows you." : "Scan the approval code it shows you.",
                  ]}
                </Steps>
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
            title={scanMode === "community" ? "Join a community" : Platform.OS === "web" ? "Enter a code" : "Scan a code"}
            onBack={backToScannerOrigin}
            backLabel="Cancel"
            {...sheetHeader}
          />
        }
      >
        {scannedCommunity ? (
          <ScrollView
            contentContainerStyle={[layout.content, sheetContent]}
            keyboardShouldPersistTaps="handled"
          >
            <Hero
              name={scannedCommunity.name}
              colorSeed={scannedCommunity.community}
              group
              title={scannedCommunity.name}
              subtitle={`Community · shared by @${scannedCommunity.admin}`}
              badge={<Badge label="Community link" icon="link" />}
            />
            <Notice text={`Your request goes to @${scannedCommunity.admin} as a message. Once they let you in, you join on this device.`} />
            <Actions>
              <Button label="Ask to join" onPress={() => askToJoinCommunity(scannedCommunity)} />
              <Button
                label={Platform.OS === "web" ? "Enter another link" : "Scan again"}
                onPress={() => openScanner("community")}
                variant="ghost"
              />
            </Actions>
          </ScrollView>
        ) : scannedProfile ? (
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
              <Text style={type.title}>{scanMode === "community" ? "Paste a community link" : "Paste the code from the other device"}</Text>
              <Text style={type.body}>
                {scanMode === "community"
                  ? "Ask someone who runs the community for its link, then paste it here."
                  : "On the other device, choose Show text code under the code, copy it, and paste it here."}
              </Text>
            </View>
            <Field
              label={scanMode === "community" ? "Community link" : "Device code"}
              placeholder={scanMode === "community" ? "Paste the link here" : "Paste the code here"}
              value={pastedCode}
              onChangeText={setPastedCode}
              multiline
            />
            <Actions>
              <Button
                label={scanMode === "community" ? "Read link" : "Read code"}
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

  // The screen opens on who you are, as the people you message see it: a
  // card with the photo (which is also how it is changed), the name and
  // handle, and the QR code that shares them. Settings proper follow in groups.
  function renderSettings() {
    const activeDevices = devices?.devices.filter((device) => device.active).length;
    const setOwnPhoto = (avatar: string | undefined) => {
      if (ownId) updateAvatar(`user/${ownId}`, ownName, avatar);
    };
    const theme = appearanceOptions.find((option) => option.value === appearance);
    return (
      <Page header={<LargeHeader title="You" />}>
        <ScrollView contentContainerStyle={layout.contentTight}>
          <Section footer="People you message see this name and photo.">
            <Card style={styles.profileCard}>
              {renderPhotoButton(ownName, ownAvatar, setOwnPhoto, { size: size.avatar["2xl"], seed: ownId })}
              <View style={layout.flex}>
                <Text numberOfLines={1} style={type.title2}>{ownName}</Text>
                <Text numberOfLines={1} style={type.subhead}>@{ownUsername}</Text>
              </View>
              <IconButton name="qr" label="My QR code" variant="soft" glass={false} size={isDesktop ? control.lg : undefined} onPress={() => go("account")} />
            </Card>
          </Section>
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
              {ownAvatar && !preview ? (
                <Row
                  icon="image"
                  title="Remove photo"
                  onPress={busy || pickingPhoto ? undefined : () => setOwnPhoto(undefined)}
                  trailing={null}
                />
              ) : null}
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
              {preview ? null : <BackupsRow onPress={() => { setBackupStart("status"); go("backups"); }} />}
            </RowGroup>
          </Section>
          {networkStatus ? (
            <Section title="Network">
              <RowGroup>
                <Row
                  icon="shield"
                  title="Witnesses"
                  subtitle={networkStatus.updateRequired ? "A group needs a newer Morse" : profileLine(networkStatus)}
                  tone={networkStatus.updateRequired ? "danger" : "accent"}
                  onPress={openNetwork}
                />
              </RowGroup>
            </Section>
          ) : null}
          <Section title="Wallet">
            <RowGroup>
              <Row icon="key" title="Wallet" subtitle="Solana, held on this device" onPress={() => go("wallet")} />
              <CreditsRow onPress={() => go("credits")} />
            </RowGroup>
          </Section>
          <Section title="Notifications">
            <RowGroup>
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
                icon="chat"
                title="Previews"
                subtitle={notificationPreviewOptions.find((option) => option.value === notificationPreview)?.label}
                trailing={
                  <Segmented
                    label="Notification previews"
                    options={notificationPreviewOptions}
                    value={notificationPreview}
                    onSelect={(chosen) => {
                      setNotificationPreview(chosen);
                      if (accountId) saveNotificationPreview(accountId, chosen)
                        .catch(() => setError("That choice couldn’t be saved. It applies until you restart."));
                    }}
                  />
                }
              />
            </RowGroup>
          </Section>
          <Section title="Privacy">
            <RowGroup>
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
                      if (accountId) saveReadReceipts(accountId, enabled)
                        .catch(() => setError("That choice couldn’t be saved. It applies until you restart."));
                    }}
                  />
                }
              />
              <AppLockRow disabled={preview !== null} />
              <InboxPriceRow disabled={preview !== null} />
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
          {updates}
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
          {/* The one step that cannot be undone stands apart, at the end. */}
          <Section>
            <RowGroup>
              <Row
                icon="warning"
                tone="danger"
                emphasis="danger"
                title={devices?.canManage === false ? "Erase this device" : "Delete account"}
                subtitle={devices?.canManage === false
                  ? "Leaves your account and erases this device"
                  : "Erases your username and messages everywhere"}
                onPress={preview || busy ? undefined : confirmDeleteAccount}
              />
            </RowGroup>
          </Section>
        </ScrollView>
      </Page>
    );
  }

  // Settings -> Network: which witnesses must sign the key log before this
  // device trusts a key, and who runs them (plan section 4.4); the check
  // against the public record and the bond counter, read from the chain
  // (plan sections 6.7, 6.17).
  function openNetwork() {
    go("network");
    void schedulePublicRecordCheck(databasePath, "network-screen").catch(() => {});
  }

  function openTrustDetails() {
    setTrustDetails(null);
    loadTrustDetails(databasePath).then(setTrustDetails, () => setTrustDetails([]));
    go("trust-details");
  }

  // The banner every chat list shows while Morse's key log is in question
  // (blocking), or while the public record is behind (quiet).
  function renderTrustBanner() {
    const banner = trustBanner(networkStatus, Date.now());
    if (!banner) return null;
    if (!banner.blocking) return <Notice tone="warning" text={banner.text} />;
    return (
      <Tap label="Details" onPress={openTrustDetails} feedback="highlight">
        <Notice
          tone="error"
          text={`${banner.text} New chats and key changes are paused; existing chats keep working. Details`}
        />
      </Tap>
    );
  }

  function renderNetwork() {
    const now = Date.now();
    const counter = networkStatus ? bondCounterLine(networkStatus.bonds, networkStatus.anchor, now) : null;
    const lastCheck = networkStatus ? checkResultLine(networkStatus.anchor, now) : null;
    return (
      <Page header={<Header title="Network" onBack={() => go("settings")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          {networkStatus ? (
            <>
              <Text style={type.body}>{profileLine(networkStatus)}</Text>
              {networkStatus.updateRequired ? (
                <Notice
                  tone="warning"
                  text="A group you’re in moved to newer witnesses. Update Morse to keep using it."
                />
              ) : null}
              {renderTrustBanner()}
              {counter || lastCheck ? (
                <Section
                  title="Public record"
                  footer="Read from the chain through the providers this build pins, never through Morse. Nothing is reported back."
                >
                  <RowGroup>
                    {counter ? <Row icon="shield" title={counter} /> : null}
                    {lastCheck ? (
                      <Row
                        icon={networkStatus.alarm ? "warning" : "check"}
                        tone={networkStatus.alarm ? "danger" : "accent"}
                        title="Last check"
                        subtitle={lastCheck}
                      />
                    ) : null}
                    <Row
                      icon="info"
                      title="Details"
                      subtitle="Evidence this phone kept, and where it was filed"
                      onPress={openTrustDetails}
                    />
                  </RowGroup>
                </Section>
              ) : null}
              <Section
                title="Pinned witnesses"
                footer={`A key is used only once ${networkStatus.threshold} of these ${networkStatus.witnesses.length} witnesses have signed the key log that holds it.`}
              >
                <RowGroup>
                  {networkStatus.witnesses.map((witness) => {
                    const bond = witnessBondLine(networkStatus.bonds?.witnesses.find((row) => row.id === witness.id));
                    return (
                      <Row
                        key={witness.id}
                        icon="shield"
                        tone={witness.morseRun ? "muted" : "accent"}
                        title={witness.label}
                        subtitle={bond ? `${witness.id} · ${bond}` : witness.id}
                        trailing={witness.morseRun ? <Badge label="Run by Morse" tone="muted" /> : null}
                      />
                    );
                  })}
                </RowGroup>
              </Section>
              <BountyNoticeCard />
              <CollectBountiesRow />
            </>
          ) : (
            <Notice text="Network details aren’t available on this build." />
          )}
        </ScrollView>
      </Page>
    );
  }

  async function exportEvidence(bytes: Uint8Array) {
    try {
      // Anyone can land it: morse-relay submit evidence.frk (plan section 6.9).
      await saveAttachmentFile("evidence.frk", "application/octet-stream", bytes);
    } catch (caught) {
      setError(friendlyError(caught));
    }
  }

  const relayWords = { pending: "Not reached yet; tried again later", sent: "Received it", refused: "Refused it" } as const;
  const alarmTitles = {
    anchor_mismatch: "Morse’s key log doesn’t match the public record",
    service_slashed: "Morse’s key log was caught signing two versions",
    contact_fork: "A contact’s phone was shown a different key log",
  } as const;

  // Details: the two versions that disagree, each proof and the relays it went
  // to, and, once it landed, who the judge paid.
  function renderTrustDetails() {
    return (
      <Page header={<Header title="Details" onBack={() => go("network")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          {trustDetails === null ? null : trustDetails.length === 0 ? (
            <Notice text="Morse’s key log has matched the public record on every check this phone made." />
          ) : trustDetails.map((alarm, index) => (
            <Section
              key={`${alarm.kind}-${alarm.raisedAt}-${index}`}
              title={alarm.active ? alarmTitles[alarm.kind] : `${alarmTitles[alarm.kind]} (resolved)`}
              footer={alarm.proofs.length === 0
                ? "This phone kept the two versions but had no leaf it could prove differs; nothing was filed."
                : "Evidence goes to every relay this build pins. It holds Morse’s signed checkpoints and proofs over them, never your messages."}
            >
              <RowGroup>
                {alarm.yours ? (
                  <Row icon="key" title="Your phone’s version" subtitle={`${alarm.yours.treeSize.toLocaleString("en-US")} entries · ${hex(alarm.yours.root).slice(0, 16)}…`} />
                ) : null}
                {alarm.other ? (
                  <Row icon="shield" title={alarm.kind === "contact_fork" ? "Your contact’s version" : "The public record"} subtitle={`${alarm.other.treeSize.toLocaleString("en-US")} entries · ${hex(alarm.other.root).slice(0, 16)}…`} />
                ) : null}
                {alarm.kind === "contact_fork" ? (
                  <Row icon="info" title="Which phone was targeted" subtitle={forkTargetLine(forkTarget(alarm, trustDetails, networkStatus?.anchor))} />
                ) : null}
                {alarm.proofs.map((proof, position) => (
                  <View key={hex(proof.proofHash)}>
                    <Row
                      icon="file"
                      title={`Proof ${position + 1}${proof.complete ? "" : " (the relays complete it)"}`}
                      subtitle={proof.landed
                        ? `Landed in slot ${(proof.landedSlot ?? 0).toLocaleString("en-US")}; ${proof.paidElsewhere
                          ? `the bounty went to ${base58(proof.paidTo ?? new Uint8Array(32))}, not this phone`
                          : "the bounty went to this phone’s address"}`
                        : "Waiting to land on chain"}
                      trailing={<Button label="Export" variant="ghost" onPress={() => { void exportEvidence(proof.bytes); }} />}
                    />
                    {proof.relays.map((relay) => (
                      <Row key={relay.url} icon="link" tone={relay.status === "refused" ? "danger" : "muted"} title={relay.url.replace(/^https:\/\//, "")} subtitle={relayWords[relay.status]} />
                    ))}
                  </View>
                ))}
              </RowGroup>
            </Section>
          ))}
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
          {accountAway ? (
            <Notice
              tone="warning"
              text="Your account changed while this device was away. Check that you know every device below."
              onDismiss={() => setAccountAway(false)}
            />
          ) : null}
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
                      : device.expired
                        ? "Gets no messages until it’s opened again"
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
                        name={device.expired ? "warning" : device.active ? "check" : "close"}
                        color={device.expired ? colors.warning : device.active ? colors.success : colors.text3}
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
    // Once its invitation arrives, an approved request is that invitation.
    const asked = communityAsks.filter((ask) => ask.state !== "approved" ||
      !groupInvitations.some((item) => hex(item.groupId) === ask.part));
    const openGroupId =
      sidebar && selectedGroupId && (screen === "group" || screen === "group-info")
        ? hex(selectedGroupId)
        : null;
    return (
      <FlatList
        contentContainerStyle={sidebar ? layout.sidebarList : layout.list}
        // The most recently active first, as chats are.
        data={[...listedGroups].sort((a, b) => (groupLast(b)?.timestamp ?? 0) - (groupLast(a)?.timestamp ?? 0))}
        keyExtractor={(group) => hex(group.groupId)}
        ItemSeparatorComponent={sidebar ? null : ListSeparator}
        ListHeaderComponent={incoming.length || asked.length ? (
          <View style={styles.listHeader}>
            {asked.length ? (
              <Section title="Asked to join">
                {asked.map((ask) => (
                  <Card key={ask.community}>
                    <Text style={type.headline}>{ask.name}</Text>
                    <Text style={type.body}>
                      {ask.state === "approved" ? `@${ask.conversation.username} let you in. Joining…`
                        : ask.state === "declined" ? `@${ask.conversation.username} didn’t let you in.`
                        : `Waiting for @${ask.conversation.username} to let you in.`}
                    </Text>
                  </Card>
                ))}
              </Section>
            ) : null}
            {incoming.length ? <Section title="Invitations">
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
            </Section> : null}
          </View>
        ) : null}
        ListEmptyComponent={sidebar ? <SidebarEmptyState title="No groups yet." /> : (
          <EmptyState
            icon="groups"
            title="No groups yet."
            body={`Ask a member to invite @${ownUsername}, or open a community’s link. Invitations appear here.`}
            action={
              <View style={layout.row}>
                <Button label="Start a group" onPress={createNewGroup} />
                <Button label="Join a community" variant="ghost" onPress={() => openScanner("community")} />
              </View>
            }
          />
        )}
        renderItem={({ item }) => (
          <GroupRow
            name={groupName(item.groupId)}
            avatar={groupAvatar(item.groupId)}
            colorSeed={hex(item.groupId)}
            label={groupName(item.groupId)}
            subtitle={groupPreviewText(item)}
            time={groupLast(item) ? formatInboxTime(groupLast(item)!.timestamp) : ""}
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
                  label="Join a community"
                  variant="tonal"
                  name="link"
                  onPress={() => openScanner("community")}
                />
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

  const askedWhen = (timestamp: number) => {
    const when = formatInboxTime(timestamp);
    return /^\d/.test(when) ? `Asked at ${when}` : `Asked ${when === "Yesterday" ? "yesterday" : when}`;
  };

  // An admin answers someone who asked, through their link, to join.
  function renderReviewDialog(name: string) {
    const identity = reviewing ? senderIdentity(reviewing.conversation.peerAccountId) : null;
    const buttonSize = isDesktop ? "sm" : "md";
    return (
      <Dialog visible={Boolean(reviewing)} label={identity ? `Review ${identity.name}` : "Review"} onClose={() => setReviewing(null)}>
        {reviewing && identity ? (
          <>
            <View style={styles.dialogHero}>
              <Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar["2xl"]} />
              <Text numberOfLines={1} style={type.title2}>{identity.name}</Text>
              <Text style={type.subhead}>{`${askedWhen(reviewing.request.timestamp)} to join ${name}`}</Text>
            </View>
            <View style={styles.dialogActions}>
              <Button label="Let them in" size={buttonSize} disabled={preview !== null}
                onPress={() => approveAsk(reviewing.conversation, reviewing.request)} />
              <Button label="Decline" variant="secondary" size={buttonSize} disabled={preview !== null}
                onPress={() => declineAsk(reviewing.conversation, reviewing.request)} />
            </View>
          </>
        ) : null}
      </Dialog>
    );
  }

  // What the owner can make of one person: admin or owner, or no longer either.
  function renderRoleDialog(community: Community) {
    const accountId = managing;
    const identity = accountId ? senderIdentity(accountId) : null;
    const admin = Boolean(accountId && community.admins.includes(accountId));
    const act = (run: () => void) => { setManaging(null); run(); };
    const buttonSize = isDesktop ? "sm" : "md";
    return (
      <Dialog visible={Boolean(accountId && identity)} label={identity ? `Manage ${identity.name}` : "Manage"} onClose={() => setManaging(null)}>
        {accountId && identity ? (
          <>
            <View style={styles.dialogHero}>
              <Avatar name={identity.name} uri={identity.avatar} colorSeed={accountId} size={size.avatar["2xl"]} />
              <Text numberOfLines={1} style={type.title2}>{identity.name}</Text>
              <Text style={type.subhead}>{admin ? "Admin" : "Member"}</Text>
            </View>
            <View style={styles.dialogActions}>
              {admin ? (
                <>
                  <Button label="Make owner" size={buttonSize} onPress={() => act(() => confirmHandover(accountId, identity.name))} />
                  <Button label="Remove as admin" variant="secondary" size={buttonSize}
                    onPress={() => act(() => changeRoles({ admins: community.admins.filter((item) => item !== accountId) },
                      `${identity.name} is no longer an admin`))} />
                </>
              ) : (
                <>
                  <Button label="Make admin" size={buttonSize} disabled={community.admins.length >= MAX_ADMINS}
                    onPress={() => act(() => changeRoles({ admins: [...community.admins, accountId] }, `${identity.name} is an admin now`))} />
                  <Button label="Remove from community" variant="secondary" size={buttonSize}
                    onPress={() => act(() => removeFromCommunity(accountId, identity.name))} />
                </>
              )}
            </View>
          </>
        ) : null}
      </Dialog>
    );
  }

  // A community's details: what it is for, the requests its owner and admins
  // answer, its groups with the way in that fits each reader, who runs it and,
  // for those who run it, everyone in it across its parts.
  function renderCommunityInfo(entry: CommunityEntry) {
    const community = entry.community;
    const primary = fromHex(entry.parts[0]!);
    const name = groupName(primary);
    const avatar = groupAvatar(primary);
    const setPhoto = (value: string | undefined) => updateAvatar(`group/${entry.parts[0]}`, name, value);
    const everyone = [...new Map(Object.values(communityData).flatMap((part) => part.details.members)
      .map((member) => [hex(member.deviceId), member])).values()];
    const summary = everyone.length ? summarizeMembers(everyone) : null;
    const staff = [community.owner, ...community.admins];
    const others = (summary?.people ?? []).filter((item) => !staff.includes(hex(item.accountId)));
    const linkable = groups.filter((item) => !communityOfGroup(hex(item.groupId)) &&
      !community.groups.some((group) => group.id === hex(item.groupId)));
    const members = (count: number) => `${count} ${count === 1 ? "member" : "members"}`;
    const canInvite = preview === null && groupUsername.trim().length > 0;
    const pending = [...new Map(groupInvitations
      .filter((item) => entry.parts.includes(hex(item.groupId)) && (item.state === 0 || item.state === 3))
      .map((item) => [hex(item.accountId), item])).values()];
    const spread = community.parts.length > 1 ? `Spread across ${community.parts.length} groups of up to 64 devices. ` : "";
    const communityLink = payloadQrValue("community", utf8(encodeCommunityLink({ community: communityId(community), admin: ownUsername || "_", name })));
    return (
      <Page header={<Header title="Community details" onBack={() => go("group")} />}>
        {renderRoleDialog(community)}
        {renderReviewDialog(name)}
        <ScrollView
          contentContainerStyle={layout.contentTight}
          keyboardShouldPersistTaps="handled"
        >
          <Hero
            name={name}
            avatar={avatar}
            colorSeed={entry.parts[0]}
            group
            leading={canManage ? renderPhotoButton(name, avatar, setPhoto, { group: true, seed: entry.parts[0] }) : undefined}
            title={name}
            subtitle={canManage && summary ? `Community · ${describeMembers(summary)}` : "Community"}
            actions={canManage && avatar ? renderRemovePhoto(() => setPhoto(undefined)) : undefined}
          />
        {canManage ? (
          <Section title="About">
            <Card>
              <Field
                label="Description"
                value={aboutDraft ?? community.about}
                onChangeText={setAboutDraft}
                placeholder="What this community is for"
                multiline
                maxLength={500}
              />
              {aboutDraft !== null && aboutDraft.trim() !== community.about ? (
                <Actions>
                  <Button label="Save description" onPress={() => saveCommunity({ ...community, about: aboutDraft }, "Description saved")} />
                </Actions>
              ) : null}
            </Card>
          </Section>
        ) : community.about ? (
          <Section title="About">
            <Card><Text style={type.body}>{community.about}</Text></Card>
          </Section>
        ) : null}
        {incomingAsks.length ? (
          <Section title="Asking to join" footer="They opened your link. Letting someone in accepts their message request and invites them.">
            <RowGroup>
              {incomingAsks.map(({ conversation, request }) => {
                const identity = senderIdentity(conversation.peerAccountId);
                return (
                  <Row
                    key={request.key}
                    leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar.md} />}
                    title={identity.name}
                    subtitle={askedWhen(request.timestamp)}
                    trailing={
                      <Button label="Review" accessibilityLabel={`Review ${identity.name}`} variant="secondary" size="sm"
                        onPress={() => setReviewing({ conversation, request })} />
                    }
                  />
                );
              })}
            </RowGroup>
          </Section>
        ) : null}
        {joinWaiting.length ? (
          <Section title="Join requests" footer="Inviting sends that group’s usual encrypted invitation.">
            <RowGroup>
              {joinWaiting.map((request) => {
                const identity = senderIdentity(request.accountId);
                const group = community.groups.find((item) => item.id === request.groupId);
                return (
                  <Row
                    key={`${request.accountId}/${request.groupId}`}
                    leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar.md} />}
                    title={identity.name}
                    subtitle={`Asked to join ${group?.name ?? "a group"}`}
                    trailing={
                      <Button
                        label="Invite"
                        accessibilityLabel={`Invite ${identity.name} to ${group?.name ?? "the group"}`}
                        size="sm"
                        disabled={!identity.username}
                        onPress={() => identity.username && approveRequest(request, identity.username)}
                      />
                    }
                  />
                );
              })}
            </RowGroup>
          </Section>
        ) : null}
        <Section
          title="Groups"
          footer={canManage
            ? "Members see these names and can ask to join. You invite them from here."
            : "Ask to join a group and the community’s owner or an admin can invite you."}
        >
          {community.groups.length ? (
            <RowGroup>
              {community.groups.map((group) => {
                const joined = groups.find((item) => hex(item.groupId) === group.id);
                const invitation = groupInvitations.find((item) => hex(item.groupId) === group.id && (item.state === 1 || item.state === 2));
                const requested = communityRequests.some((item) => item.accountId === ownId && item.groupId === group.id);
                return (
                  <Row
                    key={group.id}
                    leading={<Avatar name={group.name} uri={presentationOf(`group/${group.id}`)?.avatar} colorSeed={group.id} size={size.avatar.md} group />}
                    title={group.name}
                    subtitle={joined ? members(joined.memberCount) : undefined}
                    onPress={joined ? () => openGroup(joined) : undefined}
                    trailing={
                      canManage ? (
                        <Button
                          label="Unlink"
                          accessibilityLabel={`Unlink ${group.name}`}
                          variant="secondary"
                          size="sm"
                          onPress={() => saveCommunity({ ...community, groups: community.groups.filter((item) => item.id !== group.id) }, `${group.name} unlinked`)}
                        />
                      ) : joined ? (
                        <Badge label="Joined" />
                      ) : invitation?.state === 1 ? (
                        <Button label="Join" accessibilityLabel={`Join ${group.name}`} size="sm" onPress={() => answerGroupInvitation(invitation, true)} />
                      ) : invitation ? (
                        <Badge label="Joining" tone="accent" />
                      ) : requested ? (
                        <Badge label="Requested" tone="muted" />
                      ) : (
                        <Button
                          label="Ask to join"
                          accessibilityLabel={`Ask to join ${group.name}`}
                          variant="secondary"
                          size="sm"
                          disabled={preview !== null}
                          onPress={() => askToJoin(group.id)}
                        />
                      )
                    }
                  />
                );
              })}
            </RowGroup>
          ) : (
            <Card>
              <Text style={type.body}>{canManage ? "Link groups you’re in so members can find them." : "No groups yet."}</Text>
            </Card>
          )}
        </Section>
        {canManage ? (
          <Section
            title="Disappearing announcements"
            footer="Only you and the other admins set it. Announcements go from every member’s device when their time is up."
          >
            <RowGroup>
              <Row
                icon="timer"
                title="Timer"
                subtitle={disappearingOptions.find((option) => option.value === (groupTimers[entry.parts[0]!] ?? 0))?.label
                  ?? timerLength(groupTimers[entry.parts[0]!] ?? 0)}
                trailing={
                  <Segmented
                    label="Disappear"
                    options={disappearingOptions}
                    value={groupTimers[entry.parts[0]!] ?? 0}
                    onSelect={(seconds) => {
                      // Every part carries the same timer, as it carries the same record.
                      if (preview === null && !busy) changeGroupTimer(entry.parts.map(fromHex), seconds);
                    }}
                  />
                }
              />
            </RowGroup>
          </Section>
        ) : null}
        {canManage && linkable.length ? (
          <Section title="Link a group">
            <RowGroup>
              {linkable.map((item) => (
                <Row
                  key={hex(item.groupId)}
                  leading={<Avatar name={groupName(item.groupId)} uri={groupAvatar(item.groupId)} colorSeed={hex(item.groupId)} size={size.avatar.md} group />}
                  title={groupName(item.groupId)}
                  subtitle={members(item.memberCount)}
                  trailing={
                    <Button
                      label="Link"
                      accessibilityLabel={`Link ${groupName(item.groupId)}`}
                      variant="secondary"
                      size="sm"
                      onPress={() => saveCommunity({ ...community, groups: [...community.groups, { id: hex(item.groupId), name: groupName(item.groupId) }] },
                        `${groupName(item.groupId)} linked`)}
                    />
                  }
                />
              ))}
            </RowGroup>
          </Section>
        ) : null}
          {canManage && ownUsername ? (
            <Section
              title="Invite link"
              footer="Anyone with this link or code can ask you to let them in. Their request comes to you as a message."
            >
              <QrCard value={communityLink} caption="Scan with Morse to ask to join" />
              <Actions>
                <Button label="Copy link" icon="copy" variant="secondary" onPress={() => copyCommunityLink(communityLink)} />
              </Actions>
            </Section>
          ) : null}
          {canManage ? (
            <Section
              title="Invite members"
              footer="They’ll receive an encrypted invitation and choose whether to join. Or scan the code from their Groups tab to add them right away."
            >
              <Card>
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
                    <Button label="Send invitation" disabled={!canInvite} onPress={inviteByUsername} />
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
          ) : null}
          <Section
            title="Admins"
            footer={isOwner
              ? "Admins post announcements, answer requests, invite and remove members, and edit the community. Only you change who runs it."
              : "They post the announcements and invite people to the community’s groups."}
          >
            <RowGroup>
              {staff.map((accountId) => {
                const identity = senderIdentity(accountId, accountId === ownId);
                return (
                  <Row
                    key={accountId}
                    leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={accountId} size={size.avatar.md} />}
                    title={identity.name}
                    subtitle={accountId === community.owner ? "Owner" : "Admin"}
                    trailing={accountId === ownId ? (
                      <Badge label="You" />
                    ) : isOwner ? (
                      <Button label="Manage" accessibilityLabel={`Manage ${identity.name}`} variant="secondary" size="sm"
                        onPress={() => setManaging(accountId)} />
                    ) : null}
                  />
                );
              })}
            </RowGroup>
          </Section>
          {canManage ? (
            <Section title="Members" footer={`${spread}Members see only who runs the community.`}>
              {!summary ? (
                <Card style={layout.center}>
                  <ActivityIndicator color={colors.accent} />
                </Card>
              ) : others.length ? (
                <RowGroup>
                  {others.map((item) => {
                    const identity = senderIdentity(item.accountId, item.local);
                    const accountId = hex(item.accountId);
                    return (
                      <Row
                        key={accountId}
                        leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={accountId} size={size.avatar.md} />}
                        title={identity.name}
                        subtitle={[describeMember({ local: item.local, creator: false, conversation: identity.conversation }),
                          item.devices > 1 ? `${item.devices} devices` : undefined].filter(Boolean).join(" · ") || undefined}
                        trailing={isOwner ? (
                          <Button label="Manage" accessibilityLabel={`Manage ${identity.name}`} variant="secondary" size="sm"
                            onPress={() => setManaging(accountId)} />
                        ) : (
                          <Button
                            label="Remove"
                            accessibilityLabel={`Remove ${identity.name}`}
                            variant="secondary"
                            size="sm"
                            disabled={preview !== null}
                            onPress={() => removeFromCommunity(accountId, identity.name)}
                          />
                        )}
                      />
                    );
                  })}
                </RowGroup>
              ) : (
                <Card>
                  <Text style={type.body}>No one else yet. Invite members above.</Text>
                </Card>
              )}
            </Section>
          ) : null}
          {canManage && pending.length > 0 ? (
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
          <Section footer={isOwner ? "Make an admin the owner before you leave." : undefined}>
            <RowGroup>
              <Row
                icon="close"
                tone="danger"
                emphasis="danger"
                title="Leave community"
                onPress={isOwner || preview ? undefined : () => confirmLeave(entry)}
              />
            </RowGroup>
          </Section>
        </ScrollView>
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
          <Section
            title="Disappearing messages"
            footer="Anyone in the group can change it, and everyone’s messages follow it, even on devices that join later. Messages go from every device when their time is up."
          >
            <RowGroup>
              <Row
                icon="timer"
                title="Timer"
                subtitle={disappearingOptions.find((option) => option.value === (groupTimers[hex(groupId)] ?? 0))?.label ?? timerLength(groupTimers[hex(groupId)] ?? 0)}
                trailing={
                  <Segmented
                    label="Disappear"
                    options={disappearingOptions}
                    value={groupTimers[hex(groupId)] ?? 0}
                    onSelect={(seconds) => { if (preview === null && !busy) changeGroupTimer([groupId], seconds); }}
                  />
                }
              />
            </RowGroup>
          </Section>
          {groupDetails?.senderSigning ? (
            <Section
              title="Message signing"
              footer={groupDetails.senderSigning === 2
                ? "Members' devices check your messages here with a key your device gave each of them in your direct chat. That shows them it was you, and proves nothing to anyone else."
                : "Your messages here carry your device's own signature, which can show anyone they came from you. They become deniable once your device and every other device in the group have exchanged direct messages."}
            >
              <RowGroup>
                <Row title={groupDetails.senderSigning === 2 ? "Deniable" : "Signed with your device key"} />
              </RowGroup>
            </Section>
          ) : null}
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
    const mentionSource = selectedEntry ? Object.values(communityData).flatMap((part) => part.details.members) : groupDetails?.members ?? [];
    const mentionMembers = [...new Map(mentionSource.map((member) => [hex(member.accountId), member])).values()].flatMap((member) => {
      const identity = senderIdentity(member.accountId, member.local);
      return identity.username ? [{ username: identity.username, name: identity.name }] : [];
    });
    const scope = `group/${hex(groupId)}`;
    // Asked to join the community itself, or one of its groups.
    const waiting = joinWaiting.length + incomingAsks.length;
    // In a community only the owner and admins post, so only they reply.
    const readOnly = Boolean(selectedCommunity) && !canManage;
    const canReply = (selectedGroup?.memberCount ?? 0) >= 2 && !readOnly;
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
            onAvatarPress={() => selectedCommunity ? go("group-info") : setMembersOpen(true)}
            avatarLabel={selectedCommunity ? "Community details" : "Group members"}
            onInfo={() => go("group-info")}
            infoLabel={selectedCommunity ? "Community details" : "Group details"}
          />
        }
      >
        {renderGroupMembers(groupId)}
        {waiting ? (
          <View style={[styles.banners, isDesktop && layout.threadContent]}>
            <Card tone="accent">
              <Text style={type.body}>
                {waiting === 1 ? "Someone is" : `${waiting} people are`} waiting for you to let them in.
              </Text>
              <Actions>
                <Button label="Review requests" size="sm" onPress={() => go("group-info")} />
              </Actions>
            </Card>
          </View>
        ) : null}
        <FlatList
          ref={(list) => { thread.current = list; }}
          onScrollToIndexFailed={retryShowOriginal}
          inverted
          data={groupScope ? groupRows : []}
          contentContainerStyle={[layout.messages, { paddingTop: composerHeight + composerClearance },
            waiting > 0 && styles.messagesBelowBanners]}
          keyExtractor={(row) => row.key}
          ListEmptyComponent={
            <View style={styles.flipped}>
              {selectedCommunity ? (
                <EmptyState
                  icon="megaphone"
                  title="No announcements yet."
                  body={canManage ? "Only you and the other admins post here. Members read, react and find the community’s groups in its details." : "Announcements from the people who run the community appear here. Find its groups in its details."}
                />
              ) : (
                <EmptyState
                  icon="lock"
                  title="Nothing here yet."
                  body="Add people from group details to begin."
                />
              )}
            </View>
          }
          renderItem={({ item }) =>
            item.kind === "day" ? (
              <DayDivider label={item.label} />
            ) : item.message.timerNotice !== undefined ? (
              <DayDivider label={timerNotice(
                item.message.direction === "sent" || hex(item.message.senderAccountId) === accountId
                  ? "You" : senderIdentity(item.message.senderAccountId, false).name,
                item.message.timerNotice)} />
            ) : item.message.viewOnce ? (
              <ViewOnceBubble
                text={viewOnceText({
                  direction: item.message.direction === "sent" || hex(item.message.senderAccountId) === accountId ? "sent" : "received",
                  viewOnce: item.message.viewOnce,
                })}
                sent={item.message.direction === "sent" || hex(item.message.senderAccountId) === accountId}
                timestamp={item.message.timestamp}
                tail={item.tail}
                spaced={item.spaced}
                onOpen={item.message.direction === "received" && hex(item.message.senderAccountId) !== accountId
                  && item.message.viewOnce === "unopened" ? () => openViewOnceMessage(item.message) : undefined}
              />
            ) : (
              <MessageBubble
                body={item.message.body}
                action={communityLinkAction(item.message.body)}
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
                reactionsDisabled={busy || (selectedGroup?.memberCount ?? 0) < 2}
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
          viewOnce={preview === null && !selectedCommunity
            ? { on: viewOnceScope === scope, onToggle: () => toggleViewOnce(scope) } : undefined}
          disabled={busy || preview !== null || readOnly}
          placeholder={preview ? "Sample preview · read-only" : readOnly ? "Only admins post here"
            : selectedCommunity ? "Announce something" : "Message · @mention someone"}
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
              {networkStatus ? (
                <Row
                  icon="checks"
                  tone="muted"
                  title={keyCheckedLine(networkStatus)}
                  subtitle={networkStatus.witnesses.map((witness) => `${witness.id}: ${witnessNote(witness)}`).join(" · ")}
                />
              ) : null}
              {conversation.safetyNumber && preview === null ? (
                <Row
                  icon="qr"
                  title="Verify with a code"
                  subtitle={isDesktop ? "Show your code, or paste theirs" : "Scan their code, or show yours"}
                  onPress={() => openSafetyCode(conversation)}
                />
              ) : null}
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
    const resetNotice = sessionResetNotice(conversation);
    const banners = conversation.requestPending || conversation.keyChanged || conversation.blocked || resetNotice;
    const scope = `chat/${conversation.conversationId.join(".")}`;
    const canReply = !conversation.blocked && !conversation.requestPending;
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
            {resetNotice ? <Notice text={resetNotice} /> : null}
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
            ) : item.message.viewOnce ? (
              <ViewOnceBubble
                text={viewOnceText({ direction: item.message.direction, viewOnce: item.message.viewOnce })}
                sent={item.message.direction === "sent"}
                timestamp={item.message.timestamp}
                tail={item.tail}
                spaced={item.spaced}
                onOpen={item.message.direction === "received" && item.message.viewOnce === "unopened"
                  ? () => openViewOnceMessage(item.message) : undefined}
              />
            ) : (
              <MessageBubble
                body={item.message.body}
                action={communityLinkAction(item.message.body)}
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
                reactionsDisabled={busy || conversation.blocked || conversation.requestPending}
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
          viewOnce={preview === null ? { on: viewOnceScope === scope, onToggle: () => toggleViewOnce(scope) } : undefined}
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
        ListHeaderComponent={<>{renderTrustBanner()}<BountyNoticeCard /></>}
        ListEmptyComponent={sidebar ? <SidebarEmptyState title="No chats yet." /> : (
          <EmptyState
            icon="chat"
            title="No conversations yet."
            body={firstChatHint}
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

  // A new account's first step: whom to write to, and how others find you.
  const firstChatHint = `Message someone by their exact username. People can find you as\u00A0@${ownUsername}.`;

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

  // What the pane shows while the sidebar list is the selected screen. Until
  // there is a conversation to choose, it is where a new account starts.
  function renderPanePlaceholder(list: SidebarList) {
    if (list === "chats" && homeItems.length === 0) return (
      <EmptyState
        icon="chat"
        title="No conversations yet."
        body={firstChatHint}
        action={
          <View style={layout.row}>
            <Button label="New message" icon="compose" onPress={() => go("new-chat")} />
            <Button label="My QR code" variant="ghost" onPress={() => go("account")} />
          </View>
        }
      />
    );
    if (list === "groups" && groups.length === 0 && groupInvitations.length === 0) return (
      <EmptyState
        icon="groups"
        title="No groups yet."
        body={`Start one, or ask a member to invite\u00A0@${ownUsername}.`}
        action={
          <View style={layout.row}>
            <Button label="Create group" icon="plus" onPress={createNewGroup} />
            <Button label="Join a community" variant="ghost" onPress={() => openScanner("community")} />
            <Button label="Join with a code" variant="ghost" onPress={showGroupKeyPackage} />
          </View>
        }
      />
    );
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
            <Button label="Join a community" variant="ghost" onPress={() => openScanner("community")} />
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
                {/* The strip fits two actions; a group code is offered in the pane beside it. */}
                <IconButton
                  name="link"
                  label="Join a community"
                  variant="tonal"
                  size={chrome.sidebarControl}
                  onPress={() => openScanner("community")}
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
    if (onboardingActive)
      return onboardingStep === "profile" ? renderProfileSetup() : renderWelcome();
    if (screen === "link-device" && linkRequest) return renderLinkDevice(linkRequest);
    if (screen === "scanner") return renderScanner();
    if (screen === "new-chat") return renderNewChat();
    if (screen === "account" && profile) return renderAccount(profile);
    if (screen === "settings") return renderSettings();
    if (screen === "devices") return renderDevices();
    if (screen === "network") return renderNetwork();
    if (screen === "wallet") return <WalletScreen onBack={() => go("settings")} />;
    if (screen === "backups") {
      return (
        <BackupsScreen
          key={backupStart}
          start={backupStart}
          onBack={() => go(backupStart === "recover" ? "home" : "settings")}
          onRestored={backupRestored}
          onRecovered={async () => { setProfile(await load_profile_export(utf8(databasePath))); }}
          onReviewDevices={openDevices}
          onLinkInstead={() => { setRestoreAfterLink(true); beginDeviceLink(); }}
        />
      );
    }
    if (screen === "credits") return <CreditsScreen onBack={() => go("settings")} />;
    if (screen === "trust-details") return renderTrustDetails();
    if (screen === "link-authorization" && linkAuthorization)
      return renderLinkAuthorization(linkAuthorization);
    if (screen === "group-package" && groupKeyPackage)
      return renderGroupPackage(groupKeyPackage);
    if (screen === "new-group") return renderNewGroup();
    if (screen === "groups") return split ? renderPanePlaceholder("groups") : renderGroups();
    if (screen === "group-info" && selectedEntry) return renderCommunityInfo(selectedEntry);
    if (screen === "group-info" && selectedGroupId) return renderGroupInfo(selectedGroupId);
    if (screen === "group" && selectedGroupId) return renderGroup(selectedGroupId);
    if (screen === "chat-info" && selected) return renderChatInfo(selected);
    if (screen === "chat" && selected) return renderChat(selected);
    return split ? renderPanePlaceholder("chats") : renderHome();
  }

  const ready = fontsReady && !initialLoading;
  const screenKey: ScreenKey = onboardingActive
    ? onboardingStep === "profile"
      ? "onboarding-profile"
      : "onboarding"
    : screen;
  const pane = (
    // Keyboard frames are in screen coordinates but the pane starts under the
    // top inset, which the view's own layout frame leaves out.
    <KeyboardAvoidingView
      behavior={Platform.OS === "web" ? undefined : "padding"}
      keyboardVerticalOffset={initialWindowMetrics?.insets.top ?? 0}
      style={[layout.flex, isDesktop && screenKey === "onboarding" && styles.desktopOnboarding]}
      onLayout={({ nativeEvent: { layout: { x, y } } }) => setPaneOffset({ x, y })}
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
  // Status floats over the foot of the pane, clear of a composer or the tab
  // bar. Every error can be dismissed; an action's error goes first, then
  // the mailbox's.
  const statusPill = (
    <StatusPill
      text={error || (busy ? status : shownSyncError)}
      busy={busy && !error}
      error={error.length > 0 || shownSyncError.length > 0}
      onDismiss={() => (error ? setError("") : setDismissedSyncError(syncError))}
      lift={mainScreen && !split ? chrome.tabBarSpace : composerHeight}
    />
  );
  const main = (
    <View style={layout.flex} onLayout={({ nativeEvent: { layout: { x, y, height } } }) => setMainFrame({ x, y, height })}>
      {pane}
      {statusPill}
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
        <Wallpaper />
        {/* The pane's frame reaches down to the window's foot, where the tab
            bar floats; each screen's Page narrows it to its own height. */}
        <WallpaperFrame.Provider
          value={{ x: mainFrame.x + paneOffset.x, y: mainFrame.y + paneOffset.y, height: mainFrame.height - paneOffset.y }}
        >
          {split ? renderSidebar() : null}
          {main}
          {/* Screens without a toolbar still need to move the window. It comes
              after the pane so it paints over the pane's empty top. */}
          {isDesktop && screenKey === "onboarding" ? <DragStrip /> : null}
          {mainScreen && !split ? (
            <TabBar
              tabs={tabs.map((tab) => ({ ...tab, badge: tab.key === "home" ? chatBadgeCount : tab.key === "groups" ? groupBadgeCount : 0 }))}
              current={screen as (typeof tabs)[number]["key"]}
              onSelect={go}
            />
          ) : null}
        </WallpaperFrame.Provider>
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
      <ViewOnceDialog opened={viewing} onClose={closeViewOnce} />
      {selected ? (
        <SafetyCodeDialog
          visible={safetyCodeOpen}
          username={selected.username}
          code={safetyCodeValue}
          onCheck={async (text) => {
            const outcome = await checkSafetyCode(databasePath, selected.peerAccountId, text);
            await refreshConversations();
            return outcome;
          }}
          onClose={() => setSafetyCodeOpen(false)}
        />
      ) : null}
      <CreditPrompts />
      <Modal visible={pendingConfirm !== null} transparent onRequestClose={() => setPendingConfirm(null)}>
        <View style={styles.confirmOverlay}>
          <Card style={styles.confirmCard}>
            <Text style={type.title2}>{pendingConfirm?.title}</Text>
            <Text style={type.body}>{pendingConfirm?.body}</Text>
            <View style={styles.confirmActions}>
              <Button label="Cancel" variant="secondary" onPress={() => setPendingConfirm(null)} />
              <Button label={pendingConfirm?.action ?? ""} variant="danger" onPress={() => {
                pendingConfirm?.run();
                setPendingConfirm(null);
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
  // The welcome's words and picture, as one centred spread.
  desktopOnboarding: { width: "100%", maxWidth: 960, alignSelf: "center" },
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
  // The welcome step fills the pane, so the buttons stay where a thumb
  // expects them; the picture above the words takes up the slack.
  welcome: {
    flexGrow: 1,
    paddingHorizontal: space[6],
    paddingTop: space[3],
    paddingBottom: space[4],
  },
  // Words on the left, the picture on the right, the pair centred in the
  // window and clear of the window buttons above.
  welcomeDesktop: {
    flexDirection: "row-reverse",
    alignItems: "center",
    justifyContent: "center",
    gap: space[12],
    paddingHorizontal: space[10],
    paddingTop: TOOLBAR_HEIGHT + space[4],
    paddingBottom: space[12],
  },
  welcomeCopy: isDesktop ? { flexGrow: 1, flexBasis: 0, maxWidth: 400, gap: space[6] } : { gap: space[5] },
  heroBlock: { gap: space[2.5] },
  facts: { gap: isDesktop ? space[2.5] : space[3] },
  // A phone centres who you are over the form, as the You screen does.
  profileHead: { gap: space[2.5], alignItems: "center" },
  // Full bleed: the header floats over the feed and the reticle frames it.
  camera: { flex: 1, backgroundColor: colors.black },
  photoEditor: { flexDirection: "row", alignItems: "center", gap: space[3] },
  profileCard: { flexDirection: "row", alignItems: "center", gap: space[4] },
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
