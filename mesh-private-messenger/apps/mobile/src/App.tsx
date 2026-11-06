import { ActivityModal as Modal, ActivityOverlayHost, useActivityOverlay } from "./activity-overlays";
import { BackupExportScreen } from './BackupExportScreen';
import { BackupArchiveScreen } from './BackupArchiveScreen';
import { backupArchiveLabels, pendingBackupExportLabels } from './backup-labels';
import type { AppServices } from './app-lock-services';
import { HistoryCacheEpoch, replaceHistoryCache } from "./history-cache-epoch";
import { NetworkCounter } from './NetworkCounter';
import { authorizeAttachmentRecipients, type AttachmentRecipients } from './network';
import {
  BarcodeScanningResult,
  CameraView,
  useCameraPermissions,
} from "expo-camera";
import { StatusBar } from "expo-status-bar";
import { useEffect, useLayoutEffect, useRef, useState, type ComponentProps, type ReactNode } from "react";
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
import { isDirectoryRegistrationRefused } from "./native-directory";
import { encodeReceipt, messageStatus, receiptDue, type ReceiptMarks } from "./receipts";
import {
  ActivityIndicator,
  Alert,
  AppState,
  BackHandler,
  Keyboard,
  Platform,
  StyleSheet,
  Text,
  View,
  useWindowDimensions,
  type FlatListInstance,
  type TextInputInstance,
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
  transparency_fork_export,
  anchor_check_export,
  fork_filing_export,
} from "../modules/mesh-messenger";
import { parseAnchorObservation, describeAnchorObservation, type AnchorObservation } from "./anchor";
import { AnchorCheckpointTime } from "./AnchorCheckpointTime";
import { parseFilingObservation, describeFilingObservation, type FilingObservation } from "./filing";
import {
  attachmentPreviewUri,
  discardPreviews,
  listenForIncomingFiles,
  pickAttachmentSelections,
  releasePreviewUri,
  saveAttachmentFile,
} from "./attachment-io";
import {
  attachmentPreviewText,
  composerScope,
  describeAttachmentState,
  formatBytes,
  isImageAttachment,
  shouldAutoDownload,
  type AttachmentState,
} from "./attachments";
import { AttachmentPreviewSession } from "./attachment-preview-session";
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
import { formatInboxTime, friendlyError, sameDay } from "./format";
import { Glass } from "./glass";
import { describeMember, describeMembers, summarizeMembers, type Person } from "./group-members";
import { historyRefreshDelay, unexpiredHistory } from "./expiry";
import { createMailboxSync } from "./mailbox-sync";
import { accountProfileIdentity, captureErasureNotifications, finishAccountErasure, isMissingAccountProfile } from "./account-lifecycle";
import { presentedAccountNotifications, dismissAccountNotification } from "./account-notifications";
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
  VerifiedDirectoryRemoval,
  PostageRequired,
  onPostageRequired,
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
  deleteAccount,
  downloadAttachment,
  discardAccount,
  getGroupKeyPackage,
  GROUP_KEY_PACKAGE_LENGTH,
  holdsAccountKey,
  inspectGroup,
  listGroups,
  loadAccountDevices,
  loadGroupHistory,
  groupMessageTimer,
  onUndeliverable,
  registerDirectory,
  resolveDeviceSet,
  type Removal,
  removeGroupMember,
  revokeDevice,
  sendFanout,
  sendGroupMessage,
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
import { safetyQrValue, safetyFromQr, safetyVerificationRequest } from "./safety-qr";
import { Fact, IdentityPreview, SealedChat, Steps, Strong } from "./onboarding";
import { usernameProblem } from "./username";
import { KeyboardAwareScrollView } from "./keyboard";
import { richText, useI18n } from "./language";
import { languages, msg, type Language, type LanguageChoice, type MessageKey } from "./i18n";
import { FlatList, ScrollView } from "./scroll";
import { StartupScreen } from "./StartupScreen";
import { CreditsScreen } from "./CreditsScreen";
import { PostagePanel } from "./PostagePanel";
import { PostagePolicy } from "./PostagePolicy";
import { BountyPanel } from "./BountyPanel";
import { PaidUploadList } from "./PaidUploadList";
import { previewAttachmentSelections, savedAttachmentUpload, sendAttachmentUploads, type AttachmentUpload } from "./attachment-compose";
import { attachmentSelectionLimit, smallAttachmentSelection, MAXIMUM_ATTACHMENT_SIZE, type AttachmentSelection } from "./attachment-selections";
import { readAttachmentDownloadPlan, downloadPaidAttachment } from "./paid-attachments";
import { createAttachmentRangeSink } from "./attachment-range-io";
import { CreditSignupScreen } from "./CreditSignupScreen";
import {
  createCreditSignupDraft, loadCreditSignupPolicy, readCreditSignupDraftState, selectFreeCreditSignup, completeFreeCreditSignup,
  type CreditSignupDraftState, type CreditSignupPolicy,
} from "./credits";
import { ResizableSidebar } from "./ResizableSidebar";
import { isDevelopmentBuild } from "./transport";
import {
  control as controls,
  fonts,
  isDesktop,
  space as spaces,
  themed,
  withAlpha,
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
  Field,
  GroupRow,
  Header,
  Hero,
  Icon,
  IconButton,
  Tap,
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
type StagedAttachment = { id: string; scope: string; upload: AttachmentUpload; previewUri?: string };

// How much decrypted attachment data the session keeps at hand.

type Route = { screen: Screen; direction: Direction };
// A destructive action, held until it is confirmed.
type Confirmation = { title: string; body: string; action: string; run: () => void; cancel?: () => void; primary?: boolean };
// Why a device erased itself, said on the screen it starts over on.
const removalNotices: Record<Removal, MessageKey> = {
  "account-deleted": msg("Your account was deleted on another device, so its messages and keys were erased from this one too."),
  "device-removed": msg("This device was removed from your account on another device, so its messages and keys were erased from it."),
  "device-left": msg("This device left your account, so its messages and keys were erased from it."),
};

// Keyboard shortcuts continue to follow the host during a UI preview.
const userAgent = Platform.OS === "web" ? navigator.userAgent : "";
const macDesktop = isDesktop && /Mac/.test(userAgent);

// The words in these lists are English keys, translated where they show.
// `short` is what a segment has room for beside a phone row's title.
type Option<T> = { value: T; label: MessageKey; short?: MessageKey; icon?: IconName };

const disappearingOptions: Option<number>[] = [
  { label: msg("Off"), value: 0 },
  { label: msg("1 minute"), short: msg("1m"), value: 60 },
  { label: msg("1 hour"), short: msg("1h"), value: 3_600 },
  { label: msg("1 day"), short: msg("1d"), value: 86_400 },
];

const notificationPreviewOptions: Option<NotificationPreview>[] = [
  { value: "full", label: msg("Name and message"), short: msg("All") },
  { value: "sender", label: msg("Name only"), short: msg("Name") },
  { value: "none", label: msg("No name or message"), short: msg("None") },
];

const appearanceOptions: Option<Appearance>[] = [
  { value: "system", label: msg("Match system"), icon: "contrast" },
  { value: "light", label: msg("Light"), icon: "sun" },
  { value: "dark", label: msg("Dark"), icon: "moon" },
];

const tabs = [
  { key: "home", title: msg("Chats"), icon: "chat" },
  { key: "groups", title: msg("Groups"), icon: "groups" },
  { key: "settings", title: msg("You"), icon: "person" },
] as const;


const reloadByDatabase = createKeyedSerialQueue<string>();

// Each language is listed in itself and, beneath, in the language in effect.
const languageNames: Record<Language, MessageKey> = {
  en: msg("English"),
  es: msg("Spanish"),
  pt: msg("Portuguese (Brazil)"),
  fr: msg("French"),
  de: msg("German"),
  ru: msg("Russian"),
};
const nativeName = (code: Language) => languages.find((language) => language.code === code)!.name;

// How much of a form stays in view below the line being typed on: the rest
// of the field, its hint, and the button that follows, clear of the keyboard.
const formKeyboardOffset = 2 * controls["3xl"] + spaces[6];

const pushSummary = (pushStatus: PushStatus): MessageKey =>
  pushStatus === "enabled"
    ? msg("Messages and mentions enabled")
    : pushStatus === "disabled"
      ? msg("Notifications off")
      : pushStatus === "pending-bind"
        ? msg("Turning on once the notification service is reachable")
        : msg("Turning off; cleanup retries until registration is removed");

type AppProps = { services: AppServices;
  environment: { kind: 'mobile'; scope: ComponentProps<typeof ActivityOverlayHost>['scope'] } | { kind: 'desktop' };
  windowsPreview?: boolean;
  onWindowsPreviewChange?: (enabled: boolean) => Promise<void>;
  // The desktop shell's own settings section; phones update through their store.
  updates?: ReactNode;
  // Starts the app over with nothing in memory: erasing the account empties
  // storage, not state. The notice says why, on the screen it starts over on.
  onAccountErased: (notice?: string) => void;
  notice?: string;
};

export default function App(props: AppProps) {
  const styles = useStyles();
  return <SafeAreaProvider style={styles.screen}>
    {props.environment.kind === 'mobile'
      ? <ActivityOverlayHost scope={props.environment.scope}><AppContent {...props} /></ActivityOverlayHost>
      : <AppContent {...props} />}
  </SafeAreaProvider>;
}

function AppContent({ services, windowsPreview = false, onWindowsPreviewChange, onAccountErased, notice, updates }: AppProps) {
  const activityOverlay = useActivityOverlay();
  const { listenForGenericWakeups, listenForNotificationOpens } = services;
  const { authorizeAttachmentRecipients, group_send_export, complete_device_link_export, create_account_export, create_link_request_export, device_link_sas_export, list_conversations_export, load_history_export, load_profile_export, update_conversation_export, transparency_fork_export, anchor_check_export, fork_filing_export, attachmentPreviewUri, discardPreviews, listenForIncomingFiles, pickAttachmentSelections, releasePreviewUri, saveAttachmentFile, pickAvatar, loadPresentation, savePresentation, saveNickname, setActiveNotificationScope, synchronizeWithNotifications, onPostageRequired, addGroupMember, forgetGroup, acceptGroupInvitation, declineGroupInvitation, inviteToGroup, listGroupInvitations, authorizeDeviceLink, drainOutbox, createGroup, connectMailboxStream, deleteAccount, downloadAttachment, discardAccount, getGroupKeyPackage, holdsAccountKey, inspectGroup, listGroups, loadAccountDevices, loadGroupHistory, groupMessageTimer, onUndeliverable, registerDirectory, resolveDeviceSet, removeGroupMember, revokeDevice, sendFanout, sendGroupMessage, disablePushBinding, enablePushBinding, getPushStatus, listenForPushRegistrationChanges, recoverPushBinding, forgetPreferences, loadDeclinedRequests, loadNotificationPreview, loadReadReceipts, loadReadState, loadReceiptMarks, saveDeclinedRequests, saveNotificationPreview, saveReadReceipts, saveReadState, previewAttachmentSelections, savedAttachmentUpload, readAttachmentDownloadPlan, downloadPaidAttachment, createAttachmentRangeSink, createCreditSignupDraft, loadCreditSignupPolicy, readCreditSignupDraftState, selectFreeCreditSignup, completeFreeCreditSignup } = services;

  const previewWindows = isDesktop && isDevelopmentBuild() && windowsPreview;
  const lightsInset = isDesktop && !previewWindows ? trafficLightInset(userAgent) : 0;
  const [changingWindowsUI, setChangingWindowsUI] = useState(false);
  const { width } = useWindowDimensions();
  const { colors, type, scheme, size, control } = useTheme();
  const { t, locale, choice: languageChoice, systemLanguage, setChoice: setLanguageChoice } = useI18n();
  const [choosingLanguage, setChoosingLanguage] = useState(false);
  const languageLabel = nativeName(languageChoice === "system" ? systemLanguage : languageChoice);
  const chooseLanguage = (next: LanguageChoice) => {
    setLanguageChoice(next);
    setChoosingLanguage(false);
  };
  // An option list in the language in effect.
  const translated = <T,>(options: Option<T>[]) =>
    options.map((option) => ({ ...option, label: t(option.label), ...(option.short ? { short: t(option.short) } : {}) }));
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
  const [profileLoadProblem, setProfileLoadProblem] = useState(false);
  const [profileLoadAttempt, setProfileLoadAttempt] = useState(0);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [qrCollector] = useState(createQrCollector);
  const [profile, setProfile] = useState<Uint8Array | null>(null);
  const [signupDraft, setSignupDraft] = useState<CreditSignupDraftState>(0);
  const draftPending = signupDraft === 1 || signupDraft === 2;
  const [signupPolicy, setSignupPolicy] = useState<CreditSignupPolicy>();
  const [priorityUnavailable, setPriorityUnavailable] = useState(false);
  const [route, setRoute] = useState<Route>({ screen: "home", direction: "lateral" });
  const screen = route.screen;
  // The desktop sidebar keeps showing whichever list the open screen came
  // from, and stays put while the pane shows account screens.
  const [sidebarList, setSidebarList] = useState<SidebarList>("chats");
  const setScreen = (next: Screen) => {
    if (screen !== next && services.backups.kind === 'available') {
      const files = services.backups.files;
      try {
        if (screen === 'backups') void files.discardBackupSource().catch(() => {});
        if (screen === 'backup-export') void files.discardBackupDestination().catch(() => {});
      } catch { /* Scope revocation retains only native continuation metadata. */ }
    }
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
  // A development build can show onboarding again over a signed-in account,
  // to look at it; nothing it collects is used (see replayOnboarding).
  const [replayingOnboarding, setReplayingOnboarding] = useState(false);
  const split = usesSplitLayout(Platform.OS, width) && profile !== null && !replayingOnboarding && !draftPending;
  // Until there is an account the pane belongs to onboarding, except while
  // it has pushed the scanner or the device-linking screen over it.
  const onboardingActive = (!profile || replayingOnboarding || draftPending) && screen !== "scanner" && screen !== "link-device" && screen !== "credits";
  const [storedConversations, setConversations] = useState<Conversation[]>([]);
  const [forkEvidence, setForkEvidence] = useState("");
  const [showNetworkCounter, setShowNetworkCounter] = useState(false);
  const [anchorObservation, setAnchorObservation] = useState<AnchorObservation | null>(null);
  const [filingObservation, setFilingObservation] = useState<FilingObservation | null>(null);
  const [filingError, setFilingError] = useState(false);
  const [showAnchorDetails, setShowAnchorDetails] = useState(false);
  const [showForkDetails, setShowForkDetails] = useState(false);
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
  const [groupTimer, setGroupTimer] = useState<{ groupId: string; seconds: number; epoch: object } | null>(null);
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
  const nameEditorTitle = editingNickname ? t("Private nickname") : t("Display name");
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
  const firstMessageInput = useRef<TextInputInstance>(null);
  const displayNameInput = useRef<TextInputInstance>(null);
  const [composer, setComposer] = useState("");
  // The message being answered stays with the thread whose composer took it,
  // so a reply can never follow you into another thread. A quote that is
  // pressed scrolls the thread to its original, which flashes once.
  const [replying, setReplying] = useState<{ scope: string; target: string } | null>(null);
  const thread = useRef<Pick<FlatListInstance, "scrollToIndex" | "scrollToOffset"> | null>(null);
  const [flashKey, setFlashKey] = useState<string | null>(null);
  // The file staged in a composer, and whether one is being dragged over the
  // window. Downloads are remembered by object so a picture is fetched once
  // and a file's state survives scrolling its bubble away.
  const [staged, setStaged] = useState<StagedAttachment[]>([]);
  const stagedRef = useRef(staged);
  const stagedSerial = useRef(0);
  const choosingAttachments = useRef(false);
  const pendingAttachments = useRef<AttachmentUpload[]>([]);
  const [savedUploadsScope, setSavedUploadsScope] = useState<string | null>(null);
  const [postageTriggers, setPostageTriggers] = useState<Uint8Array[]>([]);
  const [showPostage, setShowPostage] = useState(false);
  const [showPostagePolicy, setShowPostagePolicy] = useState(false);
  const [showBounty, setShowBounty] = useState(false);
  useEffect(() => onPostageRequired(({ triggerId }) => setPostageTriggers(current =>
    current.some(id => hex(id) === hex(triggerId)) ? current : [...current.slice(-127), triggerId])), []);
  useEffect(() => { if (!profile) setPostageTriggers([]); }, [profile]);
  function postageSettled(ids: Uint8Array[]) {
    const settled = new Set(ids.map(hex));
    setPostageTriggers(current => current.filter(id => !settled.has(hex(id))));
  }
  useEffect(() => () => {
    for (const entry of stagedRef.current) entry.upload.dispose();
    for (const upload of pendingAttachments.current) upload.dispose();
  }, []);
  const [dropping, setDropping] = useState(false);
  const attachmentSession = useRef<AttachmentPreviewSession | null>(null);
  const [, refreshAttachments] = useState(0);
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
  const [status, setStatus] = useState(() => t("Opening encrypted storage…"));
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
  const visibleAccountIdentity = useRef<string | null>(null);
  visibleAccountIdentity.current = profile ? accountProfileIdentity(profile) : null;
  const historyCacheEpoch = useRef(new HistoryCacheEpoch());
  const cacheEpoch = historyCacheEpoch.current.capture(profile, databasePath, preview);
  const erasureNotifications = useRef<{ identity: string; ids: string[] } | null>(null);
  const filingDescription = describeFilingObservation(filingObservation);

  useEffect(() => {
    setFilingObservation(null);
    setFilingError(false);
    if (!forkEvidence || !accountId || preview || !foreground) return;
    let cancelled = false;
    let running = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = "";
    let pollUntil = 0;
    const check = async () => {
      if (running) return;
      running = true;
      let delay = 60_000;
      try {
        const observation = parseFilingObservation(await fork_filing_export(utf8(databasePath)));
        if (!cancelled) { setFilingObservation(observation); setFilingError(false); }
        if (observation.nextAttempt !== attempt) {
          attempt = observation.nextAttempt;
          pollUntil = Date.now() + 45_000;
        }
        // A killed actor leaves a reservation until its next retry. Never
        // turn that durable marker into an unbounded fast polling loop.
        if (observation.working && Date.now() < pollUntil) delay = 2_000;
      } catch {
        if (!cancelled) setFilingError(true);
      } finally {
        running = false;
        if (!cancelled) timer = setTimeout(() => { void check(); }, delay);
      }
    };
    // Mesh persists the retry budget before networking and shares it with all
    // background wakes. Filing must not hold up local navigation or message sync.
    void check();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [forkEvidence, accountId, preview, foreground, databasePath]);

  useEffect(() => {
    setActiveNotificationScope(foreground && !preview && !membersOpen
      ? screen === "chat" && selected ? `chat/${hex(selected.conversationId)}`
        : screen === "group" && selectedGroupId ? threadScope(hex(selectedGroupId)) : null
      : null, readReceipts);
    return () => setActiveNotificationScope(null);
  }, [foreground, preview, membersOpen, screen, selected, selectedGroupId, presentations, readReceipts]);

  useEffect(() => listenForNotificationOpens(setNotificationTarget, () => { setNotificationTarget(null); go("home"); }), []);
  useEffect(() => {
    if (!notificationTarget || preview) return;
    const chat = conversations.find((item) => notificationTarget === `chat/${hex(item.conversationId)}`);
    const group = groups.find((item) => notificationTarget === threadScope(hex(item.groupId)));
    if (chat) openConversation(chat);
    else if (group) openGroup(group);
    else return;
    setNotificationTarget(null);
  }, [notificationTarget, conversations, groups, preview]);

  useEffect(() => {
    if (!accountId || !profile) return;
    const expected = profile.slice();
    let current = true;
    // Read markers and privacy choices share the account-bound sealed database.
    // Unread counts wait until those choices have loaded.
    void (async () => {
      try {
        const [read, marks, receipts, notifications] = await Promise.all([loadReadState(expected), loadReceiptMarks(expected), loadReadReceipts(expected), loadNotificationPreview(expected)]);
        if (!current) return;
        setReadState(read);
        setReceiptMarks(marks);
        setReadReceipts(receipts);
        setNotificationPreview(notifications);
      } catch {
        if (!current) return;
        setReadState({});
        setReadReceipts(false);
        setError(t("Couldn’t load read status on this device."));
      }
      if (current) setReadAccount(accountId);
    })();
    return () => { current = false; };
  }, [accountId, profile]);

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
    ? t("A message couldn’t reach one of the recipient’s devices because it is no longer registered.")
    : t("A message waited more than 30 days to send and has expired."))), []);

  // Only a loaded, visible conversation counts as opened. A selected chat in
  // settings, its details screen, or an unfocused window stays unread.
  useEffect(() => {
    if (!foreground || !accountId || !profile || readAccount !== accountId || membersOpen) return;
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
      const expected = profile.slice();
      saveReadState(expected, next)
        .catch(() => { if (visibleAccountIdentity.current === accountProfileIdentity(expected)) setError(t("Read status couldn’t be saved. Unread badges may return after restarting.")); });
      // One cumulative receipt for what was just read. Best effort: the next covers a lost one.
      const through = screen === "chat" && selected && readReceipts && !selected.blocked && !selected.requestPending
        ? receiptDue(history, 2) : undefined;
      if (through) {
        void sendFanout(databasePath, profile!, selected!.username, encodeReceipt(2, through), selected!.peerAccountId)
          .catch(() => undefined);
      }
    }
  }, [foreground, accountId, profile, readAccount, membersOpen, screen, selected, selectedGroupId,
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
    communityAsks.find((ask) => ask.state === "approved" && ask.part === hex(id))?.name ?? t("Group {id}", { id: hex(id).slice(0, 6) });
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
  const groupSubtitle = (group: GroupSummary) => communityOfGroup(hex(group.groupId)) ? t("Community")
    : t.plural("{count} member", "{count} members", group.memberCount);
  // A community's latest is its latest announcement, never a request hidden in a part.
  const groupLast = (group: GroupSummary) => threadHistory(group).at(-1);
  // A group's row shows its latest words as a conversation's does: yours
  // marked as yours, anyone else's by name where the name is known. A
  // community's row keeps saying what it is.
  function groupPreviewText(group: GroupSummary): string {
    const last = groupLast(group);
    if (!last || communityOfGroup(hex(group.groupId))) return groupSubtitle(group);
    const text = attachmentPreviewText(last);
    if (last.direction === "sent") return t("You: {text}", { text });
    const id = hex(last.senderAccountId);
    const contact = conversations.find((item) => hex(item.peerAccountId) === id);
    const name = identityName(contact?.username ?? null, presentationOf(`user/${id}`), presentationOf(`nickname/${id}`));
    return name ? t("{name}: {text}", { name, text }) : text;
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
  // Expiry also removes never-opened sidebar previews. These are local native
  // getter reads only: refreshGroups would additionally send/network, so it is
  // deliberately not called here. Active contexts schedule local reads below.
  useEffect(() => {
    if (preview || !profile) return;
    const direct = conversations.flatMap((conversation) => {
      const key = hex(conversation.conversationId), original = previews[key];
      return original && key !== (selected ? hex(selected.conversationId) : null)
        ? [{ key, original, peer: conversation.peerAccountId, empty: [] as HistoryMessage[] }] : [];
    });
    const group = listedGroups.flatMap((value) => {
      const id = hex(value.groupId), entry = communityOfGroup(id);
      const parts = entry?.parts ?? [id], key = entry ? communityId(entry.community) : id;
      const original = groupPreviews[key];
      if (!original || parts.some(part => part === (selectedGroupId ? hex(selectedGroupId) : null) || selectedEntry?.parts.includes(part))) return [];
      return [{ key, original, parts, entry, empty: [] as GroupHistoryMessage[],
        held: parts.map(part => ({ part, original: communityParts[part]?.messages, empty: [] as GroupHistoryMessage[] })) }];
    });
    const delays = [...direct, ...group].flatMap(job => {
      const delay = historyRefreshDelay(job.original, Date.now());
      return delay === undefined ? [] : [delay];
    });
    if (!delays.length) return;
    const timer = setTimeout(() => {
      if (!historyCacheEpoch.current.current(cacheEpoch)) return;
      const dueDirect = direct.filter(job => historyRefreshDelay(job.original, Date.now()) === 0);
      const dueGroups = group.filter(job => historyRefreshDelay(job.original, Date.now()) === 0);
      // Hide the expired cache before awaiting I/O. A failure leaves an empty
      // optional preview; a normal sync can subsequently restore public display.
      setPreviews(previous => dueDirect.reduce((next, job) => replaceHistoryCache(next, job.key, job.original, job.empty), previous));
      setGroupPreviews(previous => dueGroups.reduce((next, job) => replaceHistoryCache(next, job.key, job.original, job.empty), previous));
      setCommunityParts(previous => {
        const next = { ...previous };
        for (const job of dueGroups) for (const held of job.held) {
          const current = next[held.part];
          if (current && current.messages === held.original) next[held.part] = { ...current, messages: held.empty };
        }
        return next;
      });
      void (async () => {
        for (const job of dueDirect) {
          try {
            const messages = await historyCacheEpoch.current.read(cacheEpoch, async () =>
              parseHistory(await load_history_export(peerRequest(databasePath, job.peer))));
            if (!messages) return;
            const visible = unexpiredHistory(messages, Date.now());
            setPreviews(previous => replaceHistoryCache(previous, job.key, job.empty, visible));
          } catch { /* Expired optional cache stays hidden if the local getter fails. */ }
        }
        for (const job of dueGroups) {
          try {
            const parts = await historyCacheEpoch.current.read(cacheEpoch, async () => {
              const loaded: { id: string; messages: GroupHistoryMessage[] }[] = [];
              for (const id of job.parts) {
                if (!historyCacheEpoch.current.current(cacheEpoch)) throw Error("account_state_changed");
                loaded.push({ id, messages: await loadGroupHistory(databasePath, fromHex(id)) });
              }
              return loaded;
            });
            if (!parts) return;
            const now = Date.now();
            const visibleParts = parts.map(part => ({ ...part, messages: unexpiredHistory(part.messages, now) }));
            const messages = job.entry ? mergeParts(visibleParts, authorities(job.entry.community)) : visibleParts[0]!.messages;
            setGroupPreviews(previous => replaceHistoryCache(previous, job.key, job.empty, messages));
            setCommunityParts(previous => {
              const next = { ...previous };
              for (const held of job.held) {
                const current = next[held.part], loaded = visibleParts.find(part => part.id === held.part);
                if (current && loaded && current.messages === held.empty) next[held.part] = { ...current, messages: loaded.messages };
              }
              return next;
            });
          } catch { /* No unavailable/old-account cache is presented as a fresh read. */ }
        }
      })();
    }, Math.min(...delays));
    return () => clearTimeout(timer);
  }, [preview, profile, databasePath, cacheEpoch, conversations, listedGroups, previews, groupPreviews, communityParts, selected, selectedGroupId, selectedEntry]);

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
          rememberPreview(conversation, unexpiredHistory(parseHistory(encoded), Date.now()));
        } catch {
          // A conversation without readable history simply shows no preview.
        }
      }),
    );
  }

  async function refreshConversations(): Promise<Conversation[]> {
    const evidence = await transparency_fork_export(utf8(databasePath));
    setForkEvidence(hex(evidence));
    const encoded = await list_conversations_export(utf8(databasePath));
    const next = parseConversations(encoded);
    setConversations(next);
    await Promise.all([refreshPreviews(next), refreshPresentations([...next.map((item) => `user/${hex(item.peerAccountId)}`), ...(profile ? [`user/${hex(parseProfileSummary(profile).accountId)}`] : [])])]);
    return next;
  }

  // Display deadlines must not wait for a local getter or unrelated metadata
  // read. This timer only removes due cached rows; the existing native reads
  // below remain responsible for persistent cleanup and fresh history.
  useEffect(() => {
    if (preview || !profile) return;
    const direct = selected && historyFor === hex(selected.conversationId)
      ? { key: hex(selected.conversationId), original: history } : undefined;
    const group = selectedGroup && !selectedEntry && groupHistoryFor === hex(selectedGroup.groupId)
      ? { key: hex(selectedGroup.groupId), original: groupHistory } : undefined;
    const directPreview = selected && previews[hex(selected.conversationId)]
      ? { key: hex(selected.conversationId), original: previews[hex(selected.conversationId)]! } : undefined;
    const groupPreview = selectedGroup && !selectedEntry && groupPreviews[hex(selectedGroup.groupId)]
      ? { key: hex(selectedGroup.groupId), original: groupPreviews[hex(selectedGroup.groupId)]! } : undefined;
    const parts = selectedEntry ? selectedEntry.parts.flatMap(part => {
      const original = communityParts[part]?.messages;
      return original ? [{ part, original }] : [];
    }) : [];
    const communityPreview = selectedEntry && groupPreviews[communityId(selectedEntry.community)]
      ? { key: communityId(selectedEntry.community), original: groupPreviews[communityId(selectedEntry.community)]! } : undefined;
    const messages = [...(direct?.original ?? []), ...(group?.original ?? []),
      ...(directPreview?.original ?? []), ...(groupPreview?.original ?? []),
      ...parts.flatMap(part => part.original), ...(communityPreview?.original ?? [])];
    const delay = historyRefreshDelay(messages, Date.now());
    if (delay === undefined) return;
    const timer = setTimeout(() => {
      if (!historyCacheEpoch.current.current(cacheEpoch)) return;
      const now = Date.now();
      if (direct) {
        const visible = unexpiredHistory(direct.original, now);
        setHistory(previous => previous === direct.original ? visible : previous);
      }
      if (directPreview) {
        const visible = unexpiredHistory(directPreview.original, now);
        setPreviews(previous => replaceHistoryCache(previous, directPreview.key, directPreview.original, visible));
      }
      if (group) {
        const visible = unexpiredHistory(group.original, now);
        setGroupHistory(previous => previous === group.original ? visible : previous);
      }
      if (groupPreview) {
        const visible = unexpiredHistory(groupPreview.original, now);
        setGroupPreviews(previous => replaceHistoryCache(previous, groupPreview.key, groupPreview.original, visible));
      }
      if (parts.length) setCommunityParts(previous => {
        let next = previous;
        for (const part of parts) {
          const current = previous[part.part];
          if (!current || current.messages !== part.original) continue;
          const visible = unexpiredHistory(part.original, now);
          if (visible !== part.original) next = { ...next, [part.part]: { ...current, messages: visible } };
        }
        return next;
      });
      if (communityPreview) {
        const visible = unexpiredHistory(communityPreview.original, now);
        setGroupPreviews(previous => replaceHistoryCache(previous, communityPreview.key, communityPreview.original, visible));
      }
    }, delay);
    return () => clearTimeout(timer);
  }, [preview, profile, databasePath, cacheEpoch, selected, historyFor, history, previews,
    selectedGroup, selectedEntry, groupHistoryFor, groupHistory, communityParts, groupPreviews]);

  useEffect(() => {
    if (preview || !selected) return;
    const conversation = selected;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const encoded = await load_history_export(peerRequest(databasePath, conversation.peerAccountId));
        if (cancelled || !historyCacheEpoch.current.current(cacheEpoch)) return;
        const messages = unexpiredHistory(parseHistory(encoded), Date.now());
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
  }, [selected, preview, profile, databasePath, cacheEpoch]);

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
    const now = Date.now();
    const visiblePreviews = Object.fromEntries(Object.entries(previews).map(([id, messages]) => [id, unexpiredHistory(messages, now)]));
    setGroupPreviews((previous) => ({ ...previous, ...visiblePreviews }));
    // The list names whoever spoke last in each group.
    void refreshPresentations(Object.values(visiblePreviews).flatMap((messages) => {
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
    const expected = profile?.slice();
    return reloadByDatabase(databasePath, async () => {
      if (expected) {
        const identity = accountProfileIdentity(expected);
        try {
          const marks = await loadReceiptMarks(expected);
          if (visibleAccountIdentity.current === identity) setReceiptMarks(marks);
        } catch { /* Keep the last known marks. */ }
        try {
          const declined = await loadDeclinedRequests(expected);
          if (visibleAccountIdentity.current === identity) setDeclinedRequests(declined);
        } catch { /* Keep the last known answers. */ }
      }
      const results = await Promise.allSettled([refreshConversations(), refreshGroups()]);
      const failure = results.find((result) => result.status === "rejected");
      if (failure?.status === "rejected") throw failure.reason;
      // Refresh local conversations first. A daily RPC observation must not
      // hold the app's startup or navigation while providers are unavailable.
      // Mesh separately awaits a due check before accepting changed keys.
      void anchor_check_export(utf8(databasePath)).then(async (wire) => {
        setAnchorObservation(parseAnchorObservation(wire));
        // The check may have just retained a fork after the local refresh.
        // Make its evidence available immediately without another network call.
        setForkEvidence(hex(await transparency_fork_export(utf8(databasePath))));
      }).catch((caught) => setError(friendlyError(caught)));
    });
  }

  useEffect(() => {
    if (preview || !selectedGroup) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const group = selectedGroup;
    async function load() {
      try {
        const [details, loadedMessages, seconds] = await Promise.all([
          inspectGroup(databasePath, group.groupId), loadGroupHistory(databasePath, group.groupId),
          groupMessageTimer(databasePath, group.groupId),
        ]);
        if (cancelled || !historyCacheEpoch.current.current(cacheEpoch)) return;
        const messages = unexpiredHistory(loadedMessages, Date.now());
        setGroupDetails(details);
        setGroupHistory(messages);
        setGroupHistoryFor(hex(group.groupId));
        setGroupTimer({ groupId: hex(group.groupId), seconds, epoch: cacheEpoch });
        if (!presentationOf(`group/${hex(group.groupId)}`)?.community) {
          setGroupPreviews((previous) => ({ ...previous, [hex(group.groupId)]: messages }));
        }
        const delay = historyRefreshDelay(messages, Date.now());
        if (delay !== undefined) timer = setTimeout(() => void load(), delay);
        await refreshPresentations([...details.members.map((member) => `user/${hex(member.accountId)}`), ...messages.map((message) => `user/${hex(message.senderAccountId)}`)]);
      } catch (caught) {
        if (!cancelled) setError(friendlyError(caught));
      }
    }
    void load();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [selectedGroup, preview, databasePath, profile, cacheEpoch]);

  // Community parts share the same encrypted group format. This timer reads
  // local history only; it never starts a network sync or changes send policy.
  useEffect(() => {
    if (preview || !selectedEntry) return;
    const messages = selectedEntry.parts.flatMap((part) => communityParts[part]?.messages ?? []);
    const delay = historyRefreshDelay(messages, Date.now());
    if (delay === undefined) return;
    let cancelled = false;
    const parts = selectedEntry.parts;
    const timer = setTimeout(() => {
      void Promise.all(parts.map(async (part) => ({ part, messages: await loadGroupHistory(databasePath, fromHex(part)) }))).then((updates) => {
        if (cancelled || !historyCacheEpoch.current.current(cacheEpoch)) return;
        const now = Date.now();
        setCommunityParts((previous) => {
          const next = { ...previous };
          for (const update of updates) {
            const existing = next[update.part];
            if (existing) next[update.part] = { ...existing, messages: unexpiredHistory(update.messages, now) };
          }
          return next;
        });
      }).catch((caught) => { if (!cancelled) setError(friendlyError(caught)); });
    }, delay);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [selectedEntry, communityParts, preview, databasePath, profile, cacheEpoch]);

  async function refreshDevices(
    currentProfile: Uint8Array,
  ): Promise<DeviceSetSummary> {
    await rememberErasureNotifications(currentProfile);
    const loaded = await loadAccountDevices(databasePath, currentProfile);
    if (visibleAccountIdentity.current !== accountProfileIdentity(currentProfile)) throw new Error("account_state_changed");
    setDeviceSet(loaded.wire);
    setDevices(loaded.summary);
    return loaded.summary;
  }

  async function updatePush(work: () => Promise<PushStatus>): Promise<void> {
    if (preview || !profile) return;
    const identity = accountProfileIdentity(profile);
    setPushBusy(true);
    setPushError("");
    try {
      const next = await work();
      if (visibleAccountIdentity.current === identity) setPushStatus(next);
    } catch (caught) {
      if (visibleAccountIdentity.current !== identity) return;
      setPushError(friendlyError(caught));
      try {
        const next = await getPushStatus(databasePath, profile.slice());
        if (visibleAccountIdentity.current === identity) setPushStatus(next);
      } catch {
        // Keep the last Mesh-derived status when encrypted storage is unavailable.
      }
    } finally {
      if (visibleAccountIdentity.current === identity) setPushBusy(false);
    }
  }

  function recoverPush(): void {
    if (!profile) return;
    const expected = profile.slice();
    void updatePush(() => recoverPushBinding(databasePath, expected));
  }

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      let foundProfile = false;
      let guardRead = false;
      try {
        const loaded = await load_profile_export(utf8(databasePath));
        foundProfile = true;
        // A local profile may be a paid draft. Read its native guard before
        // making it visible to any registration or mailbox effect.
        const draft = await readCreditSignupDraftState(databasePath);
        guardRead = true;
        if (cancelled) return;
        setSignupDraft(draft);
        setProfile(loaded);
        if (draft === 1 || draft === 2) {
          setOnboardingStep("profile");
          setUsername(parseProfileSummary(loaded).username);
          return;
        }
        await refreshPresentations([`user/${hex(parseProfileSummary(loaded).accountId)}`]);
        await refreshLocalData();
        setStatus(t("Welcome back"));
      } catch (caught) {
        if (!cancelled) {
          if (guardRead) setError(friendlyError(caught));
          else if (foundProfile || !/local_state_not_found|profile_not_found/.test(String(caught))) setProfileLoadProblem(true);
          else setStatus(t("Choose a username to get started"));
        }
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
  }, [profileLoadAttempt]);

  useEffect(() => {
    if (!profile || leaving || draftPending) return undefined;
    const sync = createMailboxSync(
      async () => {
        await rememberErasureNotifications(profile);
        return connectMailboxStream(databasePath);
      },
      async () => {
        try {
          await rememberErasureNotifications(profile);
          await synchronizeWithNotifications(databasePath);
          const currentDevices = await refreshDevices(profile);
          if (currentDevices.changed) {
            setError(t("Your account changed while this device was away. Review your linked devices."));
            go("devices");
          }
        } finally {
          // Native writes may have committed even if delivery or acknowledgement failed.
          await refreshLocalData();
        }
      },
      (caught) => {
        if (caught instanceof VerifiedDirectoryRemoval) {
          if (visibleAccountIdentity.current !== accountProfileIdentity(profile)) return;
          setLeaving(true);
          void finishErasing(profile, t(removalNotices[caught.removal]));
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
  }, [profile, leaving, draftPending]);

  useEffect(() => {
    if (!profile || leaving || draftPending) return undefined;
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
  }, [profile, leaving, draftPending]);

  async function perform(
    label: string,
    work: () => Promise<void>,
  ): Promise<void> {
    if (preview) {
      setError(t("Sample preview is read-only. Turn it off in You → Development to make changes."));
      return;
    }
    setBusy(true);
    setError("");
    setStatus(label);
    try {
      await work();
    } catch (caught) {
      qrCollector.reset();
      if (caught instanceof VerifiedDirectoryRemoval && profile) {
        await finishErasing(profile, t(removalNotices[caught.removal]));
      } else setError(friendlyError(caught));
    } finally {
      if (profile && !draftPending) mailboxSync.current?.invalidate();
      try {
        if (profile && !draftPending) await refreshLocalData();
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

  // Onboarding again, from its first screen and with its fields empty, over
  // the account this device already has. Its last steps end the replay
  // instead of creating an account or linking a device (endReplay).
  function replayOnboarding(): void {
    if (!isDevelopmentBuild() || busy) return;
    setUsername("");
    setDisplayName("");
    setAccountAvatar(undefined);
    setTakenUsername("");
    setOnboardingStep("welcome");
    setReplayingOnboarding(true);
    setRoute((current) => ({ ...current, direction: "forward" }));
  }

  // Leaves a replay where finishing it would have: in the app, on Chats, or
  // back where it was started when it is backed out of.
  function endReplay(finished: boolean): void {
    setReplayingOnboarding(false);
    setOnboardingStep("welcome");
    setUsername("");
    setDisplayName("");
    setAccountAvatar(undefined);
    if (finished) enterApp();
    else setRoute({ screen: "settings", direction: "backward" });
  }

  async function finishPaidSignup(): Promise<void> {
    if (await readCreditSignupDraftState(databasePath) !== 3) throw new Error("paid_signup_draft_pending");
    setSignupDraft(3);
    enterApp();
  }

  function checkSignupOptions(): void {
    void perform(t("Checking signup options…"), async () => {
      try {
        setSignupPolicy(await loadCreditSignupPolicy(databasePath));
        setPriorityUnavailable(false);
      } catch {
        setPriorityUnavailable(true);
        setSignupPolicy(undefined);
      }
    });
  }

  function createPaidSignupDraft(): void {
    const normalized = username.trim().toLowerCase();
    if (usernameProblem(normalized) || !signupPolicy?.enabled || signupPolicy.currentDifficulty <= signupPolicy.baseDifficulty) return;
    const presentation = { name: displayName.trim() || normalized, avatar: accountAvatar };
    try { encodePresentation(presentation); }
    catch (caught) { setError(friendlyError(caught)); return; }
    void perform(t("Saving your signup profile…"), async () => {
      const created = await createCreditSignupDraft(databasePath, normalized);
      setSignupDraft(await readCreditSignupDraftState(databasePath));
      setProfile(created);
      setScreen("home");
      const key = `user/${hex(parseProfileSummary(created).accountId)}`;
      await savePresentation(databasePath, key, presentation);
    });
  }

  async function finishFreeDraft(policy: Uint8Array): Promise<void> {
    const local = await selectFreeCreditSignup(databasePath);
    setSignupDraft(2);
    setProfile(local);
    // No erase on a name conflict: the same local identity may already own
    // purchased credits. Native guards retain pending paid reservations.
    try {
      await registerDirectory(databasePath, policy);
      // Resolve our entry through the normal pinned witness checks, then let
      // native code compare the authenticated cache with this exact draft.
      await resolveDeviceSet(databasePath, parseProfileSummary(local).username);
      const completed = await completeFreeCreditSignup(databasePath);
      if (await readCreditSignupDraftState(databasePath) !== 3) throw new Error("signup_completion_pending");
      setProfile(completed);
    } catch (caught) {
      if (/registration_refused/.test(String(caught))) throw new Error("free_signup_name_taken");
      throw new Error("free_signup_pending");
    }
    setSignupDraft(3);
    enterApp();
  }

  function createAccount(): void {
    const normalized = username.trim().toLowerCase();
    if (usernameProblem(normalized)) {
      setError(t("Use 3–32 lowercase letters, numbers, or underscores."));
      return;
    }
    if (replayingOnboarding) {
      endReplay(true);
      return;
    }
    const presentation = { name: displayName.trim() || normalized, avatar: accountAvatar, revision: Date.now() };
    let request: Uint8Array;
    try { request = vectors(utf8(databasePath), utf8(normalized), encodePresentation(presentation)); }
    catch (caught) { setError(friendlyError(caught)); return; }
    void perform(t("Creating your account…"), async () => {
      const created = await create_account_export(request);
      // A name the directory refuses would leave an account no server takes,
      // and no way back to choosing another, so it is undone before anyone sees
      // it. An outage keeps the account: connecting registers it later.
      let unregistered: unknown = null;
      try {
        await registerDirectory(databasePath);
      } catch (caught) {
        if (isDirectoryRegistrationRefused(caught)) {
          await discardAccount(databasePath, created);
          // Said at the field, which stays as typed for another try.
          setTakenUsername(normalized);
          return;
        }
        unregistered = caught;
      }
      setProfile(created);
      enterApp();
      const key = `user/${hex(parseProfileSummary(created).accountId)}`;
      setPresentations((previous) => ({ ...previous, [key]: presentation }));
      if (unregistered) throw unregistered;
      // The mailbox sync loads the device set once the witnesses countersign
      // it, seconds from now; the account is usable before then.
      setUsername("");
      setDisplayName("");
      setStatus(t("Account created"));
    });
  }

  function startWithProfile(contact: Uint8Array, body: string): void {
    if (!body.trim() && !stagedFor("new-chat").length) {
      setError(t("Write a first message."));
      return;
    }
    void perform(t("Sending…"), async () => {
      const peer = parseProfileSummary(contact);
      let changed = false;
      const queued = await sendWithAttachment("new-chat", { username: peer.username, expectedPeer: peer.accountId }, async (attachment) => {
        changed = await sendFanout(databasePath, profile!, peer.username, body.trim(), peer.accountId, attachment);
      });
      setFirstMessage("");
      setScannedProfile(null);
      noteSent(peer.username, changed, queued);
      setScreen("home");
    });
  }

  function startByUsername(): void {
    const target = contactUsername.trim().toLowerCase();
    void perform(t("Sending…"), async () => {
      let changed = false;
      const queued = await sendWithAttachment("new-chat", { username: target }, async (attachment) => {
        changed = await sendFanout(databasePath, profile!, target, firstMessage.trim(), undefined, attachment);
      });
      Keyboard.dismiss();
      setContactUsername("");
      setFirstMessage("");
      setScreen("home");
      noteSent(target, changed, queued);
    });
  }

  function sendMessage(): void {
    if (!selected) return;
    const scope = `chat/${selected.conversationId.join(".")}`;
    if (!composer.trim() && !stagedFor(scope).length) return;
    void perform(t("Sending…"), async () => {
      let changed = false;
      const queued = await sendWithAttachment(scope, { username: selected.username, expectedPeer: selected.peerAccountId }, async (attachment) => {
        changed = await sendFanout(databasePath, profile!, selected.username, outgoingBody(composer.trim()), selected.peerAccountId, attachment);
      });
      setComposer("");
      setReplying(null);
      noteSent(selected.username, changed, queued);
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
    void perform(t("Sending reaction…"), async () => {
      const body = encodeReaction(hex(message.messageId!), emoji);
      // A community post is one message per part; the reaction goes to each.
      const copies = "copies" in message ? (message as { copies: Copy[] }).copies : undefined;
      if (copies) {
        for (const copy of copies) {
          if (copy.messageId) await sendGroupMessage(databasePath, fromHex(copy.part), encodeReaction(hex(copy.messageId), emoji));
        }
      } else if (group) await sendGroupMessage(databasePath, selectedGroupId!, body);
      else {
        const changed = await sendFanout(databasePath, profile!, selected!.username, body, selected!.peerAccountId);
        noteSent(selected!.username, changed);
      }
      setStatus(t("Reaction sent"));
    });
  }

  // A message is on its way; if the other side's devices changed since the
  // last one, that is worth a warning in words a person can act on.
  function noteSent(username: string, devicesChanged: boolean, queued = false): void {
    setStatus(queued ? t("Message queued. Review postage before delivery.") : t("Sent"));
    if (devicesChanged)
      setError(t("@{username}’s devices changed. Compare safety numbers again before you trust this conversation.", { username }));
  }

  // Staged files stay with the composer that accepted them.
  const openScope = composerScope(screen, selectedId, selectedGroupId ? hex(selectedGroupId) : null);
  // A thread's preview cache ends when its composer leaves the screen. Layout
  // cleanup runs before the next thread's bubbles start their passive downloads.
  useLayoutEffect(() => {
    const session = openScope ? new AttachmentPreviewSession(openScope, releasePreviewUri,
      () => refreshAttachments(value => value + 1)) : null;
    attachmentSession.current = session;
    for (const entry of stagedRef.current) {
      if (entry.scope === openScope && !entry.previewUri && entry.upload.smallBytes && isImageAttachment(entry.upload.mimeType)) {
        void Promise.resolve(attachmentPreviewUri(entry.id, entry.upload.mimeType, entry.upload.smallBytes)).then(uri => {
          if (!session?.active || !stagedRef.current.includes(entry)) { releasePreviewUri(uri); return; }
          if (entry.previewUri) releasePreviewUri(entry.previewUri);
          entry.previewUri = uri; refreshAttachments(value => value + 1);
        }, () => { /* Native revoke removes unpublished previews; no stale UI result. */ });
      }
    }
    refreshAttachments(value => value + 1);
    return () => {
      session?.close();
      // Unsent selections still belong to their composer; only their generated
      // preview is discarded. Reopening creates a fresh one from that selection.
      for (const entry of stagedRef.current) if (entry.scope === openScope && entry.previewUri) {
        releasePreviewUri(entry.previewUri); entry.previewUri = undefined;
      }
      if (attachmentSession.current === session) attachmentSession.current = null;
    };
  }, [openScope, accountId]);
  useLayoutEffect(() => {
    const session = attachmentSession.current;
    if (!session || session.scope !== openScope) return;
    const messages = screen === "chat" && selected && historyFor === hex(selected.conversationId) ? history
      : screen === "group" ? selectedEntry ? communityPosts
        : selectedGroupId && groupHistoryFor === hex(selectedGroupId) ? groupHistory : [] : [];
    session.restrictTo(messages.flatMap((message) => message.attachments?.map((attachment) => hex(attachment.objectId)) ?? []));
  }, [openScope, screen, selected, historyFor, history, selectedEntry, communityParts, selectedGroupId, groupHistoryFor, groupHistory, accountId]);
  const sessionFor = (scope: string | null) => {
    const session = attachmentSession.current;
    return session?.active && session.scope === scope ? session : null;
  };
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
    for (const previous of stagedRef.current) if (!entries.includes(previous)) previous.upload.dispose();
    stagedRef.current = entries;
    setStaged(entries);
  }

  async function stageAttachments(scope: string | null, files: AttachmentSelection[]): Promise<void> {
    const dispose = () => files.forEach(file => file.dispose());
    if (scope === null || !files.length || busy || choosingAttachments.current) { dispose(); return; }
    if (preview) {
      dispose(); setError(t("Sample preview is read-only. Turn it off in You → Development to make changes.")); return;
    }
    const limit = attachmentSelectionLimit(files.map(file => file.size), stagedFor(scope).length);
    if (limit) { dispose(); setError(limit); return; }
    const session = sessionFor(scope);
    if (!session) { dispose(); return; }
    choosingAttachments.current = true;
    try {
      const uploads = await previewAttachmentSelections(databasePath, files);
      if (!session.active) { uploads.forEach(upload => upload.dispose()); choosingAttachments.current = false; return; }
      pendingAttachments.current = uploads;
      const finish = () => { pendingAttachments.current = []; choosingAttachments.current = false; };
      const cancel = () => { uploads.forEach(upload => upload.dispose()); finish(); };
      const add = async () => {
        if (!session.active) { cancel(); return; }
        const currentLimit = attachmentSelectionLimit(uploads.map(file => file.size), stagedFor(scope).length);
        if (currentLimit) { cancel(); setError(currentLimit); return; }
        const entries: StagedAttachment[] = [];
        try {
          for (const upload of uploads) {
            const id = `staged-${stagedSerial.current++}`;
            const previewUri = upload.smallBytes && isImageAttachment(upload.mimeType) ? await attachmentPreviewUri(id, upload.mimeType, upload.smallBytes) : undefined;
            if (!session.active) { if (previewUri) releasePreviewUri(previewUri); throw Error("stale_epoch"); }
            entries.push({ id, scope, upload, previewUri });
          }
          updateStaged([...stagedRef.current, ...entries]); setError(""); finish();
        } catch (caught) {
          for (const entry of entries) if (entry.previewUri) releasePreviewUri(entry.previewUri);
          cancel(); setError(friendlyError(caught));
        }
      };
      const paid = uploads.filter(upload => upload.nonce);
      const price = paid.reduce((total, upload) => total + upload.price, 0);
      if (!price) { await add(); return; }
      const available = Math.min(...paid.map(upload => upload.available ?? 0));
      if (price > available) { cancel(); setError(t("This selection needs {count} available credits. New credits wait 10 minutes before use.", { count: price })); return; }
      confirm({ title: paid[0]?.purpose === "test" ? t("Use test credits for these files?") : t("Use credits for these files?"),
        body: t.plural("{count} credit will be used when you send. Each file is encrypted and saved on this device before upload. Removing it after sending does not refund credits.", "{count} credits will be used when you send. Each file is encrypted and saved on this device before upload. Removing it after sending does not refund credits.", price),
        action: t.plural("Add files for {count} credit", "Add files for {count} credits", price), primary: true, run: () => { void add(); }, cancel });
    } catch (caught) {
      dispose(); choosingAttachments.current = false; pendingAttachments.current = [];
      if (session.active) setError(/credits_disabled/.test(String(caught)) ? t("Large attachments aren’t enabled in this app release. Files up to 16 MB are still free.") : friendlyError(caught));
    }
  }

  function unstageAttachment(id: string): void {
    const entry = stagedRef.current.find(entry => entry.id === id);
    if (entry?.previewUri) releasePreviewUri(entry.previewUri);
    entry?.upload.dispose();
    updateStaged(stagedRef.current.filter(entry => entry.id !== id));
  }

  function pickFiles(scope: string): void {
    const session = sessionFor(scope);
    if (!session) return;
    pickAttachmentSelections().then(files => {
      if (session.active) void stageAttachments(scope, files);
      else files.forEach(file => file.dispose());
    }, caught => { if (session.active) setError(friendlyError(caught)); });
  }
  function attachFile(scope: string | null): void {
    if (scope === null || busy || choosingAttachments.current) return;
    // The ordinary picker stays one tap; saved files are available beside it.
    pickFiles(scope);
  }

  const composerAttachments = (scope: string | null): ComposerAttachment[] =>
    staged.filter(entry => entry.scope === scope).map(entry => ({
      id: entry.id, filename: entry.upload.filename,
      size: entry.upload.price ? t.plural("{size} · {count} credit", "{size} · {count} credits", entry.upload.price, { size: formatBytes(entry.upload.size) }) : formatBytes(entry.upload.size),
      previewUri: entry.previewUri,
    }));

  useEffect(() => {
    const session = sessionFor(openScope);
    const accept = (files: AttachmentSelection[]) => {
      if (session?.active) void stageAttachments(openScope, files);
      else files.forEach(file => file.dispose());
    };
    return listenForIncomingFiles({
      onDragging: setDropping,
      onFiles: files => accept(files.map(smallAttachmentSelection)),
      onSelections: accept,
      onError: message => { if (session?.active) setError(message); },
    });
  });

  async function sendWithAttachment(scope: string, recipients: AttachmentRecipients, send: (attachment?: Uint8Array) => Promise<void>): Promise<boolean> {
    const entries = stagedFor(scope);
    const session = sessionFor(scope);
    let queued = false;
    const uploaded = await sendAttachmentUploads(databasePath, entries.map(entry => entry.upload), () => authorizeAttachmentRecipients(databasePath, profile!, recipients), async reference => {
      setStatus(t("Sending…"));
      try { await send(reference); }
      catch (caught) {
        if (!(caught instanceof PostageRequired)) throw caught;
        // Mesh has durably queued this exact message before its first network
        // submission. Clearing the composer prevents a replacement message.
        queued = true;
      }
    }, (completed, total, staging) => setStatus(staging ? t("Encrypting and saving… {percent}%", { percent: Math.round(completed / total * 100) }) : t("Uploading… {percent}%", { percent: Math.round(completed / total * 100) })));
    uploaded.forEach((file, index) => {
      const entry = entries[index]!; const key = hex(file.objectId);
      if (session?.active) {
        if (entry.upload.smallBytes) session.remember(key, entry.upload.smallBytes.slice());
        session.setState(key, { status: "ready", previewUri: entry.previewUri });
      }
      entry.upload.dispose();
    });
    updateStaged(stagedRef.current.filter(entry => !entries.includes(entry)));
    return queued;
  }

  const attachmentState = (scope: string, attachment: AttachmentSummary): AttachmentState | undefined =>
    sessionFor(scope)?.state(hex(attachment.objectId)) ??
    (attachment.expiresAt < Date.now() ? { status: "error", message: t("Expired") } : undefined);

  // One request per object in this opening of this thread. Closing invalidates
  // progress, results and errors, including work which cannot be recalled natively.
  function openAttachment(scope: string, attachment: AttachmentSummary, save: boolean): void {
    const key = hex(attachment.objectId);
    const session = sessionFor(scope);
    if (!session?.begin(key)) return;
    const signal = session.requestSignal(key);
    let previewUri = session.state(key)?.previewUri;
    void (async () => {
      try {
        if (attachment.size > MAXIMUM_ATTACHMENT_SIZE) {
          if (!save) return;
          const plan = await readAttachmentDownloadPlan(databasePath, attachment.reference);
          if (!session.accepts(key, signal)) return;
          if ((plan.version !== 2 && plan.version !== 4) || plan.size !== attachment.size) throw Error("invalid_paid_attachment");
          const sink = await createAttachmentRangeSink(plan.filename, plan.mimeType, plan.size, `attachment/${key}/${attachment.expiresAt}`);
          if (!sink) return;
          // A destination explicitly selected by the person is an export, not
          // a preview cache. Its transfer may finish after leaving the thread.
          session.setState(key, { status: "downloading", completed: 0, total: plan.chunkCount }, signal);
          await downloadPaidAttachment(databasePath, plan, sink, (completed, total) => session.setState(key, { status: "downloading", completed, total }, signal));
          session.setState(key, { status: "saved" }, signal);
          return;
        }
        let bytes = session.bytes(key);
        if (!bytes) {
          session.setState(key, { status: "downloading", completed: 0, total: attachment.chunkCount, previewUri }, signal);
          bytes = await downloadAttachment(databasePath, attachment, (completed, total) =>
            session.setState(key, { status: "downloading", completed, total, previewUri }, signal), signal);
          session.remember(key, bytes, signal);
          if (!session.accepts(key, signal)) return;
          if (previewUri === undefined && isImageAttachment(attachment.mimeType)) {
            previewUri = await attachmentPreviewUri(key, attachment.mimeType, bytes);
            if (!session.accepts(key, signal)) { releasePreviewUri(previewUri); return; }
          }
          session.setState(key, { status: "ready", previewUri }, signal);
        }
        if (!save || !session.accepts(key, signal)) return;
        const held = session.retain(key);
        if (!held) return;
        try {
          if (await saveAttachmentFile(attachment.filename, attachment.mimeType, held.bytes, signal, `attachment/${key}/${attachment.expiresAt}`)) {
            session.setState(key, { status: "saved", previewUri }, signal);
          }
        } finally { held.release(); }
      } catch (caught) {
        if (!session.accepts(key, signal)) return;
        const message = friendlyError(caught);
        session.setState(key, { status: "error", message, previewUri }, signal);
        // A fetch nobody asked for fails quietly, on its own card.
        if (save) setError(message);
      } finally { session.finish(key, signal); }
    })();
  }

  // What a bubble shows for its file. Pictures from people we already talk
  // with are fetched on sight; a stranger's request waits for a tap.
  function bubbleAttachment(scope: string, attachment: AttachmentSummary, trusted: boolean): BubbleAttachment {
    const state = attachmentState(scope, attachment);
    const image = attachment.size <= MAXIMUM_ATTACHMENT_SIZE && isImageAttachment(attachment.mimeType);
    return {
      id: hex(attachment.objectId),
      filename: attachment.filename || (image ? t("Photo") : t("Attachment")),
      image,
      status: describeAttachmentState(attachment, state),
      busy: state?.status === "downloading",
      previewUri: state?.previewUri,
      onPress: () => openAttachment(scope, attachment, true),
      onAppear: trusted && state === undefined && shouldAutoDownload(attachment)
        ? () => openAttachment(scope, attachment, false)
        : undefined,
    };
  }

  function applyPolicy(
    conversation: Conversation,
    action: number,
    value: number,
    status: string,
  ): void {
    void perform(t("Saving…"), async () => {
      await update_conversation_export(
        policyRequest(databasePath, conversation.peerAccountId, action, value),
      );
      setStatus(status);
    });
  }

  function updatePolicy(action: number, value = 0): void {
    if (!selected) return;
    applyPolicy(selected, action, value, t("Saved"));
  }

  function verifySafetyNumber(conversation: Conversation, number: string, scanned: boolean): void {
    const scannedRoute = route;
    void perform(t("Checking the safety number…"), async () => {
      await update_conversation_export(safetyVerificationRequest(databasePath, conversation.peerAccountId, number));
      setStatus(t("Safety number verified"));
      if (scanned) setRoute((current) => current === scannedRoute && current.screen === "scanner"
        ? { screen: "chat-info", direction: transitionDirection("scanner", "chat-info") }
        : current);
    });
  }

  function acceptRequest(conversation: Conversation): void {
    applyPolicy(conversation, 1, 0, t("You can now reply to @{username}", { username: conversation.username }));
  }

  function openScanner(mode: ScanMode): void {
    if (mode === "safety" && (!selected || !/^[0-9a-f]{64}$/.test(selected.safetyNumber))) {
      setError(t("A safety number appears once you’ve exchanged a message."));
      return;
    }
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
    if (replayingOnboarding) {
      endReplay(false);
      return;
    }
    void perform(t("Getting ready to link…"), async () => {
      const request = await create_link_request_export(utf8(databasePath));
      const sas = decodeUtf8(await device_link_sas_export(request));
      setLinkRequest(request);
      setLinkSas(sas);
      setScreen("link-device");
      setStatus(t("This code expires in ten minutes"));
    });
  }

  function openDevices(): void {
    if (!profile) return;
    void perform(t("Checking your devices…"), async () => {
      await refreshDevices(profile);
      setScreen("devices");
      setStatus(t("Devices up to date"));
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
    if (preview) { setError(t("Turn off sample preview to create a group.")); return; }
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
    void perform(draftCommunity ? t("Creating your community…") : t("Creating your group…"), async () => {
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
      setStatus(draftCommunity ? t("Community created. Invite members, then link groups.") : t("Group created. Invite someone to get started."));
    });
  }

  function updateAvatar(key: string, name: string, avatar?: string): void {
    const entry = key.startsWith("group/") ? communityOfGroup(key.slice(6)) : undefined;
    void perform(t("Saving photo…"), async () => {
      if (entry) {
        await writeCommunity(entry, { name, avatar });
        setStatus(t("Photo saved"));
        return;
      }
      const saved = await savePresentation(databasePath, key, { ...presentationOf(key), name, avatar });
      setPresentations((previous) => ({ ...previous, [key]: saved }));
      if (key.startsWith("user/")) advertisedGroups.current.clear();
      else advertisedGroups.current.delete(key.slice(6));
      setStatus(t("Photo saved"));
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
    void perform(t("Saving name…"), async () => {
      try {
        const saved = nickname
          ? await saveNickname(databasePath, key, value)
          : await savePresentation(databasePath, key, presentation);
        setPresentations((previous) => ({ ...previous, [key]: saved }));
        if (!nickname) advertisedGroups.current.clear();
        setNameEditor(null);
        setStatus(t("Name saved"));
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
        name={name || (group ? t("New group") : "")}
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
        label={t("Remove photo")}
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
      <Page header={<Header title={draftCommunity ? t("New community") : t("New group")} onBack={() => go("groups")} backLabel={t("Cancel")} />}>
        <KeyboardAwareScrollView
          bottomOffset={formKeyboardOffset}
          contentContainerStyle={[layout.content, styles.newGroup]}
          keyboardShouldPersistTaps="handled"
        >
          <View style={styles.newGroupPhoto}>
            {renderPhotoButton(groupDraftName, groupDraftAvatar, setGroupDraftAvatar, { group: true })}
            {groupDraftAvatar ? renderRemovePhoto(() => setGroupDraftAvatar(undefined)) : null}
          </View>
          <Field
            label={draftCommunity ? t("Community name") : t("Group name")}
            value={groupDraftName}
            onChangeText={setGroupDraftName}
            placeholder={draftCommunity ? t("Solana builders") : t("Weekend walks")}
            maxLength={96}
            autoFocus
            hint={t("Shown to everyone you invite. You can change both later in group details.")}
          />
          <RowGroup>
            <Row
              icon="megaphone"
              title={t("Community")}
              subtitle={t("Announcements only you post, and groups members can ask to join.")}
              trailing={<Toggle label={t("Community")} value={draftCommunity} onValueChange={setDraftCommunity} />}
            />
          </RowGroup>
          {draftCommunity ? (
            <Field
              label={t("Description")}
              value={groupDraftAbout}
              onChangeText={setGroupDraftAbout}
              placeholder={t("What this community is for")}
              multiline
              maxLength={500}
            />
          ) : null}
          <Actions>
            <Button
              label={draftCommunity ? t("Create community") : t("Create group")}
              onPress={finishGroupCreation}
              disabled={busy || pickingPhoto || !groupDraftName.trim()}
            />
          </Actions>
          <Text style={[type.footnote, styles.newGroupNote]}>{t("You’ll invite people next.")}</Text>
        </KeyboardAwareScrollView>
      </Page>
    );
  }

  function showGroupKeyPackage(): void {
    void perform(t("Preparing your code…"), async () => {
      setGroupKeyPackage(await getGroupKeyPackage(databasePath));
      if (isDesktop && screen !== "group-package") setGroupPackageOrigin(screen);
      setScreen("group-package");
      setStatus(t("Show this code to a group member"));
    });
  }

  function inviteByUsername(): void {
    if (!selectedGroupId) return;
    const target = groupUsername.trim().toLowerCase().replace(/^@/, "");
    if (!/^[a-z0-9._-]{1,64}$/.test(target)) {
      setError(t("Enter their exact username."));
      return;
    }
    const entry = selectedEntry;
    if (entry && Object.values(communityData).some((part) => part.details.members.some((member) => member.username === target))) {
      setError(t("@{target} is already in the community.", { target }));
      return;
    }
    void perform(t("Sending invitation…"), async () => {
      await inviteToGroup(databasePath, profile!, entry ? await communityPartFor(entry) : selectedGroupId, target);
      setGroupUsername("");
      setStatus(t("Invitation sent to @{target}", { target }));
    });
  }

  function answerGroupInvitation(invitation: GroupInvitation, accept: boolean): void {
    void perform(accept ? t("Accepting invitation…") : t("Declining invitation…"), async () => {
      if (accept) await acceptGroupInvitation(databasePath, profile!, invitation);
      else await declineGroupInvitation(databasePath, invitation.reference);
      setStatus(accept ? t("Accepted. You’ll join when the inviter is next online.") : t("Invitation declined"));
    });
  }

  function scanGroupKeyPackage(): void {
    const target = groupUsername.trim().toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(target)) {
      setError(t("Enter their exact username before scanning their code."));
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
    void perform(t("Sending…"), async () => {
      const queued = await sendWithAttachment(scope, { groupIds: selectedEntry ? selectedEntry.parts.map(fromHex) : [selectedGroupId] }, async (attachment) => {
        if (!selectedEntry) return sendGroupMessage(databasePath, selectedGroupId, outgoingBody(text), attachment);
        // An announcement goes to every part; a reply quotes each part's own copy.
        const pending: Uint8Array[] = [];
        for (const part of selectedEntry.parts) {
          const copy = answered?.copies.find((item) => item.part === part && item.messageId);
          try { await sendGroupMessage(databasePath, fromHex(part), copy ? encodeReply(hex(copy.messageId!), text) : text, attachment); }
          catch (caught) { if (!(caught instanceof PostageRequired)) throw caught; pending.push(...caught.triggerIds); }
        }
        if (pending.length) throw new PostageRequired(pending);
      });
      setGroupComposer("");
      setReplying(null);
      setStatus(queued ? t("Message queued. Review postage before delivery.") : t("Sent"));
    });
  }

  // Removing a person removes every device they are in the group with.
  function removeFromGroup(person: Person, name: string): void {
    if (!selectedGroupId) return;
    void perform(t("Removing {name} from the group…", { name }), async () => {
      for (const deviceId of person.deviceIds) {
        await removeGroupMember(databasePath, selectedGroupId, person.accountId, deviceId);
      }
      setStatus(t("{name} removed from the group", { name }));
    });
  }

  // The owner changes what members see of the community; the record reaches
  // them with the next message from this device, which the refresh sends.
  // Every part carries the same record. The owner or an admin writes each part
  // this device is in; members get it with the next message from this device,
  // which the refresh sends, and the other parts from devices that are there.
  async function writeCommunity(entry: CommunityEntry, change: Partial<Presentation>): Promise<void> {
    const base = presentationOf(`group/${entry.parts[0]}`);
    if (!base) throw new Error(t("The community is still loading."));
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
    void perform(t("Saving the community…"), async () => {
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
    void perform(t("Removing {name} from the community…", { name }), async () => {
      if (community?.admins.includes(accountId)) {
        await writeCommunity(selectedEntry!, { community: withRoles(community, { admins: community.admins.filter((admin) => admin !== accountId) }) });
      }
      for (const [part, { details }] of Object.entries(communityData)) {
        for (const member of details.members.filter((item) => hex(item.accountId) === accountId)) {
          await removeGroupMember(databasePath, fromHex(part), member.accountId, member.deviceId);
        }
      }
      setStatus(t("{name} removed from the community", { name }));
    });
  }

  // Asking to join from outside is a message to whoever shared the link.
  function askToJoinCommunity(link: CommunityLink): void {
    if (link.admin === ownUsername) { setError(t("That’s your own community’s link.")); return; }
    if (communityIndex.has(link.community)) { setError(t("You’re already in {name}.", { name: link.name })); return; }
    void perform(t("Asking @{admin}…", { admin: link.admin }), async () => {
      const changed = await sendFanout(databasePath, profile!, link.admin, encodeCommunityRequest(link.community, link.name));
      setScannedCommunity(null);
      setScreen("groups");
      noteSent(link.admin, changed);
      setStatus(t("Asked @{admin} to let you into {name}", { admin: link.admin, name: link.name }));
    });
  }

  // Approving someone accepts their message request, invites them to a part
  // with room and tells them which, so their device accepts it for them.
  function approveAsk(conversation: Conversation, request: UnansweredRequest): void {
    const entry = selectedEntry;
    if (!entry) return;
    setReviewing(null);
    void perform(t("Letting @{username} in…", { username: conversation.username }), async () => {
      if (conversation.requestPending) {
        await update_conversation_export(policyRequest(databasePath, conversation.peerAccountId, 1, 0));
      }
      const part = await communityPartFor(entry);
      await inviteToGroup(databasePath, profile!, part, conversation.username);
      await sendFanout(databasePath, profile!, conversation.username, encodeCommunityAnswer(request.community, hex(part)), conversation.peerAccountId);
      setStatus(t("@{username} is invited", { username: conversation.username }));
    });
  }

  // Declining stays on this device: a request that was never accepted can't be answered.
  function declineAsk(conversation: Conversation, request: UnansweredRequest): void {
    if (!profile) return;
    const expected = profile.slice();
    setReviewing(null);
    const scope = `chat/${hex(conversation.conversationId)}`;
    const next = { ...declinedRequests, [scope]: [...(declinedRequests[scope] ?? []), request.key].slice(-256) };
    setDeclinedRequests(next);
    saveDeclinedRequests(expected, next).catch(() => { if (visibleAccountIdentity.current === accountProfileIdentity(expected)) setError(t("That couldn’t be saved. The request may come back after restarting.")); });
    setStatus(t("Declined @{username}", { username: conversation.username }));
  }

  // A community link shared in a message can be answered from that message.
  function communityLinkAction(body: string) {
    const link = /mesh:\/\/community\/[A-Za-z0-9_-]+/.exec(body)?.[0];
    const read = link ? readCommunityLink(link) : undefined;
    return read ? {
      icon: "link" as const,
      label: t("Ask to join {name}", { name: read.name }),
      onPress: () => { openScanner("community"); setScannedCommunity(read); },
    } : undefined;
  }

  function copyCommunityLink(value: string): void {
    void services.copyProtectedText(value).then(() => setStatus(t("Link copied")), caught => setError(friendlyError(caught)));
  }

  function confirmLeave(entry: CommunityEntry): void {
    confirm({
      title: t("Leave this community?"),
      body: t("It’s removed from all your devices, and its admins remove you from it. Groups you joined through it stay."),
      action: t("Leave community"),
      run: () => void perform(t("Leaving the community…"), async () => {
        for (const part of entry.parts) await sendGroupMessage(databasePath, fromHex(part), LEAVE_REQUEST);
        for (const part of entry.parts) await forgetGroup(databasePath, fromHex(part));
        setSelectedGroupId(null);
        setScreen("groups");
        setStatus(t("You left the community"));
      }),
    });
  }

  function changeRoles(change: Partial<{ owner: string; admins: string[] }>, done: string): void {
    if (!selectedCommunity) return;
    saveCommunity(withRoles(selectedCommunity, change), done);
  }

  function confirmHandover(accountId: string, name: string): void {
    confirm({
      title: t("Make {name} the owner?", { name }),
      body: t("They take over the community’s roles, and you stay on as an admin. Only they can make you owner again."),
      action: t("Make owner"),
      run: () => changeRoles({ owner: accountId }, t("{name} owns the community now", { name })),
    });
  }

  function askToJoin(groupId: string): void {
    if (!selectedGroupId) return;
    const communityId = selectedGroupId;
    void perform(t("Asking to join…"), async () => {
      await sendGroupMessage(databasePath, communityId, encodeJoinRequest(groupId));
      setStatus(t("Asked. The invitation appears here when an admin adds you."));
    });
  }

  function approveRequest(request: JoinRequest, username: string): void {
    const group = groups.find((item) => hex(item.groupId) === request.groupId);
    if (!group) return;
    void perform(t("Inviting @{username}…", { username }), async () => {
      await inviteToGroup(databasePath, profile!, group.groupId, username);
      setStatus(t("Invitation sent to @{username}", { username }));
    });
  }

  function authorizeScannedDevice(): void {
    if (!profile || !scannedLinkRequest) return;
    void perform(t("Approving the new device…"), async () => {
      const loaded = await loadAccountDevices(databasePath, profile);
      const authorization = await authorizeDeviceLink(
        databasePath,
        loaded.wire,
        scannedLinkRequest,
      );
      setLinkAuthorization(authorization);
      setScreen("link-authorization");
      setStatus(t("Device approved"));
    });
  }

  // The system alert asks on a phone; the desktop has its own dialog.
  function confirm(confirmation: Confirmation): void {
    if (Platform.OS === "web") { setPendingConfirm(confirmation); return; }
    let settled = false;
    const settle = (approved: boolean) => { if (settled) return; settled = true; if (approved) confirmation.run(); else confirmation.cancel?.(); };
    Alert.alert(confirmation.title, confirmation.body, [
      { text: t("Cancel"), style: "cancel", onPress: () => settle(false) },
      { text: confirmation.action, style: confirmation.primary ? "default" : "destructive", onPress: () => settle(true) },
    ], { cancelable: true, onDismiss: () => settle(false) });
  }

  function confirmRevoke(deviceId: Uint8Array): void {
    confirm({
      title: t("Remove this device?"),
      body: t("It permanently loses access to your account and future messages, and erases its own messages and keys the next time it’s online."),
      action: t("Remove device"),
      run: () => revokeLinkedDevice(deviceId),
    });
  }

  // The device that created the account deletes it everywhere. A linked device
  // holds no account key, so it leaves the account and erases only itself.
  function confirmDeleteAccount(): void {
    if (!profile) return;
    const expected = profile.slice();
    void holdsAccountKey(databasePath, expected).then(
      (everywhere) => {
        if (visibleAccountIdentity.current !== accountProfileIdentity(expected)) return;
        confirm(everywhere ? {
          title: t("Delete your account?"),
          body: t("Your username, messages and keys are erased from the server, from this device, and from your linked devices as soon as they’re online. No one can reach this account again. This can’t be undone."),
          action: t("Delete account"),
          run: () => deleteAccountNow(expected),
        } : {
          title: t("Erase this device?"),
          body: t("This device leaves your account, and its messages and keys are erased from it. The account stays on your other devices."),
          action: t("Erase device"),
          run: () => deleteAccountNow(expected),
        });
      },
      (caught) => setError(friendlyError(caught)),
    );
  }

  function deleteAccountNow(expected: Uint8Array): void {
    if (visibleAccountIdentity.current !== accountProfileIdentity(expected)) return;
    setLeaving(true);
    setBusy(true);
    setError("");
    setStatus(t("Deleting your account…"));
    void (async () => {
      try {
        await rememberErasureNotifications(expected);
        await deleteAccount(databasePath, expected);
        await finishErasing(expected);
      } catch (caught) {
        if (visibleAccountIdentity.current === accountProfileIdentity(expected)) setError(friendlyError(caught));
      } finally {
        if (visibleAccountIdentity.current === accountProfileIdentity(expected)) {
          setLeaving(false);
          setBusy(false);
        }
      }
    })();
  }

  async function readCurrentAccount(): Promise<Uint8Array | null> {
    try { return await load_profile_export(utf8(databasePath)); }
    catch (caught) {
      if (isMissingAccountProfile(caught)) return null;
      throw caught;
    }
  }

  async function rememberErasureNotifications(expected: Uint8Array): Promise<void> {
    const identity = accountProfileIdentity(expected);
    if (visibleAccountIdentity.current !== identity) throw new Error("account_state_changed");
    const ids = await captureErasureNotifications(expected, {
      readProfile: readCurrentAccount,
      presented: presentedAccountNotifications,
    });
    if (visibleAccountIdentity.current !== identity) throw new Error("account_state_changed");
    const previous = erasureNotifications.current;
    erasureNotifications.current = {
      identity,
      ids: [...new Set([...(previous?.identity === identity ? previous.ids : []), ...ids])].slice(0, 1024),
    };
  }

  async function finishErasing(expected: Uint8Array, reason?: string): Promise<void> {
    const identity = accountProfileIdentity(expected);
    const captured = erasureNotifications.current;
    try {
      const finished = await finishAccountErasure(expected, captured?.identity === identity ? captured.ids : [], {
        readProfile: readCurrentAccount,
        visibleIdentity: () => visibleAccountIdentity.current,
        dismiss: dismissAccountNotification,
        cleanup: () => forgetPreferences(hex(parseProfileSummary(expected).accountId)),
        finish: () => {
          attachmentSession.current?.close();
          discardPreviews();
          onAccountErased(reason);
        },
      });
      if (!finished && visibleAccountIdentity.current === identity) {
        const replacement = await readCurrentAccount();
        if (replacement && visibleAccountIdentity.current === identity) setProfile(replacement);
      }
    } catch (caught) {
      if (visibleAccountIdentity.current === identity) setSyncError(friendlyError(caught));
    } finally {
      if (visibleAccountIdentity.current === identity) {
        setLeaving(false);
        setBusy(false);
      }
    }
  }

  function revokeLinkedDevice(deviceId: Uint8Array): void {
    if (!profile || !deviceSet) return;
    void perform(t("Removing the device…"), async () => {
      await revokeDevice(databasePath, deviceSet, deviceId);
      const current = await refreshDevices(profile);
      const removed = current.devices.find(device => hex(device.deviceId) === hex(deviceId));
      setStatus(removed && !removed.active && !removed.expired
        ? t("Device removed")
        : t("Device removal requested. Waiting for witnesses."));
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
    if (scanMode === "safety") {
      try {
        if (!selected) throw new Error("safety_number_unavailable");
        verifySafetyNumber(selected, safetyFromQr(data), true);
      } catch (caught) {
        qrCollector.reset();
        setError(friendlyError(caught));
      }
    } else if (scanMode === "community") {
      const link = readCommunityLink(data);
      if (link) {
        setScannedCommunity(link);
        setError("");
      } else {
        qrCollector.reset();
        setError(t("That isn’t a community link. Ask for the link again."));
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
      void perform(t("Checking the code…"), async () => {
        const request = linkRequestFromQr(data);
        const sas = decodeUtf8(await device_link_sas_export(request));
        setScannedLinkRequest(request);
        setLinkSas(sas);
        setStatus(t("Compare this code on both devices"));
      });
    } else if (scanMode === "link-authorization") {
      setScreen("link-device");
      void perform(t("Finishing the link…"), async () => {
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
        setStatus(t("This device is linked"));
      });
    } else {
      const groupId = selectedGroupId;
      const target = groupUsername.trim().toLowerCase();
      if (!groupId || !target) {
        setError(t("Choose a group and enter the exact username before scanning."));
        return;
      }
      void perform(
        t("Adding @{target} to the group…", { target }),
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
            setStatus(t("@{target} added to the group", { target }));
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
      if (cancelled || !historyCacheEpoch.current.current(cacheEpoch)) return;
      const now = Date.now();
      const visibleEntries = entries.map(([id, part]) => [id, { ...part, messages: unexpiredHistory(part.messages, now) }] as const);
      setCommunityParts(Object.fromEntries(visibleEntries));
      await refreshPresentations(visibleEntries.flatMap(([, part]) => [
        ...part.details.members.map((member) => `user/${hex(member.accountId)}`),
        ...part.messages.map((message) => `user/${hex(message.senderAccountId)}`),
      ]));
    }).catch((caught) => {
      if (!cancelled) setError(friendlyError(caught));
    });
    return () => { cancelled = true; };
  }, [partsKey, groups, preview, databasePath, profile, cacheEpoch]);
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
    return { name: name ?? t("Member {id}", { id: id.slice(0, 6) }), username, accountId: id,
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
  const mainScreen = profile && !replayingOnboarding && !draftPending && ["home", "groups", "settings"].includes(screen);
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
    void perform(t("Joining the community…"), async () => {
      for (const invitation of due) await acceptGroupInvitation(databasePath, profile!, invitation);
      setStatus(t("Approved. You join as soon as they’re next online."));
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
    screen === "credits" && draftPending ? "home" : screen === "scanner" ? scannerOrigin(scanMode) : parentScreen(screen, isDesktop ? groupPackageOrigin : undefined);
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
      if (activityOverlay?.dismissTop()) return true;
      if (membersOpen) {
        setMembersOpen(false);
        return true;
      }
      if (onboardingActive) {
        if (onboardingStep === "profile") goOnboarding("welcome");
        else if (replayingOnboarding) endReplay(false);
        else return false;
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
    if (conversation.blocked) return t("Blocked");
    const last = previewOf(conversation);
    if (last) {
      const text = attachmentPreviewText(last);
      return last.direction === "sent" ? t("You: {text}", { text }) : text;
    }
    if (conversation.requestPending) return t("Wants to start a conversation");
    return t("Encrypted conversation");
  }

  // The state of a conversation worth a glyph beside its name, matching the
  // ones its row in the list carries. Everything is encrypted, so the
  // ordinary case shows nothing; a pending request has its banner in the thread.
  function conversationMark(conversation: Conversation) {
    if (conversation.blocked)
      return { icon: "block", color: colors.text3, label: t("Blocked") } as const;
    if (conversation.keyChanged)
      return { icon: "warning", color: colors.warning, label: t("Safety number changed") } as const;
    if (conversation.verified)
      return { icon: "shield", color: colors.success, label: t("Safety number verified") } as const;
    return undefined;
  }

  // What the app is, before anything is asked of you: a conversation opening
  // on its own, the promise, three things worth knowing, and the way in. On a
  // phone the picture takes whatever height the words leave, so the buttons
  // stay at the foot of the screen, and the page only scrolls when large text
  // leaves no room at all. The desktop sets the picture beside the words.
  function renderWelcome() {
    return (
      <View style={layout.flex}>
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
                {t("Private messaging,\nmade simple.")}
              </Text>
              <Text style={type.body}>{t("Pick a username and start talking.")}</Text>
            </Reveal>
            <Reveal delay={120} style={styles.facts}>
              <Fact icon="lock">{t("End-to-end encrypted")}</Fact>
              <Fact icon="person">{t("No phone number, no contact upload")}</Fact>
              <Fact icon="shield">{t("Verify contacts with safety numbers")}</Fact>
            </Reveal>
            {notice ? <Notice text={notice} /> : null}
            <Reveal delay={180}>
              <Actions>
                <Button label={t("Get started")} onPress={() => goOnboarding("profile")} />
                <Button
                  label={t("Link an existing account")}
                  onPress={beginDeviceLink}
                  variant="ghost"
                />
              </Actions>
            </Reveal>
          </View>
        </ScrollView>
        {/* The first thing a new account can change: it starts in the phone's
            language, and stays one tap away in You. */}
        <View style={styles.languageCorner}>
          <Button
            label={languageLabel}
            accessibilityLabel={t("Language: {name}", { name: languageLabel })}
            icon="globe"
            size="sm"
            variant="secondary"
            onPress={() => setChoosingLanguage(true)}
          />
        </View>
      </View>
    );
  }

  // Each language greets in itself, with its name beneath, in a row across
  // the sheet; the one in effect is drawn as a message you sent. The phone's
  // own language leads, as the choice most people keep.
  function renderLanguageDialog() {
    const choice = (key: string, label: string, chosen: boolean, onPress: () => void, content: ReactNode) => (
      <Tap
        key={key}
        label={label}
        role="radio"
        state={{ checked: chosen }}
        scaleTo={0.98}
        onPress={onPress}
        style={[styles.languageChoice, chosen && styles.languageChoiceChosen]}
      >
        {content}
        {chosen ? <Icon name="check" size={size.icon.lg} color={colors.onAccent} strokeWidth={2.6} /> : null}
      </Tap>
    );
    const phone = languageChoice === "system";
    return (
      <Dialog visible={choosingLanguage} label={t("Language")} onClose={() => setChoosingLanguage(false)}>
        <ScrollView contentContainerStyle={styles.languageSheet}>
          <Text accessibilityRole="header" style={[type.title2, styles.languageTitle]}>{t("Language")}</Text>
          {choice("system", `${t("Phone language")}, ${nativeName(systemLanguage)}`, phone, () => chooseLanguage("system"), <>
            <Icon name="device" size={size.icon.xl} color={phone ? colors.onAccent : colors.accent} strokeWidth={2} />
            <View style={layout.flex}>
              <Text style={[styles.languageGreeting, phone && styles.languageChosenText]}>{t("Phone language")}</Text>
              <Text style={[type.footnote, phone && styles.languageChosenMuted]}>{nativeName(systemLanguage)}</Text>
            </View>
          </>)}
          <View style={styles.languageGap} />
          {languages.map((language) => {
            const chosen = languageChoice === language.code;
            const translatedName = t(languageNames[language.code]);
            return choice(
              language.code,
              translatedName === language.name ? language.name : `${language.name}, ${translatedName}`,
              chosen,
              () => chooseLanguage(language.code),
              <View style={layout.flex}>
                <Text style={[styles.languageGreeting, chosen && styles.languageChosenText]}>{language.greeting}</Text>
                <Text style={[type.footnote, chosen && styles.languageChosenMuted]}>
                  {translatedName === language.name ? language.name : `${language.name} · ${translatedName}`}
                </Text>
              </View>,
            );
          })}
        </ScrollView>
      </Dialog>
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
      ? t("That username is taken. Try another.")
      : problem === "characters"
        ? t("Use only lowercase letters, numbers, and underscores.")
        : problem === "long"
          ? t("Use 32 characters or fewer.")
          : undefined;
    const submit = problem === null && !taken ? createAccount : undefined;
    const intro = <>
      <Text accessibilityRole="header" style={isDesktop ? type.largeTitle : [type.title, layout.centerText]}>{t("Pick a username.")}</Text>
      <Text style={[type.body, !isDesktop && layout.centerText]}>{t("It is how people reach you. Your private keys stay on your devices.")}</Text>
    </>;
    const form = <>
          <Reveal delay={60} style={layout.stackLoose}>
            <Field
              label={t("Choose your username")}
              value={username}
              onChangeText={(value) => setUsername(value.replace(/^@+/, "").toLowerCase())}
              placeholder="your_name"
              prefix="@"
              maxLength={32}
              hint={t("3–32 lowercase letters, numbers, or underscores.")}
              error={usernameError}
              returnKeyType="next"
              onSubmitEditing={() => displayNameInput.current?.focus()}
            />
            <Field
              label={t("Display name (optional)")}
              value={displayName}
              onChangeText={setDisplayName}
              placeholder={t("What people call you")}
              maxLength={96}
              hint={t("Shown to people you message. You can change it later.")}
              inputRef={displayNameInput}
              returnKeyType="done"
              onSubmitEditing={submit}
            />
          </Reveal>
          <Reveal delay={120}>
            <Actions>
              <Button label={t("Create account")} disabled={busy || pickingPhoto || !submit} onPress={createAccount} />
              {!replayingOnboarding && <Button label={t("Check signup options")} variant="ghost" disabled={busy || pickingPhoto || !submit} onPress={checkSignupOptions} />}
              {signupPolicy?.enabled && signupPolicy.currentDifficulty > signupPolicy.baseDifficulty && !replayingOnboarding ? <>
                <Notice text={t("Free signup is available. You can also prepare a local profile and choose to spend 20 credits when you are ready.")} />
                <Button label={t("Set up priority signup")} variant="secondary" disabled={busy || pickingPhoto || !submit} onPress={createPaidSignupDraft} />
              </> : priorityUnavailable || signupPolicy ? <Notice text={t("Priority signup is not available. You can use the free path.")} /> : null}
            </Actions>
          </Reveal>
    </>;
    const name = displayName || username;
    return (
      <Page
        header={
          <Header
            title={t("Your profile")}
            onBack={() => goOnboarding("welcome")}
            {...sheetHeader}
          />
        }
      >
        {/* The desktop keeps the welcome's spread, so the words stay where
            they were and the picture becomes the identity being made. */}
        {isDesktop ? (
          <KeyboardAwareScrollView
            bottomOffset={formKeyboardOffset}
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
          </KeyboardAwareScrollView>
        ) : (
          <KeyboardAwareScrollView
            bottomOffset={formKeyboardOffset}
            contentContainerStyle={layout.content}
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
          >
            <Reveal style={styles.profileHead}>
              {renderPhotoEditor(name, accountAvatar, setAccountAvatar, avatarSeed, heroAvatarSize)}
              {intro}
            </Reveal>
            {form}
          </KeyboardAwareScrollView>
        )}
      </Page>
    );
  }

  function renderLinkDevice(request: Uint8Array) {
    return (
      <Page
        header={
          <Header
            title={t("Link this device")}
            onBack={() => go("home")}
            backLabel={t("Cancel")}
            {...sheetHeader}
          />
        }
      >
        <ScrollView contentContainerStyle={[layout.content, sheetContent]}>
          <QrLayout
            intro={
              <View style={layout.stackLoose}>
                <Text style={type.title}>{t("Bring your account along.")}</Text>
                <Steps>
                  {[
                    <>{richText(t("On the device you signed up on, open {place} and choose {action}."), {
                      place: <Strong>{t("You → Linked devices")}</Strong>,
                      action: <Strong>{t("Link another device")}</Strong>,
                    })}</>,
                    t("Scan this code with it."),
                    t("Check that both screens show the same code."),
                    Platform.OS === "web" ? t("Enter the approval code it shows you.") : t("Scan the approval code it shows you."),
                  ]}
                </Steps>
              </View>
            }
            qr={<QrCard value={payloadQrValue("link-request", request)} />}
            details={
              <CodeBlock
                label={t("Match this code on both devices")}
                value={linkSas}
                note={t("The request expires in 10 minutes.")}
              />
            }
            actions={
              <Actions>
                <Button
                  label={Platform.OS === "web" ? t("Enter the approval code") : t("Scan the approval code")}
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
            title={scanMode === "safety" ? t("Verify safety number") : scanMode === "community" ? t("Join a community") : Platform.OS === "web" ? t("Enter a code") : t("Scan a code")}
            onBack={backToScannerOrigin}
            backLabel={t("Cancel")}
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
              subtitle={t("Community · shared by @{admin}", { admin: scannedCommunity.admin })}
              badge={<Badge label={t("Community link")} icon="link" />}
            />
            <Notice text={t("Your request goes to @{admin} as a message. Once they let you in, you join on this device.", { admin: scannedCommunity.admin })} />
            <Actions>
              <Button label={t("Ask to join")} onPress={() => askToJoinCommunity(scannedCommunity)} />
              <Button
                label={Platform.OS === "web" ? t("Enter another link") : t("Scan again")}
                onPress={() => openScanner("community")}
                variant="ghost"
              />
            </Actions>
          </ScrollView>
        ) : scannedProfile ? (
          <KeyboardAwareScrollView
            bottomOffset={formKeyboardOffset}
            contentContainerStyle={[layout.content, sheetContent]}
            keyboardShouldPersistTaps="handled"
          >
            <Hero
              name={parseProfileSummary(scannedProfile).username}
              colorSeed={hex(parseProfileSummary(scannedProfile).accountId)}
              title={`@${parseProfileSummary(scannedProfile).username}`}
              badge={<Badge label={t("Contact code captured")} icon="check" />}
            />
            <Notice text={t("Compare safety numbers together after connecting.")} />
            <Field
              label={t("First message")}
              multiline
              value={firstMessage}
              onChangeText={setFirstMessage}
              placeholder={t("Say hello…")}
            />
            <Actions>
              <Button
                label={t("Send message request")}
                disabled={!firstMessage.trim()}
                onPress={() => startWithProfile(scannedProfile, firstMessage)}
              />
              <Button
                label={t("Scan again")}
                onPress={() => openScanner("contact")}
                variant="ghost"
              />
            </Actions>
          </KeyboardAwareScrollView>
        ) : scannedLinkRequest ? (
          <ScrollView contentContainerStyle={[layout.content, sheetContent]}>
            <View style={layout.stack}>
              <Text style={type.title}>{t("Do these codes match?")}</Text>
              <Text style={type.body}>{t("Check the code shown on the new device before giving it access to your account.")}</Text>
            </View>
            {isDesktop ? (
              <CodeBlock label={t("The new device should show")} value={linkSas} />
            ) : (
              <Card tone="accent" style={layout.center}>
                <CodeDisplay value={linkSas} />
              </Card>
            )}
            <Actions>
              <Button
                label={t("Authorize this device")}
                icon="check"
                onPress={authorizeScannedDevice}
              />
              <Button
                label={Platform.OS === "web" ? t("Reject and enter another code") : t("Reject and scan again")}
                onPress={() => openScanner("link-request")}
                variant="ghost"
              />
            </Actions>
          </ScrollView>
        ) : Platform.OS === "web" ? (
          // Desktop accepts the same canonical code as the camera scanner.
          <ScrollView contentContainerStyle={[layout.content, sheetContent]}>
            <View style={layout.stack}>
              <Text style={type.title}>{scanMode === "community" ? t("Paste a community link") : t("Paste the code from the other device")}</Text>
              <Text style={type.body}>
                {scanMode === "community"
                  ? t("Ask someone who runs the community for its link, then paste it here.")
                  : t("On the other device, choose Show text code under the code, copy it, and paste it here.")}
              </Text>
            </View>
            <Field
              label={scanMode === "safety" ? t("Safety code") : scanMode === "community" ? t("Community link") : t("Device code")}
              placeholder={scanMode === "community" ? t("Paste the link here") : t("Paste the code here")}
              value={pastedCode}
              onChangeText={setPastedCode}
              multiline
            />
            <Actions>
              <Button
                label={scanMode === "community" ? t("Read link") : t("Read code")}
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
            title={t("Camera access")}
            body={t("Camera frames never leave your device.")}
            action={
              <Button
                label={t("Allow camera")}
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
            <Reticle hint={t("Hold the code inside the frame")} />
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
      <Page keyboard header={<Header title={t("New message")} {...backTo("home")} />}>
        <ScrollView
          contentContainerStyle={[layout.centredScreen, { paddingBottom: composerHeight }]}
          keyboardShouldPersistTaps="handled"
        >
          <EmptyState
            icon="compose"
            title={t("Start a private conversation.")}
            body={t("Only they can accept your first message.")}
            action={
              Platform.OS === "web" ? undefined : (
                <Button
                  label={t("Scan a contact code")}
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
          label={t("First message")}
          sendLabel={t("Send message request")}
          value={firstMessage}
          onChangeText={setFirstMessage}
          onSend={startByUsername}
          disabled={busy}
          sendDisabled={!addressed}
          placeholder={t("Write a message…")}
          onHeightChange={setComposerHeight}
          inputRef={firstMessageInput}
          autoFocus={addressed}
          attachments={composerAttachments("new-chat")}
          onAttach={() => attachFile("new-chat")}
          onSavedUploads={() => setSavedUploadsScope("new-chat")}
          onRemoveAttachment={unstageAttachment}
          dropping={dropping}
        />
      </Page>
    );
  }

  function renderAccount(currentProfile: Uint8Array) {
    return (
      <Page header={<Header title={t("My QR code")} onBack={() => go("settings")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <QrLayout
            intro={
              <Hero
                name={ownName}
                avatar={ownAvatar}
                colorSeed={ownId}
                title={ownName}
                subtitle={t("@{ownUsername} · Have a friend scan this to connect.", { ownUsername })}
              />
            }
            qr={
              <QrCard
                value={profileQrValue(currentProfile)}
                caption={t("Only your public contact details are shared")}
              />
            }
            details={
              <Notice text={t("Keep the whole code in view while it cycles. Verify safety numbers together after connecting.")} />
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
    const theme = translated(appearanceOptions).find((option) => option.value === appearance);
    return (
      <Page header={<LargeHeader title={t("You")} />}>
        <ScrollView contentContainerStyle={layout.contentTight}>
          <Section footer={t("People you message see this name and photo.")}>
            <Card style={styles.profileCard}>
              {renderPhotoButton(ownName, ownAvatar, setOwnPhoto, { size: size.avatar["2xl"], seed: ownId })}
              <View style={layout.flex}>
                <Text numberOfLines={1} style={type.title2}>{ownName}</Text>
                <Text numberOfLines={1} style={type.subhead}>@{ownUsername}</Text>
              </View>
              <IconButton name="qr" label={t("My QR code")} variant="soft" glass={false} size={isDesktop ? control.lg : undefined} onPress={() => go("account")} />
            </Card>
          </Section>
          <Section
            title={t("Account")}
          >
            <RowGroup>
              <Row
                icon="person"
                title={t("Display name")}
                subtitle={ownName}
                onPress={preview ? undefined : () => {
                  if (ownProfile) editName(`user/${hex(ownProfile.accountId)}`, ownName === ownUsername ? "" : ownName);
                }}
              />
              {ownAvatar && !preview ? (
                <Row
                  icon="image"
                  title={t("Remove photo")}
                  onPress={busy || pickingPhoto ? undefined : () => setOwnPhoto(undefined)}
                  trailing={null}
                />
              ) : null}
              <Row
                icon="device"
                title={t("Linked devices")}
                subtitle={
                  activeDevices
                    ? t.plural("{count} active device", "{count} active devices", activeDevices)
                    : t("Manage account access")
                }
                onPress={openDevices}
              />
            </RowGroup>
          </Section>
          <Section title={t("Notifications")}>
            <RowGroup>
              <Row
                icon="bell"
                title={t("Notifications")}
                subtitle={pushError || t(pushSummary(pushStatus))}
                tone={pushStatus === "enabled" ? "muted" : "danger"}
                trailing={
                  <Toggle
                    label={t("Notifications")}
                    value={pushStatus === "enabled" || pushStatus === "pending-bind"}
                    disabled={pushBusy || preview !== null}
                    // Flipping a switch stuck turning off retries the cleanup.
                    onValueChange={() =>
                      void updatePush(() =>
                        pushStatus === "pending-unbind"
                          ? recoverPushBinding(databasePath, profile!.slice())
                          : pushStatus !== "disabled"
                            ? disablePushBinding(databasePath, profile!.slice())
                            : enablePushBinding(databasePath, profile!.slice()),
                      )
                    }
                  />
                }
              />
              <Row
                icon="chat"
                title={t("Previews")}
                subtitle={translated(notificationPreviewOptions).find((option) => option.value === notificationPreview)?.label}
                trailing={
                  <Segmented
                    label={t("Notification previews")}
                    options={translated(notificationPreviewOptions)}
                    value={notificationPreview}
                    onSelect={(chosen) => {
                      setNotificationPreview(chosen);
                      if (profile) {
                        const expected = profile.slice();
                        void saveNotificationPreview(expected, chosen).catch(() => {
                          if (visibleAccountIdentity.current === accountProfileIdentity(expected)) setError(t("That choice couldn’t be saved. It applies until you restart."));
                        });
                      }
                    }}
                  />
                }
              />
            </RowGroup>
          </Section>
          {!preview && profile && services.backups.kind === 'available' ? <Section title={t('Backups')}>
            <RowGroup>
              <Row icon="file" title={t('Export encrypted backup')} onPress={() => go('backup-export')} />
              <Row icon="file" title={t('Import or view backups')} onPress={() => go('backups')} />
            </RowGroup>
          </Section> : null}
          <Section title={t("Privacy")}>
            <RowGroup>
              {services.supportsAppLock ? <Row
                icon="key"
                title={t("App lock")}
                subtitle={t("Use device biometrics or passcode. When enabled, notifications show generic activity only and background message processing pauses.")}
                trailing={<Toggle label={t("App lock")} value={services.appLockEnabled}
                  disabled={busy || preview !== null}
                  onValueChange={enabled => { void services.setAppLockEnabled(enabled).catch(caught => setError(friendlyError(caught))); }} />}
              /> : null}
              {services.supportsAppLock && services.appLockEnabled ? <Row icon="key" title={t("Lock now")}
                onPress={() => { void services.lockApp().catch(caught => setError(friendlyError(caught))); }} /> : null}
              <Row
                icon="checks"
                title={t("Read receipts")}
                subtitle={readReceipts ? t("People see when you’ve read their messages") : t("Off. You won’t see theirs either")}
                trailing={
                  <Toggle
                    label={t("Read receipts")}
                    value={readReceipts}
                    disabled={preview !== null || !accountId}
                    onValueChange={(enabled) => {
                      setReadReceipts(enabled);
                      if (profile) {
                        const expected = profile.slice();
                        void saveReadReceipts(expected, enabled).catch(() => {
                          if (visibleAccountIdentity.current === accountProfileIdentity(expected)) setError(t("That choice couldn’t be saved. It applies until you restart."));
                        });
                      }
                    }}
                  />
                }
              />
            </RowGroup>
          </Section>
          {!preview ? <Section>
            <RowGroup>
              <Row icon="key" title={t("Fork bounties")} subtitle={t("Wallet custody and public transfers")} onPress={() => setShowBounty(true)} />
              <Row icon="key" title={t("Credits")} subtitle={t("Balance, purchases and wallet")} onPress={() => go("credits")} />
              <Row icon="clock" title={t("Queued postage")} subtitle={t("Review or recover original queued messages")} onPress={() => setShowPostage(true)} />
              <Row icon="chat" title={t("Inbox postage")} subtitle={t("Network credits for new senders")} onPress={() => setShowPostagePolicy(true)} />
            </RowGroup>
          </Section> : null}
          {!preview ? <Section title={t("Network")}>
            <RowGroup><Row icon="checks" title={t("Bonds and slashes")} subtitle={t("Public morse-main collateral")} onPress={() => setShowNetworkCounter(true)} /></RowGroup>
          </Section> : null}
          {anchorObservation && !preview ? (
            <Section title={t("Key log")}>
              <RowGroup>
                <Row
                  icon="checks"
                  title={describeAnchorObservation(anchorObservation.status).title}
                  subtitle={anchorObservation.status === "off" || anchorObservation.status === "pending"
                    ? t("Public checkpoint status") : t("Checked independently by this device")}
                  tone={describeAnchorObservation(anchorObservation.status).blocking ? "danger" : "muted"}
                  onPress={() => setShowAnchorDetails(true)}
                />
              </RowGroup>
            </Section>
          ) : null}
          <Section title={t("Appearance")}>
            <RowGroup>
              <Row
                icon={theme?.icon}
                title={t("Theme")}
                subtitle={theme?.label}
                trailing={
                  <Segmented label={t("Theme")} options={translated(appearanceOptions)} value={appearance} onSelect={setAppearance} />
                }
              />
              <Row
                icon="globe"
                title={t("Language")}
                subtitle={languageChoice === "system" ? t("Phone language · {name}", { name: languageLabel }) : languageLabel}
                onPress={() => setChoosingLanguage(true)}
              />
            </RowGroup>
          </Section>
          {updates}
          {isDevelopmentBuild() ? (
            <Section title={t("Development")}>
              <RowGroup>
                <Row
                  icon="chat"
                  title={t("Sample content")}
                  subtitle={t("Read and unread chats and groups. Nothing is saved or sent.")}
                  trailing={
                    <Toggle label={t("Sample content")} value={preview !== null} disabled={busy} onValueChange={toggleDevPreview} />
                  }
                />
                <Row
                  icon="refresh"
                  title={t("Replay onboarding")}
                  subtitle={t("The welcome and profile screens again. No account is created or linked.")}
                  onPress={busy ? undefined : replayOnboarding}
                />
                {isDesktop && onWindowsPreviewChange ? (
                  <Row
                    icon="device"
                    title={t("Windows UI")}
                    subtitle={t("Preview the Windows title bar and window controls.")}
                    trailing={
                      <Toggle
                        label={t("Windows UI")}
                        value={previewWindows}
                        disabled={changingWindowsUI}
                        onValueChange={async (enabled) => {
                          setChangingWindowsUI(true);
                          try { await onWindowsPreviewChange(enabled); }
                          catch { setError(t("Couldn’t change the window controls. Try again.")); }
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
                title={devices?.canManage === false ? t("Erase this device") : t("Delete account")}
                subtitle={devices?.canManage === false
                  ? t("Leaves your account and erases this device")
                  : t("Erases your username and messages everywhere")}
                onPress={preview || busy ? undefined : confirmDeleteAccount}
              />
            </RowGroup>
          </Section>
        </ScrollView>
      </Page>
    );
  }

  function renderDevices() {
    return (
      <Page header={<Header title={t("Linked devices")} onBack={() => go("settings")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <Text style={type.body}>{t("Only these devices can receive your messages. Remove any device you no longer trust.")}</Text>
          {devices?.changed ? (
            <Notice
              tone="warning"
              text={t("Your account changed while this device was away. Review these devices.")}
            />
          ) : null}
          {!devices?.canManage ? (
            <Notice text={t("Use your original device to link or remove other devices.")} />
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
                      ? t("This device")
                      : device.active
                        ? t("Linked device")
                        : t("Removed device")
                  }
                  subtitle={
                    device.current
                      ? t("The device you’re using now")
                      : device.expired
                        ? t("Gets no messages until it’s opened again")
                        : device.active
                          ? t("Receives your messages")
                          : t("No longer has access")
                  }
                  trailing={
                    devices.canManage && device.active && !device.current ? (
                      <Button
                        label={t("Remove")}
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
                label={t("Link another device")}
                icon="scan"
                onPress={() => openScanner("link-request")}
              />
            </Actions>
          ) : null}
          <Text style={type.caption}>{t("Removing a device is permanent. It would have to be linked again from scratch.")}</Text>
        </ScrollView>
      </Page>
    );
  }

  function renderLinkAuthorization(authorization: Uint8Array) {
    return (
      <Page
        header={
          <Header title={t("Approve the connection")} onBack={() => go("devices")} backLabel={t("Close")} />
        }
      >
        <ScrollView contentContainerStyle={layout.content}>
          <QrLayout
            intro={
              <View style={layout.stack}>
                <Text style={type.title}>{t("One last scan.")}</Text>
                <Text style={type.body}>{t("Use the new device to scan this code. Only continue if the codes match on both screens.")}</Text>
              </View>
            }
            qr={<QrCard value={payloadQrValue("link-authorization", authorization)} />}
            details={<CodeBlock label={t("Both screens should show")} value={linkSas} />}
          />
        </ScrollView>
      </Page>
    );
  }

  function renderGroupPackage(keyPackage: Uint8Array) {
    return (
      <Page header={
        <Header
          title={t("Join a group")}
          {...(isDesktop ? {} : backTo("groups"))}
          action={isDesktop ? (
            <IconButton
              name="close"
              label={t("Close join group")}
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
                <Text style={type.title}>{t("You’re invited.")}</Text>
                <Text style={type.body}>{t("Ask a group member to scan this code from their group details to add this device.")}</Text>
              </View>
            }
            qr={<QrCard value={payloadQrValue("group-key-package", keyPackage)} />}
            details={
              <Notice text={t("This invitation code is for this device only. Share a separate code for each linked device you want to add.")} />
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
        ItemSeparatorComponent={sidebar ? undefined : ListSeparator}
        ListHeaderComponent={incoming.length || asked.length ? (
          <View style={styles.listHeader}>
            {asked.length ? (
              <Section title={t("Asked to join")}>
                {asked.map((ask) => (
                  <Card key={ask.community}>
                    <Text style={type.headline}>{ask.name}</Text>
                    <Text style={type.body}>
                      {ask.state === "approved" ? t("@{username} let you in. Joining…", { username: ask.conversation.username })
                        : ask.state === "declined" ? t("@{username} didn’t let you in.", { username: ask.conversation.username })
                        : t("Waiting for @{username} to let you in.", { username: ask.conversation.username })}
                    </Text>
                  </Card>
                ))}
              </Section>
            ) : null}
            {incoming.length ? <Section title={t("Invitations")}>
              {incoming.map((invitation) => (
                <Card key={hex(invitation.reference)}>
                  <Text style={type.headline}>{groupName(invitation.groupId)}</Text>
                  <Text style={type.body}>
                    {invitation.state === 1
                      ? t("@{username} invited you. Accept to join on this device.", { username: invitation.username })
                      : t("Accepted. Joining when @{username} next connects.", { username: invitation.username })}
                  </Text>
                  {invitation.state === 1 ? (
                    <View style={layout.row}>
                      <Button label={t("Accept")} accessibilityLabel={t("Accept group invitation")} size={sidebar ? "sm" : "md"} onPress={() => answerGroupInvitation(invitation, true)} />
                      <Button label={t("Decline")} variant="ghost" size={sidebar ? "sm" : "md"} onPress={() => answerGroupInvitation(invitation, false)} />
                    </View>
                  ) : (
                    <Button label={t("Retry joining")} variant="ghost" size={sidebar ? "sm" : "md"} onPress={() => answerGroupInvitation(invitation, true)} />
                  )}
                </Card>
              ))}
            </Section> : null}
          </View>
        ) : undefined}
        ListEmptyComponent={sidebar ? <SidebarEmptyState title={t("No groups yet.")} /> : (
          <EmptyState
            icon="groups"
            title={t("No groups yet.")}
            body={t("Ask a member to invite @{ownUsername}, or open a community’s link. Invitations appear here.", { ownUsername })}
            action={
              // Stacked and centred, as the empty Chats tab sets its own.
              <>
                <Button label={t("Start a group")} icon="plus" onPress={createNewGroup} />
                <Button label={t("Join a community")} variant="ghost" onPress={() => openScanner("community")} />
              </>
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
            title={t("Groups")}
            actions={
              <>
                <IconButton
                  label={t("Join a community")}
                  variant="tonal"
                  name="link"
                  onPress={() => openScanner("community")}
                />
                <IconButton
                  label={t("Join with QR")}
                  variant="tonal"
                  name="qr"
                  onPress={showGroupKeyPackage}
                />
                <IconButton
                  name="plus"
                  label={t("Create group")}
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
    if (sameDay(timestamp, Date.now())) return t("Asked at {time}", { time: formatInboxTime(timestamp) });
    if (sameDay(timestamp, Date.now() - 86_400_000)) return t("Asked yesterday");
    return t("Asked {date}", { date: formatInboxTime(timestamp) });
  };

  // An admin answers someone who asked, through their link, to join.
  function renderReviewDialog(name: string) {
    const identity = reviewing ? senderIdentity(reviewing.conversation.peerAccountId) : null;
    const buttonSize = isDesktop ? "sm" : "md";
    return (
      <Dialog visible={Boolean(reviewing)} label={identity ? t("Review {name}", { name: identity.name }) : t("Review")} onClose={() => setReviewing(null)}>
        {reviewing && identity ? (
          <>
            <View style={styles.dialogHero}>
              <Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar["2xl"]} />
              <Text numberOfLines={1} style={type.title2}>{identity.name}</Text>
              <Text style={type.subhead}>{t("{asked} to join {name}", { asked: askedWhen(reviewing.request.timestamp), name })}</Text>
            </View>
            <View style={styles.dialogActions}>
              <Button label={t("Let them in")} size={buttonSize} disabled={preview !== null}
                onPress={() => approveAsk(reviewing.conversation, reviewing.request)} />
              <Button label={t("Decline")} variant="secondary" size={buttonSize} disabled={preview !== null}
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
      <Dialog visible={Boolean(accountId && identity)} label={identity ? t("Manage {name}", { name: identity.name }) : t("Manage")} onClose={() => setManaging(null)}>
        {accountId && identity ? (
          <>
            <View style={styles.dialogHero}>
              <Avatar name={identity.name} uri={identity.avatar} colorSeed={accountId} size={size.avatar["2xl"]} />
              <Text numberOfLines={1} style={type.title2}>{identity.name}</Text>
              <Text style={type.subhead}>{admin ? t("Admin") : t("Member")}</Text>
            </View>
            <View style={styles.dialogActions}>
              {admin ? (
                <>
                  <Button label={t("Make owner")} size={buttonSize} onPress={() => act(() => confirmHandover(accountId, identity.name))} />
                  <Button label={t("Remove as admin")} variant="secondary" size={buttonSize}
                    onPress={() => act(() => changeRoles({ admins: community.admins.filter((item) => item !== accountId) },
                      t("{name} is no longer an admin", { name: identity.name })))} />
                </>
              ) : (
                <>
                  <Button label={t("Make admin")} size={buttonSize} disabled={community.admins.length >= MAX_ADMINS}
                    onPress={() => act(() => changeRoles({ admins: [...community.admins, accountId] }, t("{name} is an admin now", { name: identity.name })))} />
                  <Button label={t("Remove from community")} variant="secondary" size={buttonSize}
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
    const members = (count: number) => t.plural("{count} member", "{count} members", count);
    const canInvite = preview === null && groupUsername.trim().length > 0;
    const pending = [...new Map(groupInvitations
      .filter((item) => entry.parts.includes(hex(item.groupId)) && (item.state === 0 || item.state === 3))
      .map((item) => [hex(item.accountId), item])).values()];
    const spread = community.parts.length > 1 ? t.plural("Spread across {count} group of up to 64 devices. ", "Spread across {count} groups of up to 64 devices. ", community.parts.length) : "";
    const communityLink = payloadQrValue("community", utf8(encodeCommunityLink({ community: communityId(community), admin: ownUsername || "_", name })));
    return (
      <Page header={<Header title={t("Community details")} onBack={() => go("group")} />}>
        {renderRoleDialog(community)}
        {renderReviewDialog(name)}
        <KeyboardAwareScrollView
          bottomOffset={formKeyboardOffset}
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
            subtitle={canManage && summary ? t("Community · {members}", { members: describeMembers(summary) }) : t("Community")}
            actions={canManage && avatar ? renderRemovePhoto(() => setPhoto(undefined)) : undefined}
          />
        {canManage ? (
          <Section title={t("About")}>
            <Card>
              <Field
                label={t("Description")}
                value={aboutDraft ?? community.about}
                onChangeText={setAboutDraft}
                placeholder={t("What this community is for")}
                multiline
                maxLength={500}
              />
              {aboutDraft !== null && aboutDraft.trim() !== community.about ? (
                <Actions>
                  <Button label={t("Save description")} onPress={() => saveCommunity({ ...community, about: aboutDraft }, t("Description saved"))} />
                </Actions>
              ) : null}
            </Card>
          </Section>
        ) : community.about ? (
          <Section title={t("About")}>
            <Card><Text style={type.body}>{community.about}</Text></Card>
          </Section>
        ) : null}
        {incomingAsks.length ? (
          <Section title={t("Asking to join")} footer={t("They opened your link. Letting someone in accepts their message request and invites them.")}>
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
                      <Button label={t("Review")} accessibilityLabel={t("Review {name}", { name: identity.name })} variant="secondary" size="sm"
                        onPress={() => setReviewing({ conversation, request })} />
                    }
                  />
                );
              })}
            </RowGroup>
          </Section>
        ) : null}
        {joinWaiting.length ? (
          <Section title={t("Join requests")} footer={t("Inviting sends that group’s usual encrypted invitation.")}>
            <RowGroup>
              {joinWaiting.map((request) => {
                const identity = senderIdentity(request.accountId);
                const group = community.groups.find((item) => item.id === request.groupId);
                return (
                  <Row
                    key={`${request.accountId}/${request.groupId}`}
                    leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={identity.accountId} size={size.avatar.md} />}
                    title={identity.name}
                    subtitle={group?.name ? t("Asked to join {group}", { group: group.name }) : t("Asked to join a group")}
                    trailing={
                      <Button
                        label={t("Invite")}
                        accessibilityLabel={group?.name ? t("Invite {name} to {group}", { name: identity.name, group: group.name }) : t("Invite {name} to the group", { name: identity.name })}
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
          title={t("Groups")}
          footer={canManage
            ? t("Members see these names and can ask to join. You invite them from here.")
            : t("Ask to join a group and the community’s owner or an admin can invite you.")}
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
                          label={t("Unlink")}
                          accessibilityLabel={t("Unlink {name}", { name: group.name })}
                          variant="secondary"
                          size="sm"
                          onPress={() => saveCommunity({ ...community, groups: community.groups.filter((item) => item.id !== group.id) }, t("{name} unlinked", { name: group.name }))}
                        />
                      ) : joined ? (
                        <Badge label={t("Joined")} />
                      ) : invitation?.state === 1 ? (
                        <Button label={t("Join")} accessibilityLabel={t("Join {name}", { name: group.name })} size="sm" onPress={() => answerGroupInvitation(invitation, true)} />
                      ) : invitation ? (
                        <Badge label={t("Joining")} tone="accent" />
                      ) : requested ? (
                        <Badge label={t("Requested")} tone="muted" />
                      ) : (
                        <Button
                          label={t("Ask to join")}
                          accessibilityLabel={t("Ask to join {name}", { name: group.name })}
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
              <Text style={type.body}>{canManage ? t("Link groups you’re in so members can find them.") : t("No groups yet.")}</Text>
            </Card>
          )}
        </Section>
        {canManage && linkable.length ? (
          <Section title={t("Link a group")}>
            <RowGroup>
              {linkable.map((item) => (
                <Row
                  key={hex(item.groupId)}
                  leading={<Avatar name={groupName(item.groupId)} uri={groupAvatar(item.groupId)} colorSeed={hex(item.groupId)} size={size.avatar.md} group />}
                  title={groupName(item.groupId)}
                  subtitle={members(item.memberCount)}
                  trailing={
                    <Button
                      label={t("Link")}
                      accessibilityLabel={t("Link {name}", { name: groupName(item.groupId) })}
                      variant="secondary"
                      size="sm"
                      onPress={() => saveCommunity({ ...community, groups: [...community.groups, { id: hex(item.groupId), name: groupName(item.groupId) }] },
                        t("{name} linked", { name: groupName(item.groupId) }))}
                    />
                  }
                />
              ))}
            </RowGroup>
          </Section>
        ) : null}
          {canManage && ownUsername ? (
            <Section
              title={t("Invite link")}
              footer={t("Anyone with this link or code can ask you to let them in. Their request comes to you as a message.")}
            >
              <QrCard value={communityLink} caption={t("Scan with Morse to ask to join")} />
              <Actions>
                <Button label={t("Copy link")} icon="copy" variant="secondary" onPress={() => copyCommunityLink(communityLink)} />
              </Actions>
            </Section>
          ) : null}
          {canManage ? (
            <Section
              title={t("Invite members")}
              footer={t("They’ll receive an encrypted invitation and choose whether to join. Or scan the code from their Groups tab to add them right away.")}
            >
              <Card>
                <View style={isDesktop && styles.inviteRow}>
                  <View style={isDesktop && [layout.flex, { minWidth: 180 }]}>
                    <Field
                      label={t("Exact username")}
                      value={groupUsername}
                      onChangeText={setGroupUsername}
                      placeholder="their_name"
                      prefix="@"
                      autoFocus={focusInvite}
                    />
                  </View>
                  <Actions style={isDesktop ? { maxWidth: "100%" } : styles.inviteActions}>
                    <Button label={t("Send invitation")} disabled={!canInvite} onPress={inviteByUsername} />
                    <Button
                      label={isDesktop ? t("Enter their code") : t("Scan their code")}
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
            title={t("Admins")}
            footer={isOwner
              ? t("Admins post announcements, answer requests, invite and remove members, and edit the community. Only you change who runs it.")
              : t("They post the announcements and invite people to the community’s groups.")}
          >
            <RowGroup>
              {staff.map((accountId) => {
                const identity = senderIdentity(accountId, accountId === ownId);
                return (
                  <Row
                    key={accountId}
                    leading={<Avatar name={identity.name} uri={identity.avatar} colorSeed={accountId} size={size.avatar.md} />}
                    title={identity.name}
                    subtitle={accountId === community.owner ? t("Owner") : t("Admin")}
                    trailing={accountId === ownId ? (
                      <Badge label={t("You")} />
                    ) : isOwner ? (
                      <Button label={t("Manage")} accessibilityLabel={t("Manage {name}", { name: identity.name })} variant="secondary" size="sm"
                        onPress={() => setManaging(accountId)} />
                    ) : null}
                  />
                );
              })}
            </RowGroup>
          </Section>
          {canManage ? (
            <Section title={t("Members")} footer={t("{spread}Members see only who runs the community.", { spread })}>
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
                          item.devices > 1 ? t.plural("{count} device", "{count} devices", item.devices) : undefined].filter(Boolean).join(" · ") || undefined}
                        trailing={isOwner ? (
                          <Button label={t("Manage")} accessibilityLabel={t("Manage {name}", { name: identity.name })} variant="secondary" size="sm"
                            onPress={() => setManaging(accountId)} />
                        ) : (
                          <Button
                            label={t("Remove")}
                            accessibilityLabel={t("Remove {name}", { name: identity.name })}
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
                  <Text style={type.body}>{t("No one else yet. Invite members above.")}</Text>
                </Card>
              )}
            </Section>
          ) : null}
          {canManage && pending.length > 0 ? (
            <Section title={t("Invited")} footer={t("They join once they accept.")}>
              <RowGroup>
                {pending.map((item) => (
                  <Row
                    key={hex(item.reference)}
                    leading={<Avatar name={`@${item.username}`} size={size.avatar.md} />}
                    title={`@${item.username}`}
                    subtitle={item.state === 3 ? t("Finishing their invitation…") : t("Waiting for them to accept")}
                    trailing={<Badge label={item.state === 3 ? t("Joining") : t("Invited")} tone={item.state === 3 ? "accent" : "muted"} />}
                  />
                ))}
              </RowGroup>
            </Section>
          ) : null}
          <Section footer={isOwner ? t("Make an admin the owner before you leave.") : undefined}>
            <RowGroup>
              <Row
                icon="close"
                tone="danger"
                emphasis="danger"
                title={t("Leave community")}
                onPress={isOwner || preview ? undefined : () => confirmLeave(entry)}
              />
            </RowGroup>
          </Section>
        </KeyboardAwareScrollView>
      </Page>
    );
  }

  // The group as the settings screen shows an account: its picture, tappable
  // by the creator to change it, over its name and who is in it; then the
  // ways to grow it, its people device by device, and the state they share.
  function renderGroupInfo(groupId: Uint8Array) {
    const timerValue = groupTimer?.groupId === hex(groupId) && groupTimer.epoch === cacheEpoch ? groupTimer.seconds : undefined;
    const name = groupName(groupId);
    const avatar = groupAvatar(groupId);
    const summary = groupDetails ? summarizeMembers(groupDetails.members) : null;
    const setGroupPhoto = (value: string | undefined) => updateAvatar(`group/${hex(groupId)}`, name, value);
    const canInvite = preview === null && groupUsername.trim().length > 0;
    const pending = [...new Map(groupInvitations
      .filter((item) => hex(item.groupId) === hex(groupId) && (item.state === 0 || item.state === 3))
      .map((item) => [hex(item.accountId), item])).values()];
    return (
      <Page header={<Header title={t("Group details")} onBack={() => go("group")} />}>
        <KeyboardAwareScrollView
          bottomOffset={formKeyboardOffset}
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
            subtitle={summary ? describeMembers(summary) : t("Loading members…")}
            actions={isGroupCreator && avatar ? renderRemovePhoto(() => setGroupPhoto(undefined)) : undefined}
          />
          <Section
            title={t("Invite someone")}
            footer={t("They’ll receive an encrypted invitation and choose whether to join. Or scan the code from their Groups tab to add them right away.")}
          >
            <Card>
              {/* Desktop keeps the field and its actions on one line. */}
              <View style={isDesktop && styles.inviteRow}>
                <View style={isDesktop && [layout.flex, { minWidth: 180 }]}>
                  <Field
                    label={t("Exact username")}
                    value={groupUsername}
                    onChangeText={setGroupUsername}
                    placeholder="their_name"
                    prefix="@"
                    autoFocus={focusInvite}
                  />
                </View>
                <Actions style={isDesktop ? { maxWidth: "100%" } : styles.inviteActions}>
                  <Button label={t("Send group invitation")} disabled={!canInvite} onPress={inviteByUsername} />
                  <Button
                    label={isDesktop ? t("Enter their code") : t("Scan their code")}
                    icon="scan"
                    variant="ghost"
                    disabled={!canInvite}
                    onPress={scanGroupKeyPackage}
                  />
                </Actions>
              </View>
            </Card>
          </Section>
          <Section title={t("Disappearing messages")} footer={t("Applies to messages this device sends to this group. Other members choose their own timers.")}>
            <RowGroup>
              <Row icon="timer" title={t("Timer")} subtitle={timerValue !== undefined ? translated(disappearingOptions).find((option) => option.value === timerValue)?.label : t("Loading…")}
                trailing={<Segmented label={t("Disappear")} options={translated(disappearingOptions)}
                  value={timerValue ?? 0}
                  onSelect={(seconds) => { if (preview || busy || timerValue === undefined) return; void perform(t("Saving the timer…"), async () => {
                    const accepted = await groupMessageTimer(databasePath, groupId, seconds);
                    if (historyCacheEpoch.current.current(cacheEpoch)) setGroupTimer({ groupId: hex(groupId), seconds: accepted, epoch: cacheEpoch });
                  }); }} />}
              />
            </RowGroup>
          </Section>
          <Section title={t("Members")}>
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
                      subtitle={[note, person.devices > 1 ? t.plural("{count} device", "{count} devices", person.devices) : undefined].filter(Boolean).join(" · ") || undefined}
                      trailing={
                        person.local ? (
                          <Badge label={t("You")} />
                        ) : identity.creator ? null : (
                          <Button
                            label={t("Remove")}
                            accessibilityLabel={t("Remove {name}", { name: identity.name })}
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
            <Section title={t("Invited")} footer={t("They join once they accept.")}>
              <RowGroup>
                {pending.map((item) => (
                  <Row
                    key={hex(item.reference)}
                    leading={<Avatar name={`@${item.username}`} size={size.avatar.md} />}
                    title={`@${item.username}`}
                    subtitle={item.state === 3 ? t("Finishing their invitation…") : t("Waiting for them to accept")}
                    trailing={<Badge label={item.state === 3 ? t("Joining") : t("Invited")} tone={item.state === 3 ? "accent" : "muted"} />}
                  />
                ))}
              </RowGroup>
            </Section>
          ) : null}
        </KeyboardAwareScrollView>
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
      <Dialog visible={membersOpen} label={t("Group members")} onClose={() => setMembersOpen(false)}>
        <View style={styles.dialogHero}>
          <Avatar name={groupName(groupId)} uri={groupAvatar(groupId)} colorSeed={hex(groupId)} size={size.avatar["2xl"]} group />
          <Text numberOfLines={1} style={type.title2}>
            {groupName(groupId)}
          </Text>
          <Text style={type.subhead}>{summary ? describeMembers(summary) : t("Loading members…")}</Text>
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
                      <Badge label={t("You")} />
                    ) : reachable ? (
                      <IconButton
                        name="chat"
                        label={t("Message {name}", { name: identity.name })}
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
          <Button label={t("Invite someone")} icon="plus" variant="secondary" size={buttonSize} onPress={inviteSomeone} />
          <Button label={t("Group details")} variant="ghost" size={buttonSize} onPress={() => go("group-info")} />
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
      return { name: own ? t("You") : identity.name, accountId: identity.accountId, text: attachmentPreviewText(message) };
    };
    const answering = replyTarget && "senderAccountId" in replyTarget ? quoteOf(replyTarget) : undefined;
    return (
      <Page
        keyboard
        header={
          <ChatHeader
            name={groupName(groupId)}
            avatar={groupAvatar(groupId)}
            colorSeed={hex(groupId)}
            group
            {...backTo("groups", t("Back to groups"))}
            onAvatarPress={() => selectedCommunity ? go("group-info") : setMembersOpen(true)}
            avatarLabel={selectedCommunity ? t("Community details") : t("Group members")}
            onInfo={() => go("group-info")}
            infoLabel={selectedCommunity ? t("Community details") : t("Group details")}
          />
        }
      >
        {renderGroupMembers(groupId)}
        {waiting ? (
          <View style={[styles.banners, isDesktop && layout.threadContent]}>
            <Card tone="accent">
              <Text style={type.body}>
                {t.plural("Someone is waiting for you to let them in.", "{count} people are waiting for you to let them in.", waiting)}
              </Text>
              <Actions>
                <Button label={t("Review requests")} size="sm" onPress={() => go("group-info")} />
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
                  title={t("No announcements yet.")}
                  body={canManage ? t("Only you and the other admins post here. Members read, react and find the community’s groups in its details.") : t("Announcements from the people who run the community appear here. Find its groups in its details.")}
                />
              ) : (
                <EmptyState
                  icon="lock"
                  title={t("Nothing here yet.")}
                  body={t("Add people from group details to begin.")}
                />
              )}
            </View>
          }
          renderItem={({ item }) =>
            item.kind === "day" ? (
              <DayDivider label={item.label} />
            ) : (
              <MessageBubble
                body={item.message.body}
                disappearing={!!item.message.disappearingSeconds}
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
                attachments={item.message.attachments?.map((attachment) => bubbleAttachment(scope, attachment, true))}
                reactions={item.message.reactions}
                reactionSender={accountId ?? ""}
                reactor={(sender) => senderIdentity(sender)}
                onReact={item.message.messageId ? (emoji) => reactToMessage(item.message, emoji) : undefined}
                reactionsDisabled={busy || (selectedGroup?.memberCount ?? 0) < 2}
                quote={item.message.reply && (item.message.reply.message
                  ? { ...quoteOf(item.message.reply.message), onPress: () => showOriginal(groupRows, item.message.reply!.target) }
                  : { text: t("Original message unavailable") })}
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
          disabled={busy || preview !== null || readOnly}
          placeholder={preview ? t("Sample preview · read-only") : readOnly ? t("Only admins post here")
            : selectedCommunity ? t("Announce something") : t("Message · @mention someone")}
          sendDisabled={(selectedGroup?.memberCount ?? 0) < 2}
          onHeightChange={setComposerHeight}
          attachments={composerAttachments(scope)}
          onAttach={() => attachFile(scope)}
          onSavedUploads={() => setSavedUploadsScope(scope)}
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
    const hasSafetyCode = /^[0-9a-f]{64}$/.test(conversation.safetyNumber);
    return (
      <Page header={<Header title={t("Conversation details")} onBack={() => go("chat")} />}>
        <ScrollView contentContainerStyle={layout.content}>
          <Hero
            name={contactName(conversation)}
            avatar={presentationOf(`user/${hex(conversation.peerAccountId)}`)?.avatar}
            colorSeed={hex(conversation.peerAccountId)}
            title={contactName(conversation)}
            subtitle={`@${conversation.username}`}
            badge={
              conversation.blocked ? (
                <Badge label={t("Blocked")} tone="danger" icon="block" />
              ) : conversation.verified ? (
                <Badge label={t("Safety number verified")} tone="success" icon="shield" />
              ) : null
            }
          />
          <Section title={t("Personalization")}>
            <RowGroup>
              <Row
                icon="person"
                title={t("Private nickname")}
                subtitle={presentationOf(`nickname/${hex(conversation.peerAccountId)}`)?.name ?? t("Only you see this, on this device.")}
                onPress={preview ? undefined : () => editName(`nickname/${hex(conversation.peerAccountId)}`,
                  presentationOf(`nickname/${hex(conversation.peerAccountId)}`)?.name ?? "")}
              />
            </RowGroup>
          </Section>
          {/* The number is the exhibit: its state above it as a row, the way
              to act on it below, and the words about it under the card. */}
          <Section title={t("Security")} footer={safety.note}>
            <RowGroup>
              <Row icon="shield" tone={safety.tone} title={t("Safety number")} subtitle={safety.status} />
              {conversation.safetyNumber ? <SafetyNumber value={conversation.safetyNumber} tone={safety.tone} /> : null}
              {hasSafetyCode ? (
                <Row icon="scan" title={t("Scan safety code")} onPress={() => openScanner("safety")} />
              ) : null}
              {safety.verifiable && hasSafetyCode ? (
                <Row
                  icon="check"
                  tone="success"
                  title={t("Mark as verified")}
                  trailing={null}
                  onPress={() => verifySafetyNumber(conversation, conversation.safetyNumber, false)}
                />
              ) : null}
            </RowGroup>
            {hasSafetyCode ? <QrCard value={safetyQrValue(conversation.safetyNumber)} caption={t("Compare in person or through a channel you already trust. This code contains only your shared safety number.")} /> : null}
          </Section>
          <Section
            title={t("Disappearing messages")}
          >
            <RowGroup>
              <Row
                icon="timer"
                title={t("Timer")}
                subtitle={translated(disappearingOptions).find((option) => option.value === conversation.disappearingSeconds)?.label}
                trailing={
                  <Segmented
                    label={t("Disappear")}
                    options={translated(disappearingOptions)}
                    value={conversation.disappearingSeconds}
                    onSelect={(seconds) => updatePolicy(5, seconds)}
                  />
                }
              />
            </RowGroup>
          </Section>
          <Section title={t("Privacy")}>
            <RowGroup>
              <Row
                icon="block"
                tone={conversation.blocked ? "muted" : "danger"}
                emphasis={conversation.blocked ? undefined : "danger"}
                title={conversation.blocked ? t("Unblock contact") : t("Block contact")}
                subtitle={
                  conversation.blocked
                    ? t("You’ll receive their messages again.")
                    : t("They won’t be told, and their messages stop arriving.")
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
    const canReply = !conversation.blocked && !conversation.requestPending;
    // Each side of a chat is named in its own colour, as group members are.
    const quoteOf = (message: Omit<HistoryMessage, "reply">) => ({
      name: message.direction === "sent" ? t("You") : contactName(conversation),
      accountId: message.direction === "sent" ? ownId : hex(conversation.peerAccountId),
      text: attachmentPreviewText(message),
    });
    const answering = replyTarget && !("senderAccountId" in replyTarget) ? quoteOf(replyTarget) : undefined;
    return (
      <Page
        keyboard
        header={
          <ChatHeader
            name={contactName(conversation)}
            avatar={presentationOf(`user/${hex(conversation.peerAccountId)}`)?.avatar}
            colorSeed={hex(conversation.peerAccountId)}
            mark={conversationMark(conversation)}
            {...backTo("home", t("Back to chats"))}
            onInfo={() => go("chat-info")}
            infoLabel={t("Conversation details")}
          />
        }
      >
        {banners ? (
          <View style={[styles.banners, isDesktop && layout.threadContent]}>
            {conversation.requestPending ? (
              <Card tone="accent">
                <Text style={type.headline}>{t("Message request")}</Text>
                <Text style={type.body}>
                  @{conversation.username} wants to start a conversation. Accept to
                  reply, or block to never hear from them.
                </Text>
                {isDesktop ? (
                  <Actions>
                    <Button label={t("Accept request")} onPress={() => updatePolicy(1)} />
                    <Button label={t("Block")} variant="secondary" onPress={() => updatePolicy(2)} />
                  </Actions>
                ) : (
                  <View style={layout.row}>
                    <View style={layout.flex}>
                      <Button label={t("Accept request")} onPress={() => updatePolicy(1)} />
                    </View>
                    <Button
                      label={t("Block")}
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
                text={t("@{username}’s safety number changed. Compare it again before sending.", { username: conversation.username })}
              />
            ) : null}
            {conversation.blocked ? (
              <Notice text={t("This contact is blocked. You can unblock them in conversation details.")} />
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
                title={t("Say hello.")}
                body={t("Your messages are encrypted from the first word.")}
              />
            </View>
          }
          renderItem={({ item }) =>
            item.kind === "day" ? (
              <DayDivider label={item.label} />
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
                  : { text: t("Original message unavailable") })}
                onReply={canReply ? () => setReplying({ scope, target: hex(item.message.messageId) }) : undefined}
                highlighted={flashKey === item.key}
                tail={item.tail}
                spaced={item.spaced}
                enter={isFreshMessage(item.key)}
                attachments={item.message.attachments?.map((attachment) => bubbleAttachment(
                  scope, attachment,
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
              ? t("Sample preview · read-only")
              : conversation.blocked
              ? t("Contact blocked")
              : conversation.requestPending
                ? t("Accept the request to reply")
                : t("Message")
          }
          onHeightChange={setComposerHeight}
          attachments={composerAttachments(scope)}
          onAttach={() => attachFile(scope)}
          onSavedUploads={() => setSavedUploadsScope(scope)}
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
            ? undefined
            : ({ leadingItem }: { leadingItem: HomeItem }) =>
                leadingItem.kind === "chat" ? <ListSeparator /> : null
        }
        ListEmptyComponent={sidebar ? <SidebarEmptyState title={t("No chats yet.")} /> : (
          <EmptyState
            icon="chat"
            title={t("No conversations yet.")}
            body={firstChatHint}
            action={
              <>
                <Button
                  label={t("New message")}
                  icon="compose"
                  onPress={() => go("new-chat")}
                />
                {Platform.OS === "web" ? null : (
                  <Button
                    label={t("Scan a contact code")}
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
  const firstChatHint = t("Message someone by their exact username. People can find you as\u00A0@{ownUsername}.", { ownUsername });

  function renderHome() {
    return (
      <Page
        header={
          <LargeHeader
            title={t("Chats")}
            actions={
              <>
                <IconButton
                  name="compose"
                  label={t("New conversation")}
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
        title={t("No conversations yet.")}
        body={firstChatHint}
        action={
          <View style={layout.row}>
            <Button label={t("New message")} icon="compose" onPress={() => go("new-chat")} />
            <Button label={t("My QR code")} variant="ghost" onPress={() => go("account")} />
          </View>
        }
      />
    );
    if (list === "groups" && groups.length === 0 && groupInvitations.length === 0) return (
      <EmptyState
        icon="groups"
        title={t("No groups yet.")}
        body={t("Start one, or ask a member to invite\u00A0@{ownUsername}.", { ownUsername })}
        action={
          <View style={layout.row}>
            <Button label={t("Create group")} icon="plus" onPress={createNewGroup} />
            <Button label={t("Join a community")} variant="ghost" onPress={() => openScanner("community")} />
            <Button label={t("Join with a code")} variant="ghost" onPress={showGroupKeyPackage} />
          </View>
        }
      />
    );
    return list === "chats" ? (
      <EmptyState
        icon="chat"
        title={t("Your messages")}
        body={t("Choose a conversation from the sidebar.")}
        action={
          <Button label={t("New message")} icon="compose" onPress={() => go("new-chat")} />
        }
      />
    ) : (
      <EmptyState
        icon="groups"
        title={t("Your groups")}
        body={t("Choose a group from the sidebar.")}
        action={
          <View style={layout.row}>
            <Button label={t("Create group")} icon="plus" onPress={createNewGroup} />
            <Button label={t("Join a community")} variant="ghost" onPress={() => openScanner("community")} />
            <Button label={t("Join with a code")} variant="ghost" onPress={showGroupKeyPackage} />
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
                { key: "chats", title: t("Chats"), icon: "chat", badge: chatBadgeCount },
                { key: "groups", title: t("Groups"), icon: "groups", badge: groupBadgeCount },
              ]}
              current={sidebarList}
              onSelect={(key) => go(key === "chats" ? "home" : "groups")}
            />
          }
          actions={
            chats ? (
              <IconButton
                name="compose"
                label={t("New conversation")}
                variant="tonal"
                size={chrome.sidebarControl}
                onPress={() => go("new-chat")}
              />
            ) : (
              <>
                {/* The strip fits two actions; a group code is offered in the pane beside it. */}
                <IconButton
                  name="link"
                  label={t("Join a community")}
                  variant="tonal"
                  size={chrome.sidebarControl}
                  onPress={() => openScanner("community")}
                />
                <IconButton name="plus" label={t("Create group")} variant="tonal" size={chrome.sidebarControl} onPress={createNewGroup} />
              </>
            )
          }
        />
        <View pointerEvents="none" style={styles.sidebarEdge} />
      </ResizableSidebar>
    );
  }

  function renderScreen() {
    if (profileLoadProblem) return <Page header={<Header title={t("Finish signup")} />}><ScrollView contentContainerStyle={layout.content}>
      <Notice tone="error" text={t("Your saved signup could not be loaded. Retry before continuing.")} />
      <Button label={t("Retry")} onPress={() => { setProfileLoadProblem(false); setInitialLoading(true); setProfileLoadAttempt(value => value + 1); }} />
    </ScrollView></Page>;
    if (draftPending && profile && screen !== "credits") return <CreditSignupScreen services={services} database={databasePath} profile={profile} mode={signupDraft as 1 | 2}
      onProfile={setProfile} onBuyCredits={() => go("credits")} onComplete={finishPaidSignup} onFree={finishFreeDraft} />;
    if (onboardingActive)
      return onboardingStep === "profile" ? renderProfileSetup() : renderWelcome();
    if (screen === "link-device" && linkRequest) return renderLinkDevice(linkRequest);
    if (screen === "scanner") return renderScanner();
    if (screen === "new-chat") return renderNewChat();
    if (screen === "account" && profile) return renderAccount(profile);
    if (screen === "settings") return renderSettings();
    if (screen === 'backup-export' && profile && services.backups.kind === 'available') return <BackupExportScreen
      key={accountProfileIdentity(profile)} capability={services.backups} action={{ databasePath, expectedProfile: profile }} pendingLabels={pendingBackupExportLabels(t, locale)}
      choices={[
        ...conversations.map(conversation => ({ scope: { kind: 'direct' as const, id: conversation.conversationId }, label: contactName(conversation) })),
        ...groups.map(group => ({ scope: { kind: 'group' as const, id: group.groupId }, label: groupName(group.groupId) })),
      ]} onBack={() => go('settings')} />;
    if (screen === 'backups' && profile && services.backups.kind === 'available') return <Page header={<Header title={t('Backups')} onBack={() => go('settings')} />}>
      <BackupArchiveScreen key={accountProfileIdentity(profile)} scope={services.backups.scope} services={services.backups.operations}
        action={{ databasePath, expectedProfile: profile }} chooseBackupSource={services.backups.files.chooseBackupSource}
        discardBackupSource={services.backups.files.discardBackupSource} saveAttachmentFile={saveAttachmentFile} labels={backupArchiveLabels(t)} locale={locale} onClose={() => go('settings')} />
    </Page>;
    if (screen === "credits") return <CreditsScreen services={services} database={databasePath} onBack={() => go(draftPending ? "home" : "settings")} />;
    if (screen === "devices") return renderDevices();
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
    ? draftPending || onboardingStep === "profile"
      ? "onboarding-profile"
      : "onboarding"
    : screen;
  // Screens with a composer make room for the keyboard themselves (see Page);
  // every other screen scrolls its form instead.
  const pane = (
    <View
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
    </View>
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
      lift={mainScreen && !split ? 0 : composerHeight}
    />
  );
  const keyLogWarning = !profile || preview ? null
    : forkEvidence
      ? { text: t("Your device found conflicting signed key logs. New chats and key changes are paused. Existing chats can continue."), details: () => setShowForkDetails(true) }
      : anchorObservation && describeAnchorObservation(anchorObservation.status).blocking
        ? { text: t("{problem}. New chats and key changes are paused. Existing chats can continue.", { problem: describeAnchorObservation(anchorObservation.status).title }), details: () => setShowAnchorDetails(true) }
        : null;
  const main = (
    <View style={layout.flex} onLayout={({ nativeEvent: { layout: { x, y, height } } }) => setMainFrame({ x, y, height })}>
      {keyLogWarning ? (
        // The warning takes the status bar's place at the top. The screen's
        // header still covers a status bar's height of its own, which rests
        // on the warning's foot, kept empty for it.
        <View style={[layout.contentTight, styles.keyLogBanner, !isDesktop && styles.keyLogBannerPhone]}>
          <Notice tone="error" text={keyLogWarning.text} />
          <Button label={t("Details")} variant="ghost" onPress={keyLogWarning.details} />
        </View>
      ) : null}
      {profile && !preview && postageTriggers.length > 0 ? <View style={layout.contentTight}>
        <Button label={t("Review queued postage")} variant="secondary" onPress={() => setShowPostage(true)} />
      </View> : null}
      <View style={[layout.flex, keyLogWarning && !isDesktop && { marginTop: -chrome.status }]}>
        {pane}
      </View>
      {statusPill}
    </View>
  );
  return (
    <>
      {ready ? <>
      <StatusBar style={statusBar} />
      <SafeAreaView
        // A phone's screens run on under the status bar, beneath their
        // headers' fade; the desktop window has no such strip.
        edges={[
          ...(isDesktop ? ["top" as const] : []),
          "left",
          "right",
          ...(mainScreen ? [] : ["bottom" as const]),
        ]}
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
              tabs={tabs.map((tab) => ({ ...tab, title: t(tab.title), badge: tab.key === "home" ? chatBadgeCount : tab.key === "groups" ? groupBadgeCount : 0 }))}
              current={screen as (typeof tabs)[number]["key"]}
              onSelect={go}
            />
          ) : null}
        </WallpaperFrame.Provider>
      </SafeAreaView>
      {renderLanguageDialog()}
      <Dialog visible={showBounty} label={t("Fork bounties")} onClose={() => setShowBounty(false)}>
        <ScrollView contentContainerStyle={layout.content}>
          <Text style={type.title2}>{t("Fork bounties")}</Text>
          {showBounty ? <BountyPanel services={services} database={services.databasePath} /> : null}
        </ScrollView>
      </Dialog>
      <Dialog visible={showPostage} label={t("Queued postage")} onClose={() => setShowPostage(false)}>
        <ScrollView contentContainerStyle={layout.content}>
          <Text style={type.title2}>{t("Queued postage")}</Text>
          {showPostage ? <PostagePanel services={services} database={databasePath} triggers={postageTriggers} onSettled={postageSettled} /> : null}
        </ScrollView>
      </Dialog>
      <Dialog visible={showPostagePolicy} label={t("Inbox postage")} onClose={() => setShowPostagePolicy(false)}>
        <ScrollView contentContainerStyle={layout.content}>
          <Text style={type.title2}>{t("Inbox postage")}</Text>
          {showPostagePolicy && profile ? <PostagePolicy services={services} key={accountProfileIdentity(profile)} database={databasePath} accountId={parseProfileSummary(profile).accountId} publicProfile={profile} /> : null}
        </ScrollView>
      </Dialog>
      {nameEditor ? (
        <Dialog visible label={nameEditorTitle} onClose={() => { if (!busy) setNameEditor(null); }}>
          <ScrollView contentContainerStyle={styles.nameEditor} keyboardShouldPersistTaps="handled">
            <Text accessibilityRole="header" style={[type.title2, { paddingRight: control.sm }]}>{nameEditorTitle}</Text>
            <Field
              label={nameEditorTitle}
              value={nameEditor.value}
              onChangeText={(value) => setNameEditor({ ...nameEditor, value })}
              placeholder={editingNickname ? t("What you call them") : ownUsername}
              maxLength={96}
              autoFocus
              hint={editingNickname
                ? t("Only you see this, on this device. Leave blank to use their shared name.")
                : t("Shared with your next message. Leave blank to use your username.")}
            />
            {nameError ? <Notice text={nameError} tone="error" /> : null}
            <Actions>
              <Button label={t("Save")} onPress={saveName} disabled={busy || preview !== null} />
              <Button label={t("Cancel")} variant="ghost" disabled={busy} onPress={() => setNameEditor(null)} />
            </Actions>
          </ScrollView>
        </Dialog>
      ) : null}
      <Dialog visible={showAnchorDetails} label={t("Public checkpoint")} onClose={() => setShowAnchorDetails(false)}>
        {anchorObservation ? (
          <ScrollView contentContainerStyle={styles.nameEditor}>
            <Text accessibilityRole="header" style={type.title2}>{describeAnchorObservation(anchorObservation.status).title}</Text>
            <Text style={type.body}>{describeAnchorObservation(anchorObservation.status).detail}</Text>
            {showAnchorDetails ? <AnchorCheckpointTime blockTime={anchorObservation.blockTime} /> : null}
            {anchorObservation.contextSlot !== "0" ? (
              <Text selectable style={type.caption}>Finalized slot {anchorObservation.contextSlot}{"\n"}Checkpoint slot {anchorObservation.postedSlot}</Text>
            ) : null}
            <Text style={type.footnote}>{t("Check results stay on this device. Proof requests do not include your contacts.")}</Text>
          </ScrollView>
        ) : null}
      </Dialog>
      <Dialog visible={showNetworkCounter} label={t("Network")} onClose={() => setShowNetworkCounter(false)}>
        {showNetworkCounter ? <NetworkCounter services={services} database={databasePath} /> : null}
      </Dialog>
      <Dialog visible={showForkDetails} label={t("Key log evidence")} onClose={() => setShowForkDetails(false)}>
        <ScrollView contentContainerStyle={styles.nameEditor}>
          <Text accessibilityRole="header" style={type.title2}>{t("Conflicting signed checkpoints")}</Text>
          <Text style={type.body}>{t("Your device verified conflicting signed checkpoints and kept the proof on this device.")}</Text>
          <Text style={type.body}>{filingDescription.detail}</Text>
          {filingError ? <Text style={type.body}>{t("Filing status could not be loaded. The evidence is still retained; your device will retry.")}</Text> : null}
          {filingDescription.acknowledgments ? <Text style={type.footnote}>{filingDescription.acknowledgments}</Text> : null}
          {(filingDescription.payment || filingObservation?.status === "prepared") && filingObservation ? (
            <Text selectable style={type.caption}>{filingObservation.status === "prepared" ? "Prepared; payment has not been confirmed." : `Paid: ${filingDescription.payment}`}{"\n"}{filingObservation.viewVersion === "2" ? "Actual finder: " : "Finder: "}{filingObservation.paidFinder}
              {filingObservation.viewVersion === "2" ? <>{"\n"}Requested finder: {filingObservation.expectedFinder}{"\n"}USDC mint: {filingObservation.mint}{"\n"}MORSE mint: {filingObservation.morseMint}</> : <>{"\n"}Mint: {filingObservation.mint}</>}{"\n"}Finalized slot: {filingObservation.contextSlot}</Text>
          ) : null}
          {filingObservation?.proofHash ? <Text selectable style={type.caption}>Proof: {filingObservation.proofHash}</Text> : null}
          <Button label={t("Save evidence file")} onPress={() => {
            void saveAttachmentFile("morse-fork.frk", "application/octet-stream", fromHex(forkEvidence))
              .then(saved => { if (saved) setStatus(t("Evidence file saved")); })
              .catch(caught => setError(friendlyError(caught)));
          }} />
          <Button label={t("Copy evidence")} onPress={() => { void services.copyProtectedText(forkEvidence).then(() => setStatus(t("Evidence copied as FRK hexadecimal")), caught => setError(friendlyError(caught))); }} />
          <Text selectable style={type.caption}>{forkEvidence}</Text>
        </ScrollView>
      </Dialog>
      <Dialog visible={savedUploadsScope !== null} label={t("Saved large uploads")} onClose={() => setSavedUploadsScope(null)}>
        <ScrollView contentContainerStyle={layout.content}>
          <Text style={type.title2}>{t("Saved large uploads")}</Text>
          {savedUploadsScope !== null ? <PaidUploadList services={services} database={databasePath} onSelect={row => {
            const scope = savedUploadsScope;
            if (!scope) return;
            const limit = attachmentSelectionLimit([row.size], stagedFor(scope).length);
            if (limit) { setError(limit); return; }
            if (stagedFor(scope).some(entry => entry.upload.nonce && hex(entry.upload.nonce) === hex(row.nonce))) { setSavedUploadsScope(null); return; }
            updateStaged([...stagedRef.current, { id: `staged-${stagedSerial.current++}`, scope, upload: savedAttachmentUpload(row) }]);
            setSavedUploadsScope(null);
          }} /> : null}
        </ScrollView>
      </Dialog>
      <Modal visible={pendingConfirm !== null} transparent animationType="fade" onRequestClose={() => { pendingConfirm?.cancel?.(); setPendingConfirm(null); }}>
        <View style={styles.confirmOverlay}>
          <Card style={styles.confirmCard}>
            <Text style={type.title2}>{pendingConfirm?.title}</Text>
            <Text style={type.body}>{pendingConfirm?.body}</Text>
            <View style={styles.confirmActions}>
              <Button label={t("Cancel")} variant="secondary" onPress={() => { pendingConfirm?.cancel?.(); setPendingConfirm(null); }} />
              <Button label={pendingConfirm?.action ?? ""} variant={pendingConfirm?.primary ? "primary" : "danger"} onPress={() => {
                pendingConfirm?.run();
                setPendingConfirm(null);
              }} />
            </View>
          </Card>
        </View>
      </Modal>
      </> : null}
      <StartupScreen ready={ready} fontsReady={fontsReady} />
    </>
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
  // The language sheet. Each choice is a wash of the text colour, so it
  // stands off whatever is behind it, glass or the sheet's own pane; the
  // chosen one is the accent with white words, as a sent message is.
  languageSheet: { paddingHorizontal: space[4], paddingBottom: space[2], gap: space[2] },
  languageTitle: { paddingHorizontal: space[1], marginBottom: space[2] },
  languageChoice: {
    flexDirection: "row",
    alignItems: "center",
    gap: space[3],
    minHeight: controls["4xl"],
    paddingHorizontal: space[4],
    paddingVertical: space[2.5],
    borderRadius: radius["2xl"],
    backgroundColor: withAlpha(colors.text, 0.08),
  },
  languageChoiceChosen: { backgroundColor: colors.accent },
  languageGap: { height: space[2] },
  languageGreeting: { ...type.headline, color: colors.text },
  languageChosenText: { color: colors.onAccent },
  languageChosenMuted: { color: colors.onAccentMuted },
  // Over the welcome's top corner, clear of the status bar or window buttons.
  languageCorner: {
    position: "absolute",
    top: isDesktop ? TOOLBAR_HEIGHT : chrome.status + space[2],
    right: isDesktop ? space[6] : space[4],
  },
  keyLogBanner: { flexGrow: 0, paddingTop: space[3], paddingBottom: space[3], gap: space[1] },
  keyLogBannerPhone: { paddingTop: chrome.status + space[3], paddingBottom: chrome.status + space[3] },
  // A desktop alert puts its buttons in a row with the confirming action last.
  confirmActions: isDesktop
    ? { flexDirection: "row", justifyContent: "flex-end", gap: space[2], marginTop: space[1] }
    : { gap: space[2.5] },
  // The welcome step fills the pane, so the buttons stay where a thumb
  // expects them; the picture above the words takes up the slack.
  welcome: {
    flexGrow: 1,
    paddingHorizontal: space[6],
    paddingTop: chrome.status + space[3],
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
