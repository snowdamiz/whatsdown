import {
  BarcodeScanningResult,
  CameraView,
  useCameraPermissions,
} from "expo-camera";
import { StatusBar } from "expo-status-bar";
import { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  AppState,
  FlatList,
  KeyboardAvoidingView,
  Keyboard,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaProvider, SafeAreaView } from "react-native-safe-area-context";

import {
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  device_link_sas_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  update_conversation_export,
} from "../modules/mesh-messenger";
import { buildChatRows } from "./chat-rows";
import {
  accountRequest,
  Conversation,
  decodeUtf8,
  DeviceSetSummary,
  GroupDetails,
  GroupHistoryMessage,
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
import { formatInboxTime, groupDigits } from "./format";
import { historyRefreshDelay } from "./expiry";
import {
  addGroupMember,
  authorizeDeviceLink,
  createGroup,
  getGroupKeyPackage,
  GROUP_KEY_PACKAGE_LENGTH,
  inspectGroup,
  listGroups,
  loadAccountDevices,
  loadGroupHistory,
  registerDirectory,
  removeGroupMember,
  revokeDevice,
  sendFanout,
  sendGroupMessage,
  synchronizeMailbox,
} from "./network";
import {
  disablePushBinding,
  enablePushBinding,
  getPushStatus,
  listenForGenericWakeups,
  listenForPushRegistrationChanges,
  recoverPushBinding,
  type PushStatus,
} from "./push";
import { createQrCollector } from "./qr";
import { databasePath } from "./storage";
import { colors, fonts, type, useAppFonts } from "./theme";
import {
  Avatar,
  Badge,
  Button,
  Card,
  ChatHeader,
  Chip,
  CodeDisplay,
  AppGlyph,
  Composer,
  ConversationRow,
  DayDivider,
  EmptyState,
  FeatureRow,
  Field,
  GroupRow,
  Header,
  Hero,
  Icon,
  IconButton,
  KeyValue,
  LargeHeader,
  MessageBubble,
  Notice,
  QrCard,
  Reticle,
  Reveal,
  Row,
  RowGroup,
  SearchField,
  Section,
  Segmented,
  TabBar,
  Tap,
  Toast,
  layout,
} from "./ui";

type Screen =
  | "home"
  | "settings"
  | "notifications"
  | "new-chat"
  | "chat-info"
  | "group-info"
  | "account"
  | "scanner"
  | "chat"
  | "devices"
  | "link-device"
  | "link-authorization"
  | "groups"
  | "group"
  | "group-package";
type ScanMode =
  "contact" | "link-request" | "link-authorization" | "group-key-package";

const disappearingOptions = [
  { label: "Off", value: 0 },
  { label: "1 min", value: 60 },
  { label: "1 hour", value: 3_600 },
  { label: "1 day", value: 86_400 },
];

const tabs = [
  { key: "home", title: "Chats", icon: "chat" },
  { key: "groups", title: "Groups", icon: "groups" },
  { key: "settings", title: "You", icon: "person" },
] as const;

const friendlyError = (error: unknown): string => {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("peer_keys_changed"))
    return "Their security keys changed. Verify before sending.";
  if (message.includes("message_request_pending"))
    return "Accept this message request before replying.";
  if (message.includes("conversation_blocked"))
    return "Unblock this conversation before sending.";
  if (message.includes("404")) return "No exact username match was found.";
  if (message.includes("AbortError"))
    return "The server did not respond. Try again when connected.";
  return message || "Something went wrong.";
};

const groupName = (groupId: Uint8Array): string =>
  `Group ${hex(groupId).slice(0, 6)}`;

const pushSummary = (pushStatus: PushStatus): string =>
  pushStatus === "enabled"
    ? "Private alerts enabled"
    : pushStatus === "disabled"
      ? "No-push mode"
      : "Update pending";

export default function App() {
  const fontsReady = useAppFonts();
  const [initialLoading, setInitialLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [requestsOnly, setRequestsOnly] = useState(false);
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [qrCollector] = useState(createQrCollector);
  const [profile, setProfile] = useState<Uint8Array | null>(null);
  const [screen, setScreen] = useState<Screen>("home");
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [previews, setPreviews] = useState<Record<string, HistoryMessage>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryMessage[]>([]);
  const [groups, setGroups] = useState<GroupSummary[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<Uint8Array | null>(
    null,
  );
  const [groupDetails, setGroupDetails] = useState<GroupDetails | null>(null);
  const [groupHistory, setGroupHistory] = useState<GroupHistoryMessage[]>([]);
  const [groupComposer, setGroupComposer] = useState("");
  const [groupUsername, setGroupUsername] = useState("");
  const [groupKeyPackage, setGroupKeyPackage] = useState<Uint8Array | null>(
    null,
  );
  const [scannedGroupPackage, setScannedGroupPackage] =
    useState<Uint8Array | null>(null);
  const [username, setUsername] = useState("");
  const [contactUsername, setContactUsername] = useState("");
  const [firstMessage, setFirstMessage] = useState("");
  const [composer, setComposer] = useState("");
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

  const selected = conversations.find(
    (conversation) => conversation.conversationId.join(".") === selectedId,
  );
  const selectedGroup = groups.find(
    (group) => selectedGroupId && hex(group.groupId) === hex(selectedGroupId),
  );

  function rememberPreview(
    conversation: Conversation,
    messages: HistoryMessage[],
  ): void {
    const last = messages.at(-1);
    const key = hex(conversation.conversationId);
    setPreviews((previous) => {
      if (!last) {
        if (!(key in previous)) return previous;
        const { [key]: _removed, ...rest } = previous;
        return rest;
      }
      return { ...previous, [key]: last };
    });
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
    void refreshPreviews(next);
    return next;
  }

  async function refreshHistory(conversation: Conversation): Promise<void> {
    const encoded = await load_history_export(
      peerRequest(databasePath, conversation.peerAccountId),
    );
    const messages = parseHistory(encoded);
    setHistory(messages);
    rememberPreview(conversation, messages);
  }

  useEffect(() => {
    if (screen !== "chat" || !selected) return;
    const delay = historyRefreshDelay(history, Date.now());
    if (delay === undefined) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      void load_history_export(peerRequest(databasePath, selected.peerAccountId))
        .then((encoded) => {
          if (cancelled) return;
          const messages = parseHistory(encoded);
          setHistory(messages);
          rememberPreview(selected, messages);
        })
        .catch((caught) => {
          if (!cancelled) setError(friendlyError(caught));
        });
    }, delay);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [history, screen, selected]);

  async function refreshGroups(): Promise<GroupSummary[]> {
    const next = await listGroups(databasePath);
    setGroups(next);
    return next;
  }

  async function refreshGroup(groupId: Uint8Array): Promise<void> {
    const [details, nextHistory] = await Promise.all([
      inspectGroup(databasePath, groupId),
      loadGroupHistory(databasePath, groupId),
    ]);
    setGroupDetails(details);
    setGroupHistory(nextHistory);
  }

  async function refreshDevices(
    currentProfile: Uint8Array,
  ): Promise<DeviceSetSummary> {
    const loaded = await loadAccountDevices(databasePath, currentProfile);
    setDeviceSet(loaded.wire);
    setDevices(loaded.summary);
    return loaded.summary;
  }

  async function synchronize(): Promise<void> {
    if (!profile) return;
    setError("");
    setStatus("Checking the encrypted mailbox…");
    try {
      await registerDirectory(databasePath);
      await synchronizeMailbox(databasePath);
      const currentDevices = await refreshDevices(profile);
      const next = await refreshConversations();
      await refreshGroups();
      const active = next.find(
        (conversation) => conversation.conversationId.join(".") === selectedId,
      );
      if (active) await refreshHistory(active);
      if (selectedGroupId) await refreshGroup(selectedGroupId);
      if (currentDevices.changed) {
        setError("Your account device set changed. Review linked devices.");
        setStatus("Mailbox is current · device change detected");
      } else {
        setStatus("Mailbox is current");
      }
    } catch (caught) {
      setError(friendlyError(caught));
      setStatus("Offline — messages stay queued on the server");
    }
  }

  async function updatePush(work: () => Promise<PushStatus>): Promise<void> {
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
        await Promise.all([refreshConversations(), refreshGroups()]);
        setStatus("Encrypted identity unlocked");
      } catch {
        if (!cancelled) setStatus("Choose a username to create this device");
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
    const removePushListeners = listenForGenericWakeups(
      () => void synchronize(),
    );
    const appState = AppState.addEventListener("change", (state) => {
      if (state === "active") void synchronize();
    });
    void synchronize();
    return () => {
      removePushListeners();
      appState.remove();
    };
  }, [profile, selectedGroupId, selectedId]);

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
    setBusy(true);
    setError("");
    setStatus(label);
    try {
      await work();
    } catch (caught) {
      qrCollector.reset();
      setError(friendlyError(caught));
    } finally {
      setBusy(false);
    }
  }

  function openConversation(conversation: Conversation): void {
    setSelectedId(conversation.conversationId.join("."));
    setScreen("chat");
    void perform("Opening encrypted history…", async () => {
      await refreshHistory(conversation);
      setStatus("Messages decrypted on this device");
    });
  }

  function createAccount(): void {
    const normalized = username.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(normalized)) {
      setError("Use 3–32 lowercase letters, numbers, or underscores.");
      return;
    }
    void perform("Generating device keys…", async () => {
      const created = await create_account_export(
        accountRequest(databasePath, normalized),
      );
      setProfile(created);
      await registerDirectory(databasePath);
      await refreshDevices(created);
      setUsername("");
      setStatus("Identity created and public keys registered");
    });
  }

  function startWithProfile(contact: Uint8Array, body: string): void {
    if (!body.trim()) {
      setError("Write a first message.");
      return;
    }
    void perform("Sealing the first message…", async () => {
      const peer = parseProfileSummary(contact);
      const changed = await sendFanout(
        databasePath,
        peer.username,
        body.trim(),
        peer.accountId,
      );
      await refreshConversations();
      setFirstMessage("");
      setScannedProfile(null);
      setStatus(
        changed
          ? "Encrypted message queued · device change detected"
          : "Encrypted message queued",
      );
      if (changed)
        setError(
          "Their signed device set changed. Review linked devices and verify again.",
        );
      setScreen("home");
    });
  }

  function startByUsername(): void {
    const target = contactUsername.trim().toLowerCase();
    void perform("Resolving exact username…", async () => {
      const changed = await sendFanout(
        databasePath,
        target,
        firstMessage.trim(),
      );
      await refreshConversations();
      Keyboard.dismiss();
      setContactUsername("");
      setFirstMessage("");
      setScreen("home");
      setStatus(
        changed
          ? "Encrypted message queued · device change detected"
          : "Encrypted message queued",
      );
      if (changed)
        setError(
          "Their signed device set changed. Review linked devices and verify again.",
        );
    });
  }

  function sendMessage(): void {
    if (!selected || !composer.trim()) return;
    void perform("Encrypting message…", async () => {
      const changed = await sendFanout(
        databasePath,
        selected.username,
        composer.trim(),
        selected.peerAccountId,
      );
      setComposer("");
      await refreshConversations();
      await refreshHistory(selected);
      setStatus(
        changed
          ? "Encrypted message queued · device change detected"
          : "Encrypted message queued",
      );
      if (changed)
        setError(
          "Their signed device set changed. Review linked devices and verify again.",
        );
    });
  }

  function updatePolicy(action: number, value = 0): void {
    if (!selected) return;
    void perform("Updating local conversation policy…", async () => {
      await update_conversation_export(
        policyRequest(databasePath, selected.peerAccountId, action, value),
      );
      const next = await refreshConversations();
      const active = next.find(
        (conversation) => conversation.conversationId.join(".") === selectedId,
      );
      if (active) await refreshHistory(active);
      setStatus("Conversation policy updated on this device");
    });
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
    void perform("Preparing a one-time link request…", async () => {
      const request = await create_link_request_export(utf8(databasePath));
      const sas = decodeUtf8(await device_link_sas_export(request));
      setLinkRequest(request);
      setLinkSas(sas);
      setScreen("link-device");
      setStatus("Link request expires in ten minutes");
    });
  }

  function openDevices(): void {
    if (!profile) return;
    void perform("Loading signed device set…", async () => {
      await refreshDevices(profile);
      setScreen("devices");
      setStatus("Device set verified and cached");
    });
  }

  function openGroups(): void {
    void perform("Loading encrypted groups…", async () => {
      await refreshGroups();
      setScreen("groups");
      setStatus("Group state decrypted on this device");
    });
  }

  function openGroup(group: GroupSummary): void {
    setSelectedGroupId(group.groupId);
    setGroupDetails(null);
    setGroupHistory([]);
    setScreen("group");
    void perform("Opening encrypted group history…", async () => {
      await refreshGroup(group.groupId);
      setStatus("Group history decrypted on this device");
    });
  }

  function createNewGroup(): void {
    void perform("Creating a private group…", async () => {
      const groupId = await createGroup(databasePath);
      setSelectedGroupId(groupId);
      setGroupDetails(null);
      setGroupHistory([]);
      await Promise.all([refreshGroups(), refreshGroup(groupId)]);
      setScreen("group");
      setStatus("Private group created on this device");
    });
  }

  function showGroupKeyPackage(): void {
    void perform("Preparing this device’s signed group package…", async () => {
      setGroupKeyPackage(await getGroupKeyPackage(databasePath));
      setScreen("group-package");
      setStatus("One-device group package ready");
    });
  }

  function scanGroupKeyPackage(): void {
    const target = groupUsername.trim().toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(target)) {
      setError(
        "Enter the exact lowercase username before scanning their device.",
      );
      return;
    }
    openScanner("group-key-package");
  }

  function sendGroupText(): void {
    if (!selectedGroupId || !groupComposer.trim()) return;
    void perform("Encrypting for every group device…", async () => {
      await sendGroupMessage(
        databasePath,
        selectedGroupId,
        groupComposer.trim(),
      );
      setGroupComposer("");
      await Promise.all([refreshGroups(), refreshGroup(selectedGroupId)]);
      setStatus("Encrypted group message queued");
    });
  }

  function removeFromGroup(accountId: Uint8Array, deviceId: Uint8Array): void {
    if (!selectedGroupId) return;
    void perform("Removing this device from the group…", async () => {
      await removeGroupMember(
        databasePath,
        selectedGroupId,
        accountId,
        deviceId,
      );
      await Promise.all([refreshGroups(), refreshGroup(selectedGroupId)]);
      setStatus("Device removed from the group");
    });
  }

  function authorizeScannedDevice(): void {
    if (!profile || !scannedLinkRequest) return;
    void perform("Authorizing this exact device set change…", async () => {
      const loaded = await loadAccountDevices(databasePath, profile);
      const authorization = await authorizeDeviceLink(
        databasePath,
        loaded.wire,
        scannedLinkRequest,
      );
      setLinkAuthorization(authorization);
      setScreen("link-authorization");
      setStatus("Authorization signed by your account key");
    });
  }

  function confirmRevoke(deviceId: Uint8Array): void {
    Alert.alert(
      "Remove this device?",
      "It will permanently lose access to your account and future messages.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Revoke device",
          style: "destructive",
          onPress: () => revokeLinkedDevice(deviceId),
        },
      ],
    );
  }

  function revokeLinkedDevice(deviceId: Uint8Array): void {
    if (!profile || !deviceSet) return;
    void perform("Revoking device and disabling its mailbox…", async () => {
      await revokeDevice(databasePath, deviceSet, deviceId);
      await refreshDevices(profile);
      setStatus("Device permanently revoked");
    });
  }

  function onQrScanned(result: BarcodeScanningResult): void {
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
      void perform("Validating link request…", async () => {
        const request = linkRequestFromQr(data);
        const sas = decodeUtf8(await device_link_sas_export(request));
        setScannedLinkRequest(request);
        setLinkSas(sas);
        setStatus("Compare this code on both devices");
      });
    } else if (scanMode === "link-authorization") {
      setScreen("link-device");
      void perform("Verifying account authorization…", async () => {
        const authorization = payloadFromQr(data, "link-authorization", 20_864);
        const linkedProfile = await complete_device_link_export(
          vectors(utf8(databasePath), authorization),
        );
        setProfile(linkedProfile);
        await registerDirectory(databasePath);
        await refreshDevices(linkedProfile);
        setLinkRequest(null);
        setLinkSas("");
        setScreen("home");
        setStatus("Linked device active and registered");
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
        "Verifying this device and adding it to the group…",
        async () => {
          const keyPackage = payloadFromQr(
            data,
            "group-key-package",
            GROUP_KEY_PACKAGE_LENGTH,
          );
          setScannedGroupPackage(keyPackage);
          try {
            await addGroupMember(databasePath, groupId, target, keyPackage);
            await Promise.all([refreshGroups(), refreshGroup(groupId)]);
            setGroupUsername("");
            setScreen("group");
            setStatus("Verified device added and group update queued");
          } finally {
            qrCollector.reset();
            setScannedGroupPackage(null);
          }
        },
      );
    }
  }

  const ownUsername = profile ? parseProfileSummary(profile).username : "";
  const mainScreen = profile && ["home", "groups", "settings"].includes(screen);
  const pendingCount = conversations.filter((item) => item.requestPending).length;
  const previewOf = (conversation: Conversation) =>
    previews[hex(conversation.conversationId)];
  const filteredConversations = conversations
    .filter(
      (item) =>
        item.username.includes(search.trim().toLowerCase()) &&
        (!requestsOnly || item.requestPending),
    )
    .sort(
      (a, b) =>
        (previewOf(b)?.timestamp ?? 0) - (previewOf(a)?.timestamp ?? 0),
    );
  const go = (next: Screen) => {
    Keyboard.dismiss();
    setError("");
    setScreen(next);
  };
  const backToScannerOrigin = () =>
    go(
      scanMode === "link-request"
        ? "devices"
        : scanMode === "link-authorization"
          ? "link-device"
          : scanMode === "group-key-package"
            ? "group-info"
            : "new-chat",
    );

  function previewText(conversation: Conversation): string {
    if (conversation.blocked) return "Blocked";
    const last = previewOf(conversation);
    if (last) return last.direction === "sent" ? `You: ${last.body}` : last.body;
    if (conversation.requestPending) return "Wants to start a conversation";
    return "Encrypted conversation";
  }

  function conversationStatus(conversation: Conversation) {
    if (conversation.blocked)
      return { text: "Blocked", icon: "block", color: colors.text3 } as const;
    if (conversation.requestPending)
      return { text: "Message request", icon: "info", color: colors.accent } as const;
    if (conversation.keyChanged)
      return {
        text: "Safety number changed",
        icon: "warning",
        color: colors.warning,
      } as const;
    if (conversation.verified)
      return { text: "Verified · End-to-end encrypted", icon: "shield", color: colors.success } as const;
    return { text: "End-to-end encrypted", icon: "lock", color: colors.text2 } as const;
  }

  function renderOnboarding() {
    return (
      <ScrollView
        contentContainerStyle={styles.onboarding}
        keyboardShouldPersistTaps="handled"
      >
        <Reveal>
          <AppGlyph size={56} />
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
        <View style={layout.flex} />
        <Reveal delay={180} style={layout.stackLoose}>
          <Field
            label="Choose your username"
            value={username}
            onChangeText={setUsername}
            placeholder="your_name"
            prefix="@"
            hint="3–32 lowercase letters, numbers, or underscores."
          />
          <View style={layout.stack}>
            <Button label="Create account" onPress={createAccount} />
            <Button
              label="Link an existing account"
              onPress={beginDeviceLink}
              variant="ghost"
            />
          </View>
        </Reveal>
      </ScrollView>
    );
  }

  function renderLinkDevice(request: Uint8Array) {
    return (
      <>
        <Header
          title="Link this device"
          onBack={() => go("home")}
          backLabel="Cancel"
        />
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stack}>
            <Text style={type.title}>Bring your account along.</Text>
            <Text style={type.body}>
              On your trusted device, open You → Linked devices and scan this
              code.
            </Text>
          </View>
          <QrCard value={payloadQrValue("link-request", request)} />
          <View style={layout.center}>
            <Text style={type.sectionTitle}>Match this code on both devices</Text>
            <CodeDisplay value={linkSas} />
            <Text style={[type.caption, layout.centerText]}>
              The request expires in 10 minutes.
            </Text>
          </View>
          <Button
            label="Scan signed authorization"
            icon="scan"
            onPress={() => openScanner("link-authorization")}
          />
        </ScrollView>
      </>
    );
  }

  function renderScanner() {
    return (
      <>
        <Header
          title="Scan a code"
          onBack={backToScannerOrigin}
          backLabel="Cancel scan"
        />
        {scannedProfile ? (
          <ScrollView
            contentContainerStyle={layout.content}
            keyboardShouldPersistTaps="handled"
          >
            <Hero
              name={parseProfileSummary(scannedProfile).username}
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
            <View style={layout.stack}>
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
            </View>
          </ScrollView>
        ) : scannedLinkRequest ? (
          <ScrollView contentContainerStyle={layout.content}>
            <View style={layout.stack}>
              <Text style={type.title}>Do these codes match?</Text>
              <Text style={type.body}>
                Check the code shown on the new device before giving it access
                to your account.
              </Text>
            </View>
            <Card tone="accent" style={layout.center}>
              <CodeDisplay value={linkSas} />
            </Card>
            <View style={layout.stack}>
              <Button
                label="Authorize this device"
                icon="check"
                onPress={authorizeScannedDevice}
              />
              <Button
                label="Reject and scan again"
                onPress={() => openScanner("link-request")}
                variant="ghost"
              />
            </View>
          </ScrollView>
        ) : !cameraPermission?.granted ? (
          <EmptyState
            icon="camera"
            title="Camera access"
            body="Scan contact and device codes. Camera frames never leave your device."
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
      </>
    );
  }

  function renderNewChat() {
    return (
      <>
        <Header title="New message" onBack={() => go("home")} />
        <View style={styles.recipient}>
          <Text style={styles.recipientLabel}>To</Text>
          <View style={styles.recipientShell}>
            <Text style={styles.recipientPrefix}>@</Text>
            <TextInput
              accessibilityLabel="Username"
              testID="Username"
              value={contactUsername}
              onChangeText={setContactUsername}
              placeholder="exact username"
              placeholderTextColor={colors.text3}
              selectionColor={colors.accent}
              autoCapitalize="none"
              autoCorrect={false}
              autoFocus
              style={styles.recipientInput}
            />
          </View>
          <IconButton
            name="scan"
            label="Scan contact code"
            variant="tonal"
            onPress={() => openScanner("contact")}
          />
        </View>
        <View style={layout.flex}>
          <EmptyState
            icon="lock"
            title="A private conversation."
            body="Your first message arrives as a request. Only they can choose to accept it."
          />
        </View>
        <Composer
          label="First message"
          sendLabel="Send message request"
          value={firstMessage}
          onChangeText={setFirstMessage}
          onSend={startByUsername}
          sendDisabled={!contactUsername.trim()}
          placeholder="Write a message…"
        />
      </>
    );
  }

  function renderAccount(currentProfile: Uint8Array) {
    return (
      <>
        <Header title="My QR code" onBack={() => go("settings")} />
        <ScrollView contentContainerStyle={layout.content}>
          <Hero
            name={ownUsername}
            title={`@${ownUsername}`}
            subtitle="Have a friend scan this to connect."
          />
          <QrCard
            value={profileQrValue(currentProfile)}
            caption="Only your public contact details are shared"
          />
          <Notice text="Keep the whole code in view while it cycles. Verify safety numbers together after connecting." />
        </ScrollView>
      </>
    );
  }

  function renderSettings() {
    const activeDevices = devices?.devices.filter((device) => device.active).length;
    return (
      <>
        <LargeHeader title="You" />
        <ScrollView contentContainerStyle={layout.contentTight}>
          <Tap
            label="My QR code"
            onPress={() => go("account")}
            style={styles.profileCard}
            scaleTo={0.985}
          >
            <Avatar name={ownUsername} size={64} />
            <View style={layout.flex}>
              <Text numberOfLines={1} style={type.title2}>
                @{ownUsername}
              </Text>
              <Text style={type.footnote}>Show my QR code</Text>
            </View>
            <View style={styles.profileQr}>
              <Icon name="qr" size={22} color={colors.onAccent} strokeWidth={2} />
            </View>
          </Tap>
          <Section title="Account">
            <RowGroup>
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
                subtitle={pushSummary(pushStatus)}
                onPress={() => go("notifications")}
                tone="danger"
              />
            </RowGroup>
          </Section>
          <Section title="Privacy">
            <RowGroup>
              <Row
                icon="lock"
                title="Everything stays on this device"
                subtitle="Keys and message history are encrypted locally. Alerts never include a sender or a preview."
                tone="success"
              />
            </RowGroup>
          </Section>
        </ScrollView>
      </>
    );
  }

  function renderNotifications() {
    const enabled = pushStatus === "enabled" || pushStatus === "pending-bind";
    return (
      <>
        <Header title="Notifications" onBack={() => go("settings")} />
        <ScrollView contentContainerStyle={layout.content}>
          <Card style={layout.center}>
            <View style={styles.bigIcon}>
              <Icon name="bell" size={28} color={colors.accent} />
            </View>
            <Text style={[type.title2, layout.centerText]}>
              {pushStatus === "enabled"
                ? "Private alerts are on"
                : pushStatus === "pending-bind"
                  ? "Enabling notifications…"
                  : pushStatus === "pending-unbind"
                    ? "Disabling notifications…"
                    : "No-push mode"}
            </Text>
            <Text style={[type.body, layout.centerText]}>
              {enabled
                ? "Alerts only say that there is encrypted activity. Open Whatsdown to read your messages."
                : "This device isn’t registered for notifications. Open the app to check for new messages."}
            </Text>
          </Card>
          <Button
            disabled={pushBusy}
            variant={enabled ? "secondary" : "primary"}
            label={
              enabled
                ? "Use no-push mode"
                : pushStatus === "pending-unbind"
                  ? "Retry notification cleanup"
                  : "Enable private notifications"
            }
            onPress={() =>
              void updatePush(() =>
                pushStatus === "pending-unbind"
                  ? recoverPushBinding(databasePath)
                  : pushStatus !== "disabled"
                    ? disablePushBinding(databasePath)
                    : enablePushBinding(databasePath),
              )
            }
          />
          {pushStatus === "pending-bind" ? (
            <Notice text="Enablement will finish when the notification service is reachable." />
          ) : null}
          {pushStatus === "pending-unbind" ? (
            <Notice text="Cleanup will retry until notification registration is fully removed." />
          ) : null}
          {pushError ? <Notice tone="error" text={pushError} /> : null}
          <Text style={[type.caption, layout.centerText]}>
            Alerts never include a sender or message preview.
          </Text>
        </ScrollView>
      </>
    );
  }

  function renderDevices() {
    return (
      <>
        <Header title="Linked devices" onBack={() => go("settings")} />
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
                        : "Revoked device"
                  }
                  subtitle={hex(device.deviceId).slice(0, 16)}
                  trailing={
                    devices.canManage && device.active && !device.current ? (
                      <Button
                        label="Revoke"
                        variant="danger"
                        size="sm"
                        onPress={() => confirmRevoke(device.deviceId)}
                      />
                    ) : (
                      <Icon
                        name={device.active ? "check" : "close"}
                        color={device.active ? colors.success : colors.text3}
                        size={18}
                      />
                    )
                  }
                />
              ))}
            </RowGroup>
          ) : null}
          {devices?.canManage ? (
            <Button
              label="Link another device"
              icon="scan"
              onPress={() => openScanner("link-request")}
            />
          ) : null}
          <Text style={type.caption}>
            Revocation is permanent. A removed device can’t rejoin with its old
            identity.
          </Text>
        </ScrollView>
      </>
    );
  }

  function renderLinkAuthorization(authorization: Uint8Array) {
    return (
      <>
        <Header
          title="Approve the connection"
          onBack={() => go("devices")}
          backLabel="Close"
        />
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stack}>
            <Text style={type.title}>One last scan.</Text>
            <Text style={type.body}>
              Use the new device to scan this authorization. Only continue if
              the codes match on both screens.
            </Text>
          </View>
          <QrCard value={payloadQrValue("link-authorization", authorization)} />
          <View style={layout.center}>
            <Text style={type.sectionTitle}>Both screens should show</Text>
            <CodeDisplay value={linkSas} />
          </View>
        </ScrollView>
      </>
    );
  }

  function renderGroupPackage(keyPackage: Uint8Array) {
    return (
      <>
        <Header title="Join a group" onBack={() => go("groups")} />
        <ScrollView contentContainerStyle={layout.content}>
          <View style={layout.stack}>
            <Text style={type.title}>You’re invited.</Text>
            <Text style={type.body}>
              Ask a group member to scan this code from their group details to
              add this device.
            </Text>
          </View>
          <QrCard value={payloadQrValue("group-key-package", keyPackage)} />
          <Notice text="This invitation code is for this device only. Share a separate code for each linked device you want to add." />
        </ScrollView>
      </>
    );
  }

  function renderGroups() {
    return (
      <>
        <LargeHeader
          title="Groups"
          actions={
            <>
              <Button
                label="Join a group"
                variant="secondary"
                size="sm"
                icon="qr"
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
        <FlatList
          contentContainerStyle={layout.list}
          data={groups}
          keyExtractor={(group) => hex(group.groupId)}
          ListEmptyComponent={
            <EmptyState
              icon="groups"
              title="No groups yet."
              body="Create a private group, or show your device code to join one."
              action={<Button label="Start a group" onPress={createNewGroup} />}
            />
          }
          renderItem={({ item }) => (
            <GroupRow
              name={groupName(item.groupId)}
              label={groupName(item.groupId)}
              subtitle={`${item.memberCount} ${item.memberCount === 1 ? "device" : "devices"} · Epoch ${item.epoch}`}
              onPress={() => openGroup(item)}
            />
          )}
        />
      </>
    );
  }

  function renderGroupInfo(groupId: Uint8Array) {
    return (
      <>
        <Header title="Group details" onBack={() => go("group")} />
        <ScrollView
          contentContainerStyle={layout.content}
          keyboardShouldPersistTaps="handled"
        >
          <Hero
            name={groupName(groupId)}
            group
            title={groupName(groupId)}
            badge={
              <Badge
                label={`${selectedGroup?.memberCount ?? "—"} devices · Encrypted`}
                tone="muted"
                icon="lock"
              />
            }
          />
          <Card>
            <Text style={type.title2}>Invite someone</Text>
            <Text style={type.body}>
              Enter their exact username, then scan the code on their device.
            </Text>
            <Field
              label="Exact username"
              value={groupUsername}
              onChangeText={setGroupUsername}
              placeholder="their_name"
              prefix="@"
            />
            <Button
              label="Scan device package"
              icon="scan"
              disabled={!groupUsername.trim()}
              onPress={scanGroupKeyPackage}
            />
          </Card>
          <Section title={`Members · ${selectedGroup?.memberCount ?? "—"} devices`}>
            {groupDetails ? (
              <RowGroup>
                {groupDetails.members.map((member) => (
                  <Row
                    key={`${hex(member.accountId)}-${hex(member.deviceId)}`}
                    icon="device"
                    tone={member.local ? "accent" : "muted"}
                    title={member.local ? "This device" : `Member ${member.leaf + 1}`}
                    subtitle={`${hex(member.deviceId).slice(0, 16)} · ${member.witnessCount} witnesses`}
                    trailing={
                      member.local ? (
                        <Icon name="check" color={colors.success} size={18} />
                      ) : (
                        <Button
                          label="Remove"
                          variant="secondary"
                          size="sm"
                          onPress={() =>
                            removeFromGroup(member.accountId, member.deviceId)
                          }
                        />
                      )
                    }
                  />
                ))}
              </RowGroup>
            ) : (
              <Card style={layout.center}>
                <ActivityIndicator color={colors.accent} />
              </Card>
            )}
          </Section>
          <Section title="Security">
            <Card>
              <KeyValue label="Epoch" value={String(selectedGroup?.epoch ?? "—")} />
              <KeyValue
                label="Tree hash"
                value={groupDetails ? hex(groupDetails.treeHash) : "Loading…"}
              />
              <KeyValue
                label="Checkpoint"
                value={groupDetails ? hex(groupDetails.checkpointHash) : "Loading…"}
              />
            </Card>
          </Section>
        </ScrollView>
      </>
    );
  }

  function renderGroup(groupId: Uint8Array) {
    const rows = buildChatRows(
      groupHistory,
      (message, index) =>
        `${message.epoch}-${hex(message.senderDeviceId)}-${index}`,
    ).reverse();
    return (
      <>
        <ChatHeader
          name={groupName(groupId)}
          group
          status={`${selectedGroup?.memberCount ?? "—"} devices · Encrypted`}
          statusIcon="lock"
          onBack={() => go("groups")}
          backLabel="Back to groups"
          onInfo={() => go("group-info")}
          infoLabel="Group details"
        />
        <FlatList
          inverted
          data={rows}
          contentContainerStyle={layout.messages}
          keyExtractor={(row) => row.key}
          ListEmptyComponent={
            <View style={styles.flipped}>
              <EmptyState
                icon="lock"
                title="Nothing here yet."
                body="Add people from group details, then send your first message."
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
                tail={item.tail}
                spaced={item.spaced}
              />
            )
          }
        />
        <Composer
          group
          value={groupComposer}
          onChangeText={setGroupComposer}
          onSend={sendGroupText}
          sendDisabled={(selectedGroup?.memberCount ?? 0) < 2}
        />
      </>
    );
  }

  function renderChatInfo(conversation: Conversation) {
    const digitGroups = groupDigits(conversation.safetyNumber, 5);
    return (
      <>
        <Header title="Conversation details" onBack={() => go("chat")} />
        <ScrollView contentContainerStyle={layout.content}>
          <Hero
            name={conversation.username}
            title={`@${conversation.username}`}
            badge={
              conversation.blocked ? (
                <Badge label="Blocked" tone="danger" icon="block" />
              ) : conversation.verified ? (
                <Badge label="Safety number verified" tone="success" icon="shield" />
              ) : (
                <Badge label="End-to-end encrypted" tone="muted" icon="lock" />
              )
            }
          />
          <Card>
            <View style={layout.row}>
              <View style={styles.cardIcon}>
                <Icon name="shield" size={18} color={colors.white} strokeWidth={2.2} />
              </View>
              <Text style={[type.headline, layout.flex]}>Safety number</Text>
            </View>
            <Text style={type.body}>
              {conversation.safetyNumber
                ? "Compare this number together, in person or through a channel you trust."
                : "Send a new message to refresh this conversation’s security keys before verifying."}
            </Text>
            {digitGroups.length ? (
              <View style={styles.safetyGrid}>
                {digitGroups.map((group, index) => (
                  <Text key={index} selectable style={styles.safetyGroup}>
                    {group}
                  </Text>
                ))}
              </View>
            ) : null}
            {conversation.verified ? (
              <View style={layout.row}>
                <Icon name="check" size={16} color={colors.success} strokeWidth={2.4} />
                <Text style={[type.label, { color: colors.success }]}>
                  Verified on this device
                </Text>
              </View>
            ) : (
              <Button
                label={
                  conversation.safetyNumber
                    ? "Mark safety number verified"
                    : "Send a message to refresh security keys"
                }
                variant="secondary"
                icon="check"
                onPress={() => updatePolicy(4)}
                disabled={!conversation.safetyNumber}
              />
            )}
          </Card>
          <Section title="Disappearing messages">
            <Text style={type.body}>
              Choose how long messages remain visible on this device.
            </Text>
            <View style={layout.wrap}>
              {disappearingOptions.map((option) => (
                <Chip
                  key={option.value}
                  label={option.label}
                  accessibilityLabel={`Disappear: ${option.label}`}
                  selected={conversation.disappearingSeconds === option.value}
                  onPress={() => updatePolicy(5, option.value)}
                />
              ))}
            </View>
          </Section>
          <Button
            label={conversation.blocked ? "Unblock contact" : "Block contact"}
            icon="block"
            onPress={() => updatePolicy(conversation.blocked ? 3 : 2)}
            variant="danger"
          />
        </ScrollView>
      </>
    );
  }

  function renderChat(conversation: Conversation) {
    const rows = buildChatRows(history, (message) => hex(message.messageId)).reverse();
    const chatStatus = conversationStatus(conversation);
    return (
      <>
        <ChatHeader
          name={conversation.username}
          status={chatStatus.text}
          statusIcon={chatStatus.icon}
          statusColor={chatStatus.color}
          onBack={() => go("home")}
          backLabel="Back to chats"
          onInfo={() => go("chat-info")}
          infoLabel="Conversation details"
        />
        {conversation.requestPending ? (
          <Card tone="accent" style={styles.banner}>
            <Text style={type.headline}>Message request</Text>
            <Text style={type.body}>
              @{conversation.username} wants to start a conversation. Accept to
              reply, or block to never hear from them.
            </Text>
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
          </Card>
        ) : null}
        {conversation.keyChanged ? (
          <View style={styles.bannerNotice}>
            <Notice
              tone="warning"
              text="Security keys changed. Compare your safety number again before sending."
            />
          </View>
        ) : null}
        {conversation.blocked ? (
          <View style={styles.bannerNotice}>
            <Notice text="This contact is blocked. You can unblock them in conversation details." />
          </View>
        ) : null}
        <FlatList
          inverted
          data={rows}
          contentContainerStyle={layout.messages}
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
                disappearing={!!item.message.disappearingSeconds}
                tail={item.tail}
                spaced={item.spaced}
              />
            )
          }
        />
        <Composer
          value={composer}
          onChangeText={setComposer}
          onSend={sendMessage}
          disabled={conversation.blocked || conversation.requestPending}
          placeholder={
            conversation.blocked
              ? "Contact blocked"
              : conversation.requestPending
                ? "Accept the request to reply"
                : "Message"
          }
        />
      </>
    );
  }

  function renderHome() {
    return (
      <>
        <LargeHeader
          title="Chats"
          actions={
            <>
              <IconButton
                name="refresh"
                label="Sync messages"
                variant="tonal"
                onPress={() => void synchronize()}
              />
              <IconButton
                name="compose"
                label="New conversation"
                variant="filled"
                onPress={() => go("new-chat")}
              />
            </>
          }
        />
        <SearchField
          label="Search conversations"
          placeholder="Search"
          value={search}
          onChangeText={setSearch}
        />
        <Segmented
          value={requestsOnly ? "requests" : "all"}
          onChange={(key) => setRequestsOnly(key === "requests")}
          options={[
            { key: "all", label: "All" },
            {
              key: "requests",
              label: "Requests",
              accessibilityLabel: "Message requests",
              count: pendingCount,
            },
          ]}
        />
        <FlatList
          keyboardShouldPersistTaps="handled"
          keyboardDismissMode="on-drag"
          contentContainerStyle={layout.list}
          data={filteredConversations}
          keyExtractor={(item) => hex(item.conversationId)}
          ListEmptyComponent={
            <EmptyState
              icon={requestsOnly ? "shield" : "chat"}
              title={
                search
                  ? "No matches."
                  : requestsOnly
                    ? "No requests waiting."
                    : "No conversations yet."
              }
              body={
                search
                  ? "Try a different username."
                  : requestsOnly
                    ? "Messages from new people will wait here until you accept them."
                    : "Start with a username, or scan a friend’s contact code."
              }
              action={
                !search && !requestsOnly ? (
                  <>
                    <Button
                      label="New message"
                      icon="compose"
                      onPress={() => go("new-chat")}
                    />
                    <Button
                      label="Scan a contact code"
                      variant="ghost"
                      onPress={() => openScanner("contact")}
                    />
                  </>
                ) : undefined
              }
            />
          }
          renderItem={({ item }) => {
            const last = previewOf(item);
            return (
              <ConversationRow
                name={item.username}
                preview={previewText(item)}
                time={last ? formatInboxTime(last.timestamp) : ""}
                requestPending={item.requestPending}
                blocked={item.blocked}
                verified={item.verified}
                keyChanged={item.keyChanged}
                onPress={() => openConversation(item)}
              />
            );
          }}
        />
      </>
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
    if (screen === "notifications") return renderNotifications();
    if (screen === "devices") return renderDevices();
    if (screen === "link-authorization" && linkAuthorization)
      return renderLinkAuthorization(linkAuthorization);
    if (screen === "group-package" && groupKeyPackage)
      return renderGroupPackage(groupKeyPackage);
    if (screen === "groups") return renderGroups();
    if (screen === "group-info" && selectedGroupId) return renderGroupInfo(selectedGroupId);
    if (screen === "group" && selectedGroupId) return renderGroup(selectedGroupId);
    if (screen === "chat-info" && selected) return renderChatInfo(selected);
    if (screen === "chat" && selected) return renderChat(selected);
    return renderHome();
  }

  if (!fontsReady) return <View style={layout.screen} />;
  if (initialLoading)
    return (
      <SafeAreaProvider>
        <StatusBar style="light" />
        <SafeAreaView style={styles.loading}>
          <Reveal style={layout.center}>
            <AppGlyph size={76} />
            <Text style={[type.title2, { marginTop: 8 }]}>Whatsdown</Text>
          </Reveal>
          <View style={styles.loadingStatus}>
            <ActivityIndicator color={colors.accent} />
            <Text style={type.caption}>{status}</Text>
          </View>
        </SafeAreaView>
      </SafeAreaProvider>
    );
  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <SafeAreaView
        edges={
          mainScreen
            ? ["top", "left", "right"]
            : ["top", "left", "right", "bottom"]
        }
        style={layout.screen}
      >
        <KeyboardAvoidingView
          behavior={Platform.OS === "ios" ? "padding" : undefined}
          style={layout.flex}
        >
          <View style={layout.flex} pointerEvents={busy ? "none" : "auto"}>
            {renderScreen()}
          </View>
          {busy ? <Toast text={status} busy /> : null}
          {error ? (
            <Toast text={error} error onDismiss={() => setError("")} />
          ) : null}
        </KeyboardAvoidingView>
        {mainScreen ? (
          <TabBar
            tabs={tabs}
            current={screen as (typeof tabs)[number]["key"]}
            onSelect={(key) => (key === "groups" ? openGroups() : go(key))}
          />
        ) : null}
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  loading: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    gap: 28,
    backgroundColor: colors.canvas,
  },
  loadingStatus: { alignItems: "center", gap: 12 },
  onboarding: {
    flexGrow: 1,
    paddingHorizontal: 24,
    paddingTop: 12,
    paddingBottom: 16,
    gap: 22,
  },
  heroBlock: { gap: 10 },
  features: { gap: 16 },
  camera: {
    flex: 1,
    margin: 16,
    marginTop: 4,
    borderRadius: 28,
    overflow: "hidden",
    backgroundColor: colors.black,
  },
  recipient: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    paddingHorizontal: 20,
    paddingTop: 4,
    paddingBottom: 14,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: colors.line,
  },
  recipientLabel: { ...type.label, color: colors.text2 },
  recipientShell: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
    gap: 2,
    minHeight: 46,
    paddingHorizontal: 14,
    borderRadius: 23,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.line,
  },
  recipientPrefix: { fontFamily: fonts.medium, fontSize: 16, color: colors.text3 },
  recipientInput: {
    flex: 1,
    fontFamily: fonts.regular,
    fontSize: 16,
    color: colors.text,
    paddingVertical: 0,
  },
  profileCard: {
    flexDirection: "row",
    alignItems: "center",
    gap: 16,
    padding: 16,
    borderRadius: 18,
    backgroundColor: colors.surface,
  },
  profileQr: {
    width: 44,
    height: 44,
    borderRadius: 14,
    backgroundColor: colors.accent,
    alignItems: "center",
    justifyContent: "center",
  },
  bigIcon: {
    width: 64,
    height: 64,
    borderRadius: 22,
    backgroundColor: colors.accentSoft,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 4,
  },
  cardIcon: {
    width: 32,
    height: 32,
    borderRadius: 9,
    backgroundColor: colors.success,
    alignItems: "center",
    justifyContent: "center",
  },
  safetyGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 10,
    paddingVertical: 4,
  },
  safetyGroup: {
    fontFamily: fonts.mono,
    fontSize: 17,
    lineHeight: 24,
    letterSpacing: 1.5,
    color: colors.text,
    fontVariant: ["tabular-nums"],
    width: "30%",
  },
  banner: { marginHorizontal: 16, marginTop: 12 },
  bannerNotice: { paddingHorizontal: 16, paddingTop: 12 },
  flipped: { flex: 1, transform: [{ scaleY: -1 }] },
});
