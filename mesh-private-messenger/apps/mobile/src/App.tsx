import { IBMPlexMono_400Regular } from '@expo-google-fonts/ibm-plex-mono/400Regular';
import { Newsreader_400Regular } from '@expo-google-fonts/newsreader/400Regular';
import { Newsreader_600SemiBold } from '@expo-google-fonts/newsreader/600SemiBold';
import { BarcodeScanningResult, CameraView, useCameraPermissions } from 'expo-camera';
import { useFonts } from 'expo-font';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import {
  ActivityIndicator,
  AppState,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import {
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  device_link_sas_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  update_conversation_export,
} from '../modules/mesh-messenger';
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
} from './codec';
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
} from './network';
import {
  disablePushBinding,
  enablePushBinding,
  getPushStatus,
  listenForGenericWakeups,
  listenForPushRegistrationChanges,
  recoverPushBinding,
  type PushStatus,
} from './push';
import { databasePath } from './storage';

const colors = {
  background: '#11120F',
  panel: '#1A1C17',
  panelRaised: '#24261F',
  paper: '#F0E7D2',
  muted: '#AAA38F',
  amber: '#FFBE45',
  amberDark: '#5E4318',
  green: '#8CCF9A',
  red: '#FF766C',
  line: '#3A3D32',
};

type Screen =
  | 'home'
  | 'account'
  | 'scanner'
  | 'chat'
  | 'devices'
  | 'link-device'
  | 'link-authorization'
  | 'groups'
  | 'group'
  | 'group-package';
type ScanMode = 'contact' | 'link-request' | 'link-authorization' | 'group-key-package';

const disappearingOptions = [
  { label: 'Off', value: 0 },
  { label: '1 min', value: 60 },
  { label: '1 hour', value: 3_600 },
  { label: '1 day', value: 86_400 },
];

const friendlyError = (error: unknown): string => {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes('peer_keys_changed')) return 'Their security keys changed. Verify before sending.';
  if (message.includes('message_request_pending')) return 'Accept this message request before replying.';
  if (message.includes('conversation_blocked')) return 'Unblock this conversation before sending.';
  if (message.includes('404')) return 'No exact username match was found.';
  if (message.includes('AbortError')) return 'The server did not respond. Try again when connected.';
  return message || 'Something went wrong.';
};

function PrimaryButton({
  label,
  onPress,
  disabled = false,
  quiet = false,
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  quiet?: boolean;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        quiet ? styles.buttonQuiet : styles.buttonPrimary,
        pressed && !disabled ? styles.pressed : null,
        disabled ? styles.disabled : null,
      ]}
    >
      <Text style={[styles.buttonText, quiet ? styles.buttonQuietText : null]}>{label}</Text>
    </Pressable>
  );
}

function StatusNotice({ text, error = false }: { text: string; error?: boolean }) {
  return (
    <View
      accessibilityLiveRegion={error ? 'assertive' : 'polite'}
      style={[styles.notice, error ? styles.noticeError : null]}
    >
      <Text style={[styles.noticeText, error ? styles.noticeErrorText : null]}>{text}</Text>
    </View>
  );
}

function Field({
  label,
  value,
  onChangeText,
  placeholder,
  multiline = false,
}: {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  placeholder: string;
  multiline?: boolean;
}) {
  return (
    <View style={styles.field}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput
        accessibilityLabel={label}
        autoCapitalize="none"
        autoCorrect={false}
        multiline={multiline}
        onChangeText={onChangeText}
        placeholder={placeholder}
        placeholderTextColor="#777365"
        style={[styles.input, multiline ? styles.inputMultiline : null]}
        value={value}
      />
    </View>
  );
}

export default function App() {
  const [fontsLoaded] = useFonts({
    Newsreader_400Regular,
    Newsreader_600SemiBold,
    IBMPlexMono_400Regular,
  });
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [profile, setProfile] = useState<Uint8Array | null>(null);
  const [screen, setScreen] = useState<Screen>('home');
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryMessage[]>([]);
  const [groups, setGroups] = useState<GroupSummary[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<Uint8Array | null>(null);
  const [groupDetails, setGroupDetails] = useState<GroupDetails | null>(null);
  const [groupHistory, setGroupHistory] = useState<GroupHistoryMessage[]>([]);
  const [groupComposer, setGroupComposer] = useState('');
  const [groupUsername, setGroupUsername] = useState('');
  const [groupKeyPackage, setGroupKeyPackage] = useState<Uint8Array | null>(null);
  const [scannedGroupPackage, setScannedGroupPackage] = useState<Uint8Array | null>(null);
  const [username, setUsername] = useState('');
  const [contactUsername, setContactUsername] = useState('');
  const [firstMessage, setFirstMessage] = useState('');
  const [composer, setComposer] = useState('');
  const [scannedProfile, setScannedProfile] = useState<Uint8Array | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>('contact');
  const [scannedLinkRequest, setScannedLinkRequest] = useState<Uint8Array | null>(null);
  const [linkRequest, setLinkRequest] = useState<Uint8Array | null>(null);
  const [linkAuthorization, setLinkAuthorization] = useState<Uint8Array | null>(null);
  const [linkSas, setLinkSas] = useState('');
  const [deviceSet, setDeviceSet] = useState<Uint8Array | null>(null);
  const [devices, setDevices] = useState<DeviceSetSummary | null>(null);
  const [busy, setBusy] = useState(true);
  const [status, setStatus] = useState('Opening encrypted storage…');
  const [error, setError] = useState('');
  const [pushStatus, setPushStatus] = useState<PushStatus>('disabled');
  const [pushBusy, setPushBusy] = useState(false);
  const [pushError, setPushError] = useState('');

  const selected = conversations.find((conversation) => conversation.conversationId.join('.') === selectedId);
  const selectedGroup = groups.find(
    (group) => selectedGroupId && hex(group.groupId) === hex(selectedGroupId),
  );

  async function refreshConversations(): Promise<Conversation[]> {
    const encoded = await list_conversations_export(utf8(databasePath));
    const next = parseConversations(encoded);
    setConversations(next);
    return next;
  }

  async function refreshHistory(conversation: Conversation): Promise<void> {
    const encoded = await load_history_export(peerRequest(databasePath, conversation.peerAccountId));
    setHistory(parseHistory(encoded));
  }

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

  async function refreshDevices(currentProfile: Uint8Array): Promise<DeviceSetSummary> {
    const loaded = await loadAccountDevices(databasePath, currentProfile);
    setDeviceSet(loaded.wire);
    setDevices(loaded.summary);
    return loaded.summary;
  }

  async function synchronize(): Promise<void> {
    if (!profile) return;
    setError('');
    setStatus('Checking the encrypted mailbox…');
    try {
      await registerDirectory(databasePath);
      await synchronizeMailbox(databasePath);
      const currentDevices = await refreshDevices(profile);
      const next = await refreshConversations();
      await refreshGroups();
      const active = next.find((conversation) => conversation.conversationId.join('.') === selectedId);
      if (active) await refreshHistory(active);
      if (selectedGroupId) await refreshGroup(selectedGroupId);
      if (currentDevices.changed) {
        setError('Your account device set changed. Review linked devices.');
        setStatus('Mailbox is current · device change detected');
      } else {
        setStatus('Mailbox is current');
      }
    } catch (caught) {
      setError(friendlyError(caught));
      setStatus('Offline — messages stay queued on the server');
    }
  }

  async function updatePush(work: () => Promise<PushStatus>): Promise<void> {
    setPushBusy(true);
    setPushError('');
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
        setStatus('Encrypted identity unlocked');
      } catch {
        if (!cancelled) setStatus('Choose a username to create this device');
      } finally {
        if (!cancelled) setBusy(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!profile) return undefined;
    const removePushListeners = listenForGenericWakeups(() => void synchronize());
    const appState = AppState.addEventListener('change', (state) => {
      if (state === 'active') void synchronize();
    });
    void synchronize();
    return () => {
      removePushListeners();
      appState.remove();
    };
  }, [profile, selectedGroupId, selectedId]);

  useEffect(() => {
    if (!profile) return undefined;
    const removeRegistrationListener = listenForPushRegistrationChanges(recoverPush);
    const appState = AppState.addEventListener('change', (state) => {
      if (state === 'active') recoverPush();
    });
    recoverPush();
    return () => {
      removeRegistrationListener();
      appState.remove();
    };
  }, [profile]);

  async function perform(label: string, work: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError('');
    setStatus(label);
    try {
      await work();
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setBusy(false);
    }
  }

  function openConversation(conversation: Conversation): void {
    setSelectedId(conversation.conversationId.join('.'));
    setScreen('chat');
    void perform('Opening encrypted history…', async () => {
      await refreshHistory(conversation);
      setStatus('Messages decrypted on this device');
    });
  }

  function createAccount(): void {
    const normalized = username.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(normalized)) {
      setError('Use 3–32 lowercase letters, numbers, or underscores.');
      return;
    }
    void perform('Generating device keys…', async () => {
      const created = await create_account_export(accountRequest(databasePath, normalized));
      setProfile(created);
      await registerDirectory(databasePath);
      await refreshDevices(created);
      setUsername('');
      setStatus('Identity created and public keys registered');
    });
  }

  function startWithProfile(contact: Uint8Array, body: string): void {
    if (!body.trim()) {
      setError('Write a first message.');
      return;
    }
    void perform('Sealing the first message…', async () => {
      const changed = await sendFanout(databasePath, parseProfileSummary(contact).username, body.trim());
      await refreshConversations();
      setFirstMessage('');
      setScannedProfile(null);
      setStatus(changed ? 'Encrypted message queued · device change detected' : 'Encrypted message queued');
      if (changed) setError('Their signed device set changed. Review linked devices and verify again.');
      setScreen('home');
    });
  }

  function startByUsername(): void {
    const target = contactUsername.trim().toLowerCase();
    void perform('Resolving exact username…', async () => {
      const changed = await sendFanout(databasePath, target, firstMessage.trim());
      await refreshConversations();
      setContactUsername('');
      setFirstMessage('');
      setStatus(changed ? 'Encrypted message queued · device change detected' : 'Encrypted message queued');
      if (changed) setError('Their signed device set changed. Review linked devices and verify again.');
    });
  }

  function sendMessage(): void {
    if (!selected || !composer.trim()) return;
    void perform('Encrypting message…', async () => {
      const changed = await sendFanout(databasePath, selected.username, composer.trim());
      setComposer('');
      await refreshHistory(selected);
      setStatus(changed ? 'Encrypted message queued · device change detected' : 'Encrypted message queued');
      if (changed) setError('Their signed device set changed. Review linked devices and verify again.');
    });
  }

  function updatePolicy(action: number, value = 0): void {
    if (!selected) return;
    void perform('Updating local conversation policy…', async () => {
      await update_conversation_export(
        policyRequest(databasePath, selected.peerAccountId, action, value),
      );
      const next = await refreshConversations();
      const active = next.find((conversation) => conversation.conversationId.join('.') === selectedId);
      if (active) await refreshHistory(active);
      setStatus('Conversation policy updated on this device');
    });
  }

  function openScanner(mode: ScanMode): void {
    setScanMode(mode);
    setScannedProfile(null);
    setScannedLinkRequest(null);
    setScannedGroupPackage(null);
    setError('');
    setScreen('scanner');
  }

  function beginDeviceLink(): void {
    void perform('Preparing a one-time link request…', async () => {
      const request = await create_link_request_export(utf8(databasePath));
      const sas = decodeUtf8(await device_link_sas_export(request));
      setLinkRequest(request);
      setLinkSas(sas);
      setScreen('link-device');
      setStatus('Link request expires in ten minutes');
    });
  }

  function openDevices(): void {
    if (!profile) return;
    void perform('Loading signed device set…', async () => {
      await refreshDevices(profile);
      setScreen('devices');
      setStatus('Device set verified and cached');
    });
  }

  function openGroups(): void {
    void perform('Loading encrypted groups…', async () => {
      await refreshGroups();
      setScreen('groups');
      setStatus('Group state decrypted on this device');
    });
  }

  function openGroup(group: GroupSummary): void {
    setSelectedGroupId(group.groupId);
    setGroupDetails(null);
    setGroupHistory([]);
    setScreen('group');
    void perform('Opening encrypted group history…', async () => {
      await refreshGroup(group.groupId);
      setStatus('Group history decrypted on this device');
    });
  }

  function createNewGroup(): void {
    void perform('Creating a private group…', async () => {
      const groupId = await createGroup(databasePath);
      setSelectedGroupId(groupId);
      setGroupDetails(null);
      setGroupHistory([]);
      await Promise.all([refreshGroups(), refreshGroup(groupId)]);
      setScreen('group');
      setStatus('Private group created on this device');
    });
  }

  function showGroupKeyPackage(): void {
    void perform('Preparing this device’s signed group package…', async () => {
      setGroupKeyPackage(await getGroupKeyPackage(databasePath));
      setScreen('group-package');
      setStatus('One-device group package ready');
    });
  }

  function scanGroupKeyPackage(): void {
    const target = groupUsername.trim().toLowerCase();
    if (!/^[a-z0-9._-]{1,64}$/.test(target)) {
      setError('Enter the exact lowercase username before scanning their device.');
      return;
    }
    openScanner('group-key-package');
  }

  function sendGroupText(): void {
    if (!selectedGroupId || !groupComposer.trim()) return;
    void perform('Encrypting for every group device…', async () => {
      await sendGroupMessage(databasePath, selectedGroupId, groupComposer.trim());
      setGroupComposer('');
      await Promise.all([refreshGroups(), refreshGroup(selectedGroupId)]);
      setStatus('Encrypted group message queued');
    });
  }

  function removeFromGroup(accountId: Uint8Array, deviceId: Uint8Array): void {
    if (!selectedGroupId) return;
    void perform('Removing this device from the group…', async () => {
      await removeGroupMember(databasePath, selectedGroupId, accountId, deviceId);
      await Promise.all([refreshGroups(), refreshGroup(selectedGroupId)]);
      setStatus('Device removed from the group');
    });
  }

  function authorizeScannedDevice(): void {
    if (!profile || !scannedLinkRequest) return;
    void perform('Authorizing this exact device set change…', async () => {
      const loaded = await loadAccountDevices(databasePath, profile);
      const authorization = await authorizeDeviceLink(
        databasePath,
        loaded.wire,
        scannedLinkRequest,
      );
      setLinkAuthorization(authorization);
      setScreen('link-authorization');
      setStatus('Authorization signed by your account key');
    });
  }

  function revokeLinkedDevice(deviceId: Uint8Array): void {
    if (!profile || !deviceSet) return;
    void perform('Revoking device and disabling its mailbox…', async () => {
      await revokeDevice(databasePath, deviceSet, deviceId);
      await refreshDevices(profile);
      setStatus('Device permanently revoked');
    });
  }

  function onQrScanned(result: BarcodeScanningResult): void {
    if (scannedProfile || scannedLinkRequest || scannedGroupPackage) return;
    if (scanMode === 'contact') {
      try {
        setScannedProfile(profileFromQr(result.data));
        setError('');
      } catch (caught) {
        setError(friendlyError(caught));
      }
    } else if (scanMode === 'link-request') {
      void perform('Validating link request…', async () => {
        const request = linkRequestFromQr(result.data);
        setScannedLinkRequest(request);
        setLinkSas(decodeUtf8(await device_link_sas_export(request)));
        setStatus('Compare this code on both devices');
      });
    } else if (scanMode === 'link-authorization') {
      setScreen('link-device');
      void perform('Verifying account authorization…', async () => {
        const authorization = payloadFromQr(result.data, 'link-authorization', 20_864);
        const linkedProfile = await complete_device_link_export(
          vectors(utf8(databasePath), authorization),
        );
        setProfile(linkedProfile);
        await registerDirectory(databasePath);
        await refreshDevices(linkedProfile);
        setLinkRequest(null);
        setLinkSas('');
        setScreen('home');
        setStatus('Linked device active and registered');
      });
    } else {
      const groupId = selectedGroupId;
      const target = groupUsername.trim().toLowerCase();
      if (!groupId || !target) {
        setError('Choose a group and enter the exact username before scanning.');
        return;
      }
      void perform('Verifying this device and adding it to the group…', async () => {
        const keyPackage = payloadFromQr(
          result.data,
          'group-key-package',
          GROUP_KEY_PACKAGE_LENGTH,
        );
        setScannedGroupPackage(keyPackage);
        try {
          await addGroupMember(databasePath, groupId, target, keyPackage);
          await Promise.all([refreshGroups(), refreshGroup(groupId)]);
          setGroupUsername('');
          setScreen('group');
          setStatus('Verified device added and group update queued');
        } finally {
          setScannedGroupPackage(null);
        }
      });
    }
  }

  if (!fontsLoaded || busy) {
    return (
      <SafeAreaProvider>
        <SafeAreaView style={styles.loading}>
          <ActivityIndicator color={colors.amber} size="large" />
          <Text accessibilityLiveRegion="polite" style={styles.loadingText}>
            {status}
          </Text>
        </SafeAreaView>
      </SafeAreaProvider>
    );
  }

  const onboarding = !profile;

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <SafeAreaView style={styles.safeArea}>
        <KeyboardAvoidingView
          behavior={Platform.OS === 'ios' ? 'padding' : undefined}
          style={styles.flex}
        >
          {onboarding && screen === 'link-device' && linkRequest ? (
            <ScrollView contentContainerStyle={styles.screenContent}>
              <View style={styles.topRow}>
                <PrimaryButton label="Cancel" onPress={() => setScreen('home')} quiet />
                <Text style={styles.eyebrow}>LINK THIS DEVICE</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Scan this from a trusted device.
              </Text>
              <Text style={styles.bodyCopy}>
                Compare the short code on both screens before authorizing. This request expires in ten
                minutes.
              </Text>
              <View accessibilityLabel="One-time device link QR code" style={styles.qrFrame}>
                <QRCode
                  backgroundColor={colors.paper}
                  color={colors.background}
                  quietZone={12}
                  size={250}
                  value={payloadQrValue('link-request', linkRequest)}
                />
              </View>
              <Text style={styles.sas}>{linkSas}</Text>
              <PrimaryButton
                label="Scan signed authorization"
                onPress={() => openScanner('link-authorization')}
              />
              {error ? <StatusNotice error text={error} /> : null}
            </ScrollView>
          ) : onboarding ? (
            <ScrollView contentContainerStyle={styles.onboarding} keyboardShouldPersistTaps="handled">
              <Text style={styles.eyebrow}>PRIVATE MESSENGER / DEVICE 01</Text>
              <Text accessibilityRole="header" style={styles.heroTitle}>
                A quiet line to the people you trust.
              </Text>
              <Text style={styles.heroBody}>
                Your private keys stay in this device’s secure hardware. A phone number is never
                required.
              </Text>
              <View style={styles.rule} />
              <Field
                label="Choose your username"
                onChangeText={setUsername}
                placeholder="river_stone"
                value={username}
              />
              {error ? <StatusNotice error text={error} /> : null}
              <PrimaryButton label="Create encrypted identity" onPress={createAccount} />
              <PrimaryButton label="Link an existing account" onPress={beginDeviceLink} quiet />
              <Text style={styles.finePrint}>
                Losing this device without a linked device or recovery export means losing encrypted
                history.
              </Text>
            </ScrollView>
          ) : screen === 'account' ? (
            <ScrollView contentContainerStyle={styles.screenContent}>
              <View style={styles.topRow}>
                <PrimaryButton label="Back" onPress={() => setScreen('home')} quiet />
                <Text style={styles.eyebrow}>MY CONTACT CODE</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Let them scan. Nothing else.
              </Text>
              <Text style={styles.bodyCopy}>
                This code contains public identity and prekey material. It never contains a private key
                or message history.
              </Text>
              <View accessibilityLabel="Your Whatsdown contact QR code" style={styles.qrFrame}>
                <QRCode
                  backgroundColor={colors.paper}
                  color={colors.background}
                  quietZone={12}
                  size={250}
                  value={profileQrValue(profile)}
                />
              </View>
              <Text style={styles.monoCaption}>VERIFY THE SAFETY NUMBER AFTER CONNECTING</Text>
              <View style={styles.newContactPanel}>
                <Text style={styles.panelKicker}>GENERIC NOTIFICATIONS</Text>
                <Text accessibilityRole="header" style={styles.panelTitle}>
                  {pushStatus === 'enabled'
                    ? 'Enabled'
                    : pushStatus === 'pending-bind'
                      ? 'Enabling notifications…'
                    : pushStatus === 'pending-unbind'
                      ? 'Disabling notifications…'
                      : 'No-push mode'}
                </Text>
                <Text style={styles.bodyCopy}>
                  No-push mode never requests notification permission or registers this device. When
                  enabled, alerts reveal only generic encrypted activity.
                </Text>
                <PrimaryButton
                  disabled={pushBusy}
                  label={
                    pushStatus === 'enabled' || pushStatus === 'pending-bind'
                      ? 'Use no-push mode'
                      : pushStatus === 'pending-unbind'
                        ? 'Retry notification cleanup'
                        : 'Enable generic notifications'
                  }
                  onPress={() =>
                    void updatePush(() => {
                      if (pushStatus === 'pending-unbind') {
                        return recoverPushBinding(databasePath);
                      }
                      if (pushStatus !== 'disabled') return disablePushBinding(databasePath);
                      return enablePushBinding(databasePath);
                    })
                  }
                />
                {pushStatus === 'pending-bind' ? (
                  <StatusNotice text="Notification enablement will finish when the broker is reachable." />
                ) : null}
                {pushStatus === 'pending-unbind' ? (
                  <StatusNotice text="Notification cleanup is pending and will retry until local token removal and broker unbinding both finish." />
                ) : null}
                {pushError ? <StatusNotice error text={pushError} /> : null}
              </View>
            </ScrollView>
          ) : screen === 'link-authorization' && linkAuthorization ? (
            <ScrollView contentContainerStyle={styles.screenContent}>
              <View style={styles.topRow}>
                <PrimaryButton label="Close" onPress={() => setScreen('devices')} quiet />
                <Text style={styles.eyebrow}>SIGNED DEVICE LINK</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Return this authorization to the new device.
              </Text>
              <Text style={styles.bodyCopy}>
                Scan only after the short code matches on both screens. The signature is bound to that
                exact one-time request.
              </Text>
              <View accessibilityLabel="Signed device authorization QR code" style={styles.qrFrame}>
                <QRCode
                  backgroundColor={colors.paper}
                  color={colors.background}
                  quietZone={12}
                  size={250}
                  value={payloadQrValue('link-authorization', linkAuthorization)}
                />
              </View>
              <Text style={styles.sas}>{linkSas}</Text>
            </ScrollView>
          ) : screen === 'devices' ? (
            <ScrollView contentContainerStyle={styles.screenContent}>
              <View style={styles.topRow}>
                <PrimaryButton label="Back" onPress={() => setScreen('home')} quiet />
                <Text style={styles.eyebrow}>ACCOUNT DEVICES</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Devices that can receive your messages.
              </Text>
              <Text style={styles.bodyCopy}>
                Revocation is permanent. A lost device cannot silently rejoin with the same identity.
              </Text>
              {devices?.changed ? (
                <StatusNotice error text="The signed device sequence changed since your last review." />
              ) : null}
              {devices && !devices.canManage ? (
                <StatusNotice text="This linked device can receive messages but does not hold the account authority key needed to link or revoke devices." />
              ) : null}
              <View style={styles.deviceList}>
                {devices?.devices.map((device) => (
                  <View key={hex(device.deviceId)} style={styles.deviceRow}>
                    <View style={styles.deviceCopy}>
                      <Text style={styles.deviceTitle}>
                        {device.current ? 'This device' : device.active ? 'Linked device' : 'Revoked device'}
                      </Text>
                      <Text style={styles.monoCaption}>{hex(device.deviceId).slice(0, 20)}…</Text>
                    </View>
                    {devices?.canManage && device.active && !device.current ? (
                      <PrimaryButton
                        label="Revoke permanently"
                        onPress={() => revokeLinkedDevice(device.deviceId)}
                        quiet
                      />
                    ) : null}
                  </View>
                ))}
              </View>
              {devices?.canManage ? (
                <PrimaryButton label="Link another device" onPress={() => openScanner('link-request')} />
              ) : null}
              {error ? <StatusNotice error text={error} /> : null}
            </ScrollView>
          ) : screen === 'group-package' && groupKeyPackage ? (
            <ScrollView contentContainerStyle={styles.screenContent}>
              <View style={styles.topRow}>
                <PrimaryButton label="Back to groups" onPress={() => setScreen('groups')} quiet />
                <Text style={styles.eyebrow}>THIS DEVICE / GROUP PACKAGE</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Let an existing member scan this device.
              </Text>
              <Text style={styles.bodyCopy}>
                This signed one-use package represents only this device. Every linked device shares its
                own package; usernames are never used as key-package storage.
              </Text>
              <View accessibilityLabel="This device’s signed group key package" style={styles.qrFrame}>
                <QRCode
                  backgroundColor={colors.paper}
                  color={colors.background}
                  quietZone={12}
                  size={250}
                  value={payloadQrValue('group-key-package', groupKeyPackage)}
                />
              </View>
              <Text style={styles.monoCaption}>369-BYTE SIGNED PACKAGE · ONE DEVICE ONLY</Text>
              {error ? <StatusNotice error text={error} /> : null}
            </ScrollView>
          ) : screen === 'groups' ? (
            <ScrollView contentContainerStyle={styles.screenContent}>
              <View style={styles.topRow}>
                <PrimaryButton label="Back" onPress={() => setScreen('home')} quiet />
                <Text style={styles.eyebrow}>PRIVATE GROUPS</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Rooms without a server-side roster.
              </Text>
              <Text style={styles.bodyCopy}>
                Membership, epochs, and message history are encrypted and owned by the Mesh core on
                this device.
              </Text>
              <View style={styles.headerActions}>
                <PrimaryButton label="Create group" onPress={createNewGroup} />
                <PrimaryButton label="My device package" onPress={showGroupKeyPackage} quiet />
              </View>
              <Text style={styles.sectionLabel}>LOCAL GROUP STATE</Text>
              {groups.length === 0 ? (
                <View style={styles.emptyPanel}>
                  <Text style={styles.emptyTitle}>No private groups yet.</Text>
                  <Text style={styles.emptyText}>Create one here, then add exact verified devices.</Text>
                </View>
              ) : (
                groups.map((group) => (
                  <Pressable
                    accessibilityHint="Opens encrypted group history and membership"
                    accessibilityLabel={`Group with ${group.memberCount} devices at epoch ${group.epoch}`}
                    accessibilityRole="button"
                    key={hex(group.groupId)}
                    onPress={() => openGroup(group)}
                    style={({ pressed }) => [styles.conversationRow, pressed ? styles.pressed : null]}
                  >
                    <View style={styles.avatar}>
                      <Text style={styles.avatarText}>{hex(group.groupId).slice(0, 2).toUpperCase()}</Text>
                    </View>
                    <View style={styles.conversationCopy}>
                      <Text style={styles.conversationName}>Group {hex(group.groupId).slice(0, 10)}</Text>
                      <Text style={styles.conversationMeta}>
                        EPOCH {group.epoch} · {group.memberCount} DEVICE
                        {group.memberCount === 1 ? '' : 'S'}
                      </Text>
                    </View>
                    <Text style={styles.chevron}>→</Text>
                  </Pressable>
                ))
              )}
              {error ? <StatusNotice error text={error} /> : null}
            </ScrollView>
          ) : screen === 'group' && selectedGroupId ? (
            <ScrollView contentContainerStyle={styles.screenContent} keyboardShouldPersistTaps="handled">
              <View style={styles.topRow}>
                <PrimaryButton label="Back to groups" onPress={() => setScreen('groups')} quiet />
                <Text style={styles.eyebrow}>ENCRYPTED GROUP</Text>
              </View>
              <Text accessibilityRole="header" style={styles.title}>
                Group {hex(selectedGroupId).slice(0, 10)}
              </Text>
              <Text style={styles.monoCaption}>
                EPOCH {selectedGroup?.epoch ?? '—'} · {selectedGroup?.memberCount ?? '—'} VERIFIED DEVICES
              </Text>
              {groupDetails ? (
                <Text style={styles.monoCaption}>
                  TREE {hex(groupDetails.treeHash).slice(0, 12)}… · BASELINE{' '}
                  {hex(groupDetails.checkpointHash).slice(0, 12)}…
                </Text>
              ) : null}
              <View style={styles.newContactPanel}>
                <Text style={styles.panelKicker}>ADD ONE VERIFIED DEVICE</Text>
                <Text style={styles.bodyCopy}>
                  Enter the exact username, then scan that specific device’s signed package.
                </Text>
                <Field
                  label="Exact username"
                  onChangeText={setGroupUsername}
                  placeholder="person_name"
                  value={groupUsername}
                />
                <PrimaryButton
                  disabled={!groupUsername.trim()}
                  label="Scan device package"
                  onPress={scanGroupKeyPackage}
                />
              </View>
              <Text style={styles.sectionLabel}>MESH-OWNED MEMBERSHIP</Text>
              {groupDetails ? (
                <View style={styles.deviceList}>
                  {groupDetails.members.map((member) => (
                    <View key={`${hex(member.accountId)}-${hex(member.deviceId)}`} style={styles.deviceRow}>
                      <View style={styles.deviceCopy}>
                        <Text style={styles.deviceTitle}>
                          {member.local ? 'This device' : `Member leaf ${member.leaf}`}
                        </Text>
                        <Text style={styles.monoCaption}>
                          ACCOUNT {hex(member.accountId).slice(0, 12)}… · DEVICE{' '}
                          {hex(member.deviceId).slice(0, 12)}…
                        </Text>
                        <Text style={styles.monoCaption}>
                          DIRECTORY {member.directorySequence} · {member.witnessCount} WITNESSES
                        </Text>
                      </View>
                      {!member.local ? (
                        <PrimaryButton
                          label="Remove from group"
                          onPress={() => removeFromGroup(member.accountId, member.deviceId)}
                          quiet
                        />
                      ) : null}
                    </View>
                  ))}
                </View>
              ) : (
                <View style={styles.emptyPanel}>
                  <Text style={styles.emptyText}>Loading the signed member summary…</Text>
                </View>
              )}
              <Text style={styles.sectionLabel}>ENCRYPTED HISTORY</Text>
              {groupHistory.length === 0 ? (
                <View style={styles.emptyPanel}>
                  <Text style={styles.emptyText}>No visible group messages yet.</Text>
                </View>
              ) : (
                groupHistory.map((message, index) => (
                  <View
                    accessibilityLabel={`${message.direction === 'sent' ? 'Sent' : 'Received'} group message: ${message.body}`}
                    key={`${message.epoch}-${hex(message.senderDeviceId)}-${index}`}
                    style={[
                      styles.message,
                      message.direction === 'sent' ? styles.messageSent : styles.messageReceived,
                    ]}
                  >
                    <Text style={styles.messageBody}>{message.body}</Text>
                    <Text style={styles.messageMeta}>
                      EPOCH {message.epoch} · {message.direction === 'sent' ? 'YOU' : hex(message.senderDeviceId).slice(0, 10)} ·{' '}
                      {new Date(message.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </Text>
                  </View>
                ))
              )}
              <View style={styles.composerRow}>
                <TextInput
                  accessibilityLabel="Group message"
                  multiline
                  onChangeText={setGroupComposer}
                  placeholder="Write to every current member"
                  placeholderTextColor="#777365"
                  style={styles.composer}
                  value={groupComposer}
                />
                <PrimaryButton
                  disabled={!groupComposer.trim()}
                  label="Send"
                  onPress={sendGroupText}
                />
              </View>
              {error ? <StatusNotice error text={error} /> : null}
            </ScrollView>
          ) : screen === 'scanner' ? (
            <View style={styles.cameraScreen}>
              <View style={styles.topRowPadded}>
                <PrimaryButton
                  label="Cancel scan"
                  onPress={() =>
                    setScreen(
                      scanMode === 'link-request'
                        ? 'devices'
                        : scanMode === 'link-authorization'
                          ? 'link-device'
                          : scanMode === 'group-key-package'
                            ? 'group'
                            : 'home',
                    )
                  }
                  quiet
                />
                <Text style={styles.eyebrow}>
                  {scanMode === 'contact'
                    ? 'CONTACT SCANNER'
                    : scanMode === 'group-key-package'
                      ? 'GROUP DEVICE SCANNER'
                      : 'DEVICE LINK SCANNER'}
                </Text>
              </View>
              {!cameraPermission?.granted ? (
                <View style={styles.permissionPanel}>
                  <Text accessibilityRole="header" style={styles.title}>
                    Camera access is only used for Whatsdown QR codes.
                  </Text>
                  <Text style={styles.bodyCopy}>No frames are uploaded or stored.</Text>
                  <PrimaryButton label="Allow camera" onPress={() => void requestCameraPermission()} />
                </View>
              ) : scannedProfile ? (
                <ScrollView contentContainerStyle={styles.screenContent}>
                  <StatusNotice text="Contact code captured and validated by the Mesh core." />
                  <Field
                    label="First message"
                    multiline
                    onChangeText={setFirstMessage}
                    placeholder="Say hello without sharing more than you mean to."
                    value={firstMessage}
                  />
                  <PrimaryButton
                    label="Send encrypted request"
                    onPress={() => startWithProfile(scannedProfile, firstMessage)}
                  />
                  <PrimaryButton label="Scan again" onPress={() => setScannedProfile(null)} quiet />
                </ScrollView>
              ) : scannedLinkRequest ? (
                <ScrollView contentContainerStyle={styles.screenContent}>
                  <StatusNotice text="Link request validated by the Mesh core." />
                  <Text accessibilityRole="header" style={styles.title}>
                    Do these codes match?
                  </Text>
                  <Text style={styles.sas}>{linkSas}</Text>
                  <Text style={styles.bodyCopy}>
                    Confirm the same code is visible on the new device before signing.
                  </Text>
                  <PrimaryButton label="Authorize this device" onPress={authorizeScannedDevice} />
                  <PrimaryButton
                    label="Reject and scan again"
                    onPress={() => setScannedLinkRequest(null)}
                    quiet
                  />
                </ScrollView>
              ) : (
                <CameraView
                  barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                  onBarcodeScanned={onQrScanned}
                  style={styles.camera}
                >
                  <View pointerEvents="none" style={styles.reticle}>
                    <View style={styles.reticleInner} />
                    <Text style={styles.cameraLabel}>
                      {scanMode === 'group-key-package'
                        ? 'CENTER THE DEVICE PACKAGE'
                        : 'CENTER THE CONTACT CODE'}
                    </Text>
                  </View>
                </CameraView>
              )}
              {error ? <StatusNotice error text={error} /> : null}
            </View>
          ) : screen === 'chat' && selected ? (
            <View style={styles.flex}>
              <View style={styles.chatHeader}>
                <PrimaryButton label="Back to conversations" onPress={() => setScreen('home')} quiet />
                <View style={styles.chatIdentity}>
                  <Text accessibilityRole="header" style={styles.chatTitle}>
                    @{selected.username}
                  </Text>
                  <Text style={styles.monoCaption}>
                    {selected.verified ? 'VERIFIED' : 'NOT YET VERIFIED'} ·{' '}
                    {selected.safetyNumber.slice(0, 12)}…
                  </Text>
                </View>
              </View>
              {selected.requestPending ? (
                <View style={styles.warningPanel}>
                  <Text style={styles.warningTitle}>Message request</Text>
                  <Text style={styles.warningBody}>Replying is disabled until you accept.</Text>
                  <PrimaryButton label="Accept request" onPress={() => updatePolicy(1)} />
                </View>
              ) : null}
              {selected.keyChanged ? (
                <StatusNotice error text="Security keys changed. Compare the safety number again." />
              ) : null}
              <FlatList
                contentContainerStyle={styles.messageList}
                data={history}
                keyExtractor={(message) => message.messageId.join('.')}
                ListEmptyComponent={<Text style={styles.emptyText}>No visible messages yet.</Text>}
                renderItem={({ item }) => (
                  <View
                    accessibilityLabel={`${item.direction === 'sent' ? 'Sent' : 'Received'} message: ${item.body}`}
                    style={[
                      styles.message,
                      item.direction === 'sent' ? styles.messageSent : styles.messageReceived,
                    ]}
                  >
                    <Text style={styles.messageBody}>{item.body}</Text>
                    <Text style={styles.messageMeta}>
                      {new Date(item.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                      {item.disappearingSeconds ? ' · DISAPPEARS' : ''}
                    </Text>
                  </View>
                )}
              />
              <View style={styles.policyStrip}>
                <ScrollView horizontal showsHorizontalScrollIndicator={false}>
                  <PrimaryButton
                    label={selected.blocked ? 'Unblock' : 'Block'}
                    onPress={() => updatePolicy(selected.blocked ? 3 : 2)}
                    quiet
                  />
                  <PrimaryButton label="Mark safety number verified" onPress={() => updatePolicy(4)} quiet />
                  {disappearingOptions.map((option) => (
                    <PrimaryButton
                      key={option.value}
                      label={`Disappear: ${option.label}`}
                      onPress={() => updatePolicy(5, option.value)}
                      quiet={selected.disappearingSeconds !== option.value}
                    />
                  ))}
                </ScrollView>
              </View>
              <View style={styles.composerRow}>
                <TextInput
                  accessibilityLabel="Message"
                  editable={!selected.blocked && !selected.requestPending}
                  multiline
                  onChangeText={setComposer}
                  placeholder={selected.requestPending ? 'Accept this request to reply' : 'Write a message'}
                  placeholderTextColor="#777365"
                  style={styles.composer}
                  value={composer}
                />
                <PrimaryButton
                  disabled={!composer.trim() || selected.blocked || selected.requestPending}
                  label="Send"
                  onPress={sendMessage}
                />
              </View>
            </View>
          ) : (
            <ScrollView contentContainerStyle={styles.home} keyboardShouldPersistTaps="handled">
              <View style={styles.homeHeader}>
                <View>
                  <Text style={styles.eyebrow}>WHATSDOWN / ENCRYPTED</Text>
                  <Text accessibilityRole="header" style={styles.title}>
                    Conversations
                  </Text>
                </View>
                <View style={styles.headerActions}>
                  <PrimaryButton label="My QR" onPress={() => setScreen('account')} quiet />
                  <PrimaryButton label="Groups" onPress={openGroups} quiet />
                  <PrimaryButton label="Devices" onPress={openDevices} quiet />
                  <PrimaryButton label="Scan" onPress={() => openScanner('contact')} quiet />
                </View>
              </View>
              <View style={styles.statusLine}>
                <View style={styles.statusDot} />
                <Text style={styles.statusText}>{status}</Text>
                <PrimaryButton label="Sync" onPress={() => void synchronize()} quiet />
              </View>
              {error ? <StatusNotice error text={error} /> : null}
              <View style={styles.newContactPanel}>
                <Text style={styles.panelKicker}>EXACT USERNAME</Text>
                <Text style={styles.panelTitle}>Start a private line</Text>
                <Field
                  label="Username"
                  onChangeText={setContactUsername}
                  placeholder="person_name"
                  value={contactUsername}
                />
                <Field
                  label="First message"
                  multiline
                  onChangeText={setFirstMessage}
                  placeholder="This arrives as a message request."
                  value={firstMessage}
                />
                <PrimaryButton
                  disabled={!contactUsername.trim() || !firstMessage.trim()}
                  label="Resolve and encrypt"
                  onPress={startByUsername}
                />
              </View>
              <Text style={styles.sectionLabel}>LOCAL CONVERSATIONS</Text>
              {conversations.length === 0 ? (
                <View style={styles.emptyPanel}>
                  <Text style={styles.emptyTitle}>No conversation metadata to show.</Text>
                  <Text style={styles.emptyText}>Scan a code or use an exact username to begin.</Text>
                </View>
              ) : (
                conversations.map((conversation) => (
                  <Pressable
                    accessibilityHint="Opens encrypted message history"
                    accessibilityLabel={`Conversation with ${conversation.username}${conversation.requestPending ? ', message request pending' : ''}`}
                    accessibilityRole="button"
                    key={conversation.conversationId.join('.')}
                    onPress={() => openConversation(conversation)}
                    style={({ pressed }) => [styles.conversationRow, pressed ? styles.pressed : null]}
                  >
                    <View style={styles.avatar}>
                      <Text style={styles.avatarText}>{conversation.username.slice(0, 2).toUpperCase()}</Text>
                    </View>
                    <View style={styles.conversationCopy}>
                      <Text style={styles.conversationName}>@{conversation.username}</Text>
                      <Text style={styles.conversationMeta}>
                        {conversation.requestPending
                          ? 'MESSAGE REQUEST'
                          : conversation.keyChanged
                            ? 'KEY CHANGE — VERIFY'
                            : conversation.verified
                              ? 'SAFETY NUMBER VERIFIED'
                              : 'ENCRYPTED SESSION'}
                      </Text>
                    </View>
                    <Text style={styles.chevron}>→</Text>
                  </Pressable>
                ))
              )}
              <Text style={styles.finePrint}>
                Push alerts contain only a generic encrypted-activity wakeup. Sender and message text are
                fetched after unlock.
              </Text>
            </ScrollView>
          )}
        </KeyboardAvoidingView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  safeArea: { backgroundColor: colors.background, flex: 1 },
  loading: {
    alignItems: 'center',
    backgroundColor: colors.background,
    flex: 1,
    gap: 18,
    justifyContent: 'center',
  },
  loadingText: { color: colors.muted, fontFamily: 'IBMPlexMono_400Regular', fontSize: 12 },
  onboarding: { flexGrow: 1, justifyContent: 'center', padding: 28 },
  screenContent: { flexGrow: 1, gap: 22, padding: 24 },
  home: { gap: 20, padding: 20, paddingBottom: 56 },
  eyebrow: {
    color: colors.amber,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 11,
    letterSpacing: 1.6,
  },
  heroTitle: {
    color: colors.paper,
    fontFamily: 'Newsreader_600SemiBold',
    fontSize: 48,
    letterSpacing: -1.7,
    lineHeight: 49,
    marginTop: 18,
  },
  heroBody: {
    color: colors.muted,
    fontFamily: 'Newsreader_400Regular',
    fontSize: 20,
    lineHeight: 28,
    marginTop: 20,
  },
  title: {
    color: colors.paper,
    fontFamily: 'Newsreader_600SemiBold',
    fontSize: 38,
    letterSpacing: -1,
    lineHeight: 41,
  },
  bodyCopy: { color: colors.muted, fontFamily: 'Newsreader_400Regular', fontSize: 18, lineHeight: 25 },
  rule: { backgroundColor: colors.amber, height: 2, marginVertical: 28, width: 72 },
  field: { gap: 8 },
  fieldLabel: {
    color: colors.paper,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 11,
    letterSpacing: 0.8,
    textTransform: 'uppercase',
  },
  input: {
    backgroundColor: colors.panel,
    borderColor: colors.line,
    borderRadius: 3,
    borderWidth: 1,
    color: colors.paper,
    fontFamily: 'Newsreader_400Regular',
    fontSize: 19,
    minHeight: 52,
    paddingHorizontal: 15,
    paddingVertical: 12,
  },
  inputMultiline: { minHeight: 92, textAlignVertical: 'top' },
  button: {
    alignItems: 'center',
    borderRadius: 3,
    justifyContent: 'center',
    minHeight: 48,
    paddingHorizontal: 16,
  },
  buttonPrimary: { backgroundColor: colors.amber },
  buttonQuiet: { backgroundColor: colors.panelRaised, borderColor: colors.line, borderWidth: 1 },
  buttonText: {
    color: colors.background,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 12,
    letterSpacing: 0.5,
    textTransform: 'uppercase',
  },
  buttonQuietText: { color: colors.paper },
  pressed: { opacity: 0.68 },
  disabled: { opacity: 0.38 },
  finePrint: {
    color: colors.muted,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 10,
    lineHeight: 16,
    marginTop: 10,
  },
  notice: {
    backgroundColor: colors.amberDark,
    borderLeftColor: colors.amber,
    borderLeftWidth: 3,
    padding: 14,
  },
  noticeError: { backgroundColor: '#4A2320', borderLeftColor: colors.red },
  noticeText: { color: colors.paper, fontFamily: 'IBMPlexMono_400Regular', fontSize: 11, lineHeight: 17 },
  noticeErrorText: { color: '#FFD0CC' },
  topRow: { alignItems: 'center', flexDirection: 'row', justifyContent: 'space-between' },
  topRowPadded: {
    alignItems: 'center',
    flexDirection: 'row',
    justifyContent: 'space-between',
    padding: 16,
  },
  qrFrame: { alignItems: 'center', backgroundColor: colors.paper, padding: 18 },
  monoCaption: {
    color: colors.muted,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 10,
    letterSpacing: 0.8,
    lineHeight: 16,
  },
  sas: {
    color: colors.amber,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 28,
    letterSpacing: 4,
    textAlign: 'center',
  },
  cameraScreen: { backgroundColor: colors.background, flex: 1 },
  camera: { flex: 1 },
  reticle: { alignItems: 'center', flex: 1, gap: 24, justifyContent: 'center' },
  reticleInner: { borderColor: colors.amber, borderWidth: 2, height: 246, width: 246 },
  cameraLabel: {
    backgroundColor: colors.background,
    color: colors.amber,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 11,
    letterSpacing: 1,
    padding: 10,
  },
  permissionPanel: { flex: 1, gap: 20, justifyContent: 'center', padding: 28 },
  homeHeader: { alignItems: 'flex-end', flexDirection: 'row', justifyContent: 'space-between' },
  headerActions: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, justifyContent: 'flex-end' },
  statusLine: {
    alignItems: 'center',
    borderBottomColor: colors.line,
    borderBottomWidth: 1,
    borderTopColor: colors.line,
    borderTopWidth: 1,
    flexDirection: 'row',
    gap: 9,
    paddingVertical: 10,
  },
  statusDot: { backgroundColor: colors.green, borderRadius: 4, height: 7, width: 7 },
  statusText: { color: colors.muted, flex: 1, fontFamily: 'IBMPlexMono_400Regular', fontSize: 10 },
  newContactPanel: { backgroundColor: colors.panel, gap: 14, padding: 18 },
  panelKicker: {
    color: colors.amber,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 10,
    letterSpacing: 1.2,
  },
  panelTitle: { color: colors.paper, fontFamily: 'Newsreader_600SemiBold', fontSize: 27 },
  sectionLabel: {
    color: colors.muted,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 10,
    letterSpacing: 1.3,
    marginTop: 8,
  },
  emptyPanel: { borderColor: colors.line, borderStyle: 'dashed', borderWidth: 1, gap: 8, padding: 24 },
  emptyTitle: { color: colors.paper, fontFamily: 'Newsreader_600SemiBold', fontSize: 20 },
  emptyText: { color: colors.muted, fontFamily: 'Newsreader_400Regular', fontSize: 16, lineHeight: 22 },
  deviceList: { borderTopColor: colors.line, borderTopWidth: 1 },
  deviceRow: {
    alignItems: 'center',
    borderBottomColor: colors.line,
    borderBottomWidth: 1,
    flexDirection: 'row',
    gap: 12,
    minHeight: 78,
    paddingVertical: 12,
  },
  deviceCopy: { flex: 1, gap: 5 },
  deviceTitle: { color: colors.paper, fontFamily: 'Newsreader_600SemiBold', fontSize: 20 },
  conversationRow: {
    alignItems: 'center',
    borderBottomColor: colors.line,
    borderBottomWidth: 1,
    flexDirection: 'row',
    gap: 14,
    minHeight: 76,
    paddingVertical: 12,
  },
  avatar: {
    alignItems: 'center',
    backgroundColor: colors.amberDark,
    borderRadius: 24,
    height: 48,
    justifyContent: 'center',
    width: 48,
  },
  avatarText: { color: colors.amber, fontFamily: 'IBMPlexMono_400Regular', fontSize: 12 },
  conversationCopy: { flex: 1, gap: 5 },
  conversationName: { color: colors.paper, fontFamily: 'Newsreader_600SemiBold', fontSize: 21 },
  conversationMeta: {
    color: colors.muted,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 9,
    letterSpacing: 0.7,
  },
  chevron: { color: colors.amber, fontFamily: 'Newsreader_400Regular', fontSize: 26 },
  chatHeader: {
    alignItems: 'center',
    borderBottomColor: colors.line,
    borderBottomWidth: 1,
    flexDirection: 'row',
    gap: 14,
    padding: 14,
  },
  chatIdentity: { flex: 1 },
  chatTitle: { color: colors.paper, fontFamily: 'Newsreader_600SemiBold', fontSize: 25 },
  warningPanel: { backgroundColor: colors.amberDark, gap: 8, padding: 16 },
  warningTitle: { color: colors.amber, fontFamily: 'Newsreader_600SemiBold', fontSize: 20 },
  warningBody: { color: colors.paper, fontFamily: 'Newsreader_400Regular', fontSize: 16 },
  messageList: { gap: 10, padding: 16 },
  message: { borderRadius: 4, maxWidth: '84%', padding: 13 },
  messageSent: { alignSelf: 'flex-end', backgroundColor: colors.amberDark },
  messageReceived: { alignSelf: 'flex-start', backgroundColor: colors.panelRaised },
  messageBody: { color: colors.paper, fontFamily: 'Newsreader_400Regular', fontSize: 18, lineHeight: 24 },
  messageMeta: {
    color: colors.muted,
    fontFamily: 'IBMPlexMono_400Regular',
    fontSize: 8,
    marginTop: 6,
  },
  policyStrip: { borderTopColor: colors.line, borderTopWidth: 1, padding: 8 },
  composerRow: {
    alignItems: 'flex-end',
    borderTopColor: colors.line,
    borderTopWidth: 1,
    flexDirection: 'row',
    gap: 8,
    padding: 10,
  },
  composer: {
    backgroundColor: colors.panel,
    borderColor: colors.line,
    borderRadius: 3,
    borderWidth: 1,
    color: colors.paper,
    flex: 1,
    fontFamily: 'Newsreader_400Regular',
    fontSize: 17,
    maxHeight: 120,
    minHeight: 48,
    paddingHorizontal: 13,
    paddingVertical: 10,
  },
});
