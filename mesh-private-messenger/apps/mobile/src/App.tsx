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
  create_account_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export,
} from '../modules/mesh-messenger';
import {
  accountRequest,
  Conversation,
  HistoryMessage,
  parseConversations,
  parseHistory,
  peerRequest,
  policyRequest,
  profileFromQr,
  profileQrValue,
  startRequest,
  utf8,
} from './codec';
import { registerDirectory, resolveContact, submitEnvelope, synchronizeMailbox } from './network';
import { listenForGenericWakeups } from './push';
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

type Screen = 'home' | 'account' | 'scanner' | 'chat';

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
  const [username, setUsername] = useState('');
  const [contactUsername, setContactUsername] = useState('');
  const [firstMessage, setFirstMessage] = useState('');
  const [composer, setComposer] = useState('');
  const [scannedProfile, setScannedProfile] = useState<Uint8Array | null>(null);
  const [busy, setBusy] = useState(true);
  const [status, setStatus] = useState('Opening encrypted storage…');
  const [error, setError] = useState('');

  const selected = conversations.find((conversation) => conversation.conversationId.join('.') === selectedId);

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

  async function synchronize(): Promise<void> {
    if (!profile) return;
    setError('');
    setStatus('Checking the encrypted mailbox…');
    try {
      await synchronizeMailbox(databasePath);
      const next = await refreshConversations();
      const active = next.find((conversation) => conversation.conversationId.join('.') === selectedId);
      if (active) await refreshHistory(active);
      setStatus('Mailbox is current');
    } catch (caught) {
      setError(friendlyError(caught));
      setStatus('Offline — messages stay queued on the server');
    }
  }

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const loaded = await load_profile_export(utf8(databasePath));
        if (cancelled) return;
        setProfile(loaded);
        await refreshConversations();
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
  }, [profile, selectedId]);

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
      await registerDirectory(databasePath);
      setProfile(created);
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
      const envelope = await start_conversation_export(startRequest(databasePath, contact, body.trim()));
      await submitEnvelope(envelope);
      await refreshConversations();
      setFirstMessage('');
      setScannedProfile(null);
      setStatus('Encrypted message queued');
      setScreen('home');
    });
  }

  function startByUsername(): void {
    const target = contactUsername.trim().toLowerCase();
    void perform('Resolving exact username…', async () => {
      const contact = await resolveContact(target);
      const envelope = await start_conversation_export(
        startRequest(databasePath, contact, firstMessage.trim()),
      );
      await submitEnvelope(envelope);
      await refreshConversations();
      setContactUsername('');
      setFirstMessage('');
      setStatus('Encrypted message queued');
    });
  }

  function sendMessage(): void {
    if (!selected || !composer.trim()) return;
    void perform('Encrypting message…', async () => {
      const currentProfile = await resolveContact(selected.username);
      const envelope = await send_message_export(
        startRequest(databasePath, currentProfile, composer.trim()),
      );
      await submitEnvelope(envelope);
      setComposer('');
      await refreshHistory(selected);
      setStatus('Encrypted message queued');
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

  function onQrScanned(result: BarcodeScanningResult): void {
    try {
      setScannedProfile(profileFromQr(result.data));
      setError('');
    } catch (caught) {
      setError(friendlyError(caught));
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
          {onboarding ? (
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
            </ScrollView>
          ) : screen === 'scanner' ? (
            <View style={styles.cameraScreen}>
              <View style={styles.topRowPadded}>
                <PrimaryButton label="Cancel scan" onPress={() => setScreen('home')} quiet />
                <Text style={styles.eyebrow}>CONTACT SCANNER</Text>
              </View>
              {!cameraPermission?.granted ? (
                <View style={styles.permissionPanel}>
                  <Text accessibilityRole="header" style={styles.title}>
                    Camera access is only used for contact codes.
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
              ) : (
                <CameraView
                  barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
                  onBarcodeScanned={onQrScanned}
                  style={styles.camera}
                >
                  <View pointerEvents="none" style={styles.reticle}>
                    <View style={styles.reticleInner} />
                    <Text style={styles.cameraLabel}>CENTER THE CONTACT CODE</Text>
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
                  <PrimaryButton label="Scan" onPress={() => setScreen('scanner')} quiet />
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
  headerActions: { flexDirection: 'row', gap: 8 },
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
