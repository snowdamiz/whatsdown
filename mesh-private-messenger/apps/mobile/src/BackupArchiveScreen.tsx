import { useEffect, useRef, useState } from 'react';
import { Text, TextInput, View } from 'react-native';
import { ScrollView } from './scroll';
import { space, useTheme } from './theme';
import { Button, Card, Notice } from './ui';
import { createBackupArchiveController, type BackupArchiveController, type BackupArchivePorts, type BackupArchiveSnapshot, type BackupOverviewView, type BackupFileView } from './backup-import';

export type BackupArchiveLabels = Readonly<{
  title: string; importTitle: string; chooseFile: string; choosing: string; selectedFile: string;
  recoveryCode: string; codeHint: string; preview: string; previewing: string; confirmImport: string; importing: string;
  imported: string; alreadyPresent: string; cancelImport: string; readOnlyNote: string; exclusions: string;
  archivesTitle: string; loadingArchives: string; refresh: string; emptyArchives: string; open: string;
  remove: string; confirmRemove: string; cancelRemove: string; removalNotice: string; removing: string;
  reading: string; conversations: string; unnamedConversation: string; backToArchives: string; backToConversations: string;
  previous: string; next: string; attachmentOmitted: string; sent: string; received: string;
  expired: string; error: string; previewError: string; close: string;
  includedCount: string; candidateCount: string; omittedTimed: string; omittedUnknown: string;
  omittedNontext: string; omittedEmpty: string; attachmentMessages: string;
  filesTitle: string; totalFiles: string; includedFiles: string; unavailableFiles: string; expiredFiles: string;
  unsupportedFiles: string; aboveProfileFiles: string; requiredFiles: string; allowedFileOmissions: string; contentExclusions: string;
  saveFile: string; cancelFile: string; savingFile: string; savedFile: string; failedFile: string;
  fileUnavailable: string; fileExpired: string; fileUnsupported: string; fileAboveProfile: string;
  fileNumber(number: number): string; fileSize(size: number): string; fileProgress(loaded: number, total: number): string;
  createdAt(value: string): string; messages(count: number): string; page(offset: number, count: number): string; rawTime(value: string): string;
}>;
export type BackupArchiveScreenProps = BackupArchivePorts & { labels: BackupArchiveLabels; locale?: string; onClose(): void };
function sameRequest(left: BackupArchivePorts, right: BackupArchivePorts) {
  return left.scope === right.scope && left.services === right.services && left.action.databasePath === right.action.databasePath &&
    left.action.expectedProfile === right.action.expectedProfile && left.chooseBackupSource === right.chooseBackupSource && left.discardBackupSource === right.discardBackupSource && left.saveAttachmentFile === right.saveAttachmentFile;
}
function archiveTime(value: string, labels: BackupArchiveLabels, locale?: string) {
  const milliseconds = BigInt(value);
  return milliseconds <= 8_640_000_000_000_000n ? new Date(Number(milliseconds)).toLocaleString(locale) : labels.rawTime(value);
}
export function BackupArchiveScreen(props: BackupArchiveScreenProps) {
  const { scope, services, action, chooseBackupSource, discardBackupSource, saveAttachmentFile, labels, locale, onClose } = props;
  const { type, colors } = useTheme();
  const owner = useRef<{ request: BackupArchivePorts; controller: BackupArchiveController } | null>(null);
  const [display, setDisplay] = useState<{ request: BackupArchivePorts; state: BackupArchiveSnapshot } | null>(null);
  const state = display && sameRequest(display.request, props) ? display.state : null;
  useEffect(() => {
    const request = { scope, services, action: { databasePath: action.databasePath, expectedProfile: action.expectedProfile }, chooseBackupSource, discardBackupSource, saveAttachmentFile };
    let controller: BackupArchiveController;
    try { controller = createBackupArchiveController(request); }
    catch { setDisplay({ request, state: { kind: 'closed' } }); return; }
    let alive = true;
    owner.current = { request, controller };
    const update = () => { if (alive && owner.current?.controller === controller) setDisplay({ request, state: controller.getSnapshot() }); };
    const unsubscribe = controller.subscribe(update); update();
    void controller.refreshArchives().catch(() => controller.dispose());
    return () => {
      alive = false; unsubscribe(); if (owner.current?.controller === controller) owner.current = null; controller.dispose();
    };
  }, [scope, services, action.databasePath, action.expectedProfile, chooseBackupSource, discardBackupSource, saveAttachmentFile]);
  function run(body: (controller: BackupArchiveController) => unknown) {
    const entry = owner.current; if (!entry || !sameRequest(entry.request, props)) return;
    try { void Promise.resolve(body(entry.controller)).catch(() => {}); } catch { /* A stale rendered action has no authority. */ }
  }
  async function close() {
    const entry = owner.current;
    if (!entry || state?.kind === 'closed') { onClose(); return; }
    if (!sameRequest(entry.request, props)) return;
    try {
      entry.controller.closeReader();
      const cancelled = await entry.controller.cancelImport();
      if (owner.current === entry && cancelled) onClose();
    } catch { /* Native owner loss clears the view before its event arrives. */ }
  }
  function metadata(overview: BackupOverviewView) {
    const counts = [
      [labels.includedCount, overview.includedCount], [labels.candidateCount, overview.candidateCount],
      [labels.omittedTimed, overview.omittedTimed], [labels.omittedUnknown, overview.omittedUnknown],
      [labels.omittedNontext, overview.omittedNontext], [labels.omittedEmpty, overview.omittedEmpty],
      [labels.attachmentMessages, overview.attachmentMessages],
    ] as const;
    const fileCounts: readonly (readonly [string, number])[] = overview.files.kind === 'content' ? [
      [labels.totalFiles, overview.files.counts.total], [labels.includedFiles, overview.files.counts.included],
      [labels.unavailableFiles, overview.files.counts.unavailable], [labels.expiredFiles, overview.files.counts.expired],
      [labels.unsupportedFiles, overview.files.counts.unsupported], [labels.aboveProfileFiles, overview.files.counts.aboveProfile],
    ] : [];
    return <View style={{ gap: space[2] }}>
      <Text style={type.bodyStrong}>{labels.createdAt(archiveTime(overview.createdAt, labels, locale))}</Text>
      {counts.map(([label, count], index) => <Text key={index} style={type.footnote}>{label}: {count.toLocaleString(locale)}</Text>)}
      {overview.files.kind === 'content' ? <View style={{ gap: space[2] }}>
        <Text style={type.bodyStrong}>{labels.filesTitle}</Text>
        <Text style={type.footnote}>{overview.files.policy === 'require' ? labels.requiredFiles : labels.allowedFileOmissions}</Text>
        {fileCounts.map(([label, count], index) => <Text key={index} style={type.footnote}>{label}: {count.toLocaleString(locale)}</Text>)}
      </View> : null}
      <Text style={type.footnote}>{overview.files.kind === 'content' ? labels.contentExclusions : labels.exclusions}</Text>
    </View>;
  }
  const busy = state?.kind === 'active' && (state.import.kind === 'importing' || state.removing !== null);
  function attachment(file: BackupFileView, ordinal: number, loading: boolean) {
    if (file.kind === 'omitted') {
      const reasons = { unavailable: labels.fileUnavailable, expired: labels.fileExpired, unsupported: labels.fileUnsupported, aboveProfile: labels.fileAboveProfile };
      return <View key={file.slot} style={{ gap: space[2] }}>
        <Text style={type.bodyStrong}>{labels.fileNumber(file.slot + 1)}</Text>
        <Text style={type.footnote}>{reasons[file.reason]}</Text>
      </View>;
    }
    const status = state?.kind === 'active' && state.file.kind !== 'idle' && state.file.file === file ? state.file : null;
    const working = status?.kind === 'loading' || status?.kind === 'saving';
    return <View key={file.slot} style={{ gap: space[2] }}>
      <Text style={type.bodyStrong}>{file.filename || labels.fileNumber(file.slot + 1)}</Text>
      <Text style={type.footnote}>{file.mimeType} · {labels.fileSize(file.size)}</Text>
      {status?.kind === 'loading' ? <Text style={type.footnote}>{labels.fileProgress(status.loaded, file.size)}</Text> : null}
      {status?.kind === 'saving' ? <Notice text={labels.savingFile} /> : null}
      {status?.kind === 'saved' ? <Notice text={labels.savedFile} /> : null}
      {status?.kind === 'failed' ? <Notice tone="error" text={labels.failedFile} /> : null}
      <Button testID={`backup-file-save-${ordinal}-${file.slot}`} label={labels.saveFile} variant="secondary" size="sm" disabled={busy || loading || working} onPress={() => run(controller => controller.saveAttachment(file))} />
      {working ? <Button testID={`backup-file-cancel-${ordinal}-${file.slot}`} label={labels.cancelFile} variant="ghost" size="sm" onPress={() => run(controller => {
        const current = controller.getSnapshot();
        if (current.kind === 'active' && current.file.kind !== 'idle' && current.file.file === file) controller.cancelAttachment();
      })} /> : null}
    </View>;
  }
  let body;
  if (!state) body = <Notice text={labels.loadingArchives} />;
  else if (state.kind === 'closed') body = <Notice tone="warning" text={labels.expired} />;
  else {
    const importing = state.import, reader = state.reader;
    const hasCode = importing.kind === 'selected' || importing.kind === 'previewing' || importing.kind === 'preview';
    body = <>
      <Notice text={labels.readOnlyNote} />
      {state.error ? <Notice tone="error" text={state.error === 'preview' ? labels.previewError : labels.error} /> : null}
      {reader.kind === 'closed' ? <>
        <Text accessibilityRole="header" style={type.title2}>{labels.importTitle}</Text>
        <Button testID="backup-choose" label={labels.chooseFile} icon="file" variant="secondary" disabled={busy || importing.kind === 'choosing'} onPress={() => run(controller => { const current = controller.getSnapshot(); if (current.kind === 'active' && current.import.kind !== 'choosing') return controller.choose(); })} />
        {importing.kind === 'choosing' ? <Notice text={labels.choosing} /> : null}
        {hasCode ? <Card><View style={{ gap: space[3] }}>
          <Text style={type.body}>{labels.selectedFile}</Text>
          <Text style={type.label}>{labels.recoveryCode}</Text>
          <TextInput testID="backup-code" accessibilityLabel={labels.recoveryCode} value={importing.code}
            secureTextEntry autoCapitalize="none" autoCorrect={false} autoComplete="off" textContentType="none" importantForAutofill="no"
            maxLength={4096} editable={!busy} onChangeText={value => run(controller => controller.setRecoveryCode(value))}
            style={[type.input, { backgroundColor: colors.surface, borderColor: colors.line, borderWidth: 1, borderRadius: space[2], padding: space[3] }]} />
          <Text style={type.footnote}>{labels.codeHint}</Text>
          <Button testID="backup-preview" label={labels.preview} disabled={busy || !importing.code || importing.kind === 'previewing'} onPress={() => run(controller => controller.preview())} />
        </View></Card> : null}
        {importing.kind === 'previewing' ? <Notice text={labels.previewing} /> : null}
        {importing.kind === 'preview' ? <Card><View style={{ gap: space[3] }}>
          {metadata(importing.preview.overview)}
          {importing.preview.overview.conversations.map(conversation => <Text key={conversation.key} style={type.body}>
            {conversation.name || labels.unnamedConversation} · {labels.messages(conversation.messageCount)}
          </Text>)}
          <Button testID="backup-confirm-import" label={labels.confirmImport} disabled={busy} onPress={() => run(controller => controller.confirmImport(importing.preview))} />
        </View></Card> : null}
        {importing.kind === 'importing' ? <Notice text={labels.importing} /> : null}
        {importing.kind === 'imported' ? <Notice text={importing.alreadyPresent ? labels.alreadyPresent : labels.imported} /> : null}
        {importing.kind !== 'empty' ? <Button testID="backup-clear-import" label={labels.cancelImport} variant="ghost" disabled={busy} onPress={() => run(controller => controller.cancelImport())} /> : null}
        <View style={{ gap: space[3], marginTop: space[4] }}>
          <Text accessibilityRole="header" style={type.title2}>{labels.archivesTitle}</Text>
          <Button testID="backup-refresh" label={labels.refresh} icon="refresh" variant="ghost" disabled={busy || state.inventory.kind === 'loading'} onPress={() => run(controller => controller.refreshArchives())} />
          {state.inventory.kind === 'loading' ? <Notice text={labels.loadingArchives} /> : null}
          {state.inventory.kind === 'ready' && !state.inventory.rows.length ? <Notice text={labels.emptyArchives} /> : null}
          {state.inventory.rows.map((row, index) => <Card key={row.id}><View style={{ gap: space[2] }}>
            <Text style={type.bodyStrong}>{labels.createdAt(archiveTime(row.createdAt, labels, locale))}</Text>
            <View style={{ flexDirection: 'row', gap: space[3], flexWrap: 'wrap' }}>
              <Button testID={`backup-open-${index}`} label={labels.open} size="sm" variant="secondary" disabled={busy} onPress={() => run(controller => controller.openArchive(row.id))} />
              <Button testID={`backup-remove-${index}`} label={labels.remove} size="sm" variant="danger" disabled={busy} onPress={() => run(controller => controller.requestRemove(row.id))} />
            </View>
          </View></Card>)}
        </View>
      </> : reader.kind === 'loading' ? <Notice text={labels.reading} /> : <>
        <Button testID="backup-back-archives" label={labels.backToArchives} icon="back" variant="ghost" onPress={() => run(controller => controller.closeReader())} />
        <Card>{metadata(reader.overview)}</Card>
        {reader.kind === 'overview' ? <View style={{ gap: space[3] }}>
          <Text accessibilityRole="header" style={type.title2}>{labels.conversations}</Text>
          {reader.overview.conversations.map((conversation, index) => <Card key={conversation.key}><View style={{ gap: space[2] }}>
            <Text style={type.body}>{labels.messages(conversation.messageCount)}</Text>
            <Button testID={`backup-conversation-${index}`} label={conversation.name || labels.unnamedConversation} variant="secondary" onPress={() => run(controller => controller.openConversation(conversation))} />
          </View></Card>)}
        </View> : <View style={{ gap: space[3] }}>
          <Text accessibilityRole="header" style={type.title2}>{reader.conversation.name || labels.unnamedConversation}</Text>
          <Button testID="backup-back-conversations" label={labels.backToConversations} variant="ghost" onPress={() => run(controller => controller.openArchive(reader.overview.id))} />
          {reader.loading ? <Notice text={labels.reading} /> : null}
          {reader.page ? <>
            <Text style={type.caption}>{labels.page(reader.page.offset, reader.page.entries.length)}</Text>
            {reader.page.entries.map(entry => <Card key={entry.ordinal}><View style={{ gap: space[2] }}>
              <Text style={type.caption}>{entry.direction === 1 ? labels.sent : labels.received} · {archiveTime(entry.timestamp, labels, locale)}</Text>
              {entry.text ? <Text style={type.body}>{entry.text}</Text> : null}
              {entry.kind === 'text' ? entry.attachmentOmitted ? <Text style={type.footnote}>{labels.attachmentOmitted}</Text> : null
                : entry.attachments.map(file => attachment(file, entry.ordinal, reader.loading))}
            </View></Card>)}
            <View style={{ flexDirection: 'row', gap: space[3] }}>
              <Button testID="backup-previous" label={labels.previous} variant="secondary" disabled={reader.loading || !reader.canPrevious} onPress={() => run(controller => controller.previousPage())} />
              <Button testID="backup-next" label={labels.next} variant="secondary" disabled={reader.loading || reader.page.nextOffset === null} onPress={() => run(controller => controller.nextPage())} />
            </View>
          </> : null}
        </View>}
      </>}
      {state.removal ? <Card tone="raised"><View style={{ gap: space[3] }}>
        <Notice tone="warning" text={labels.removalNotice} />
        <Text style={type.footnote}>{labels.createdAt(archiveTime(state.removal.createdAt, labels, locale))}</Text>
        <Button testID="backup-confirm-remove" label={labels.confirmRemove} variant="danger" disabled={busy} onPress={() => { const confirmation = state.removal; if (confirmation) run(controller => controller.confirmRemove(confirmation)); }} />
        <Button testID="backup-cancel-remove" label={labels.cancelRemove} variant="ghost" onPress={() => run(controller => controller.cancelRemoval())} />
      </View></Card> : null}
      {state.removing ? <Notice text={labels.removing} /> : null}
    </>;
  }
  return <ScrollView keyboardShouldPersistTaps="handled" contentContainerStyle={{ padding: space[5], gap: space[4] }}>
    <Text accessibilityRole="header" style={type.title}>{labels.title}</Text>
    {body}
    <Button testID="backup-close" label={labels.close} variant="ghost" disabled={busy} onPress={close} />
  </ScrollView>;
}
