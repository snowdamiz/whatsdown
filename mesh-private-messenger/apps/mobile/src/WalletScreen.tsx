import { useEffect, useState } from "react";
import { Clipboard, Linking, ScrollView, Text, View } from "react-native";

import { bountyNotice, bountyProof, formatUnits, type BountyNotice } from "./bounty-notice.ts";
import { loadTrustDetails, onPublicRecordChecked } from "./network";
import { balances, bountyPayout, discoverBounties, moveBounty, pay, pinnedRpc, type Rpc } from "./solana.ts";
import { databasePath } from "./storage";
import { useTheme } from "./theme";
import { Actions, Button, Card, Field, Header, Notice, Page, Row, RowGroup, Section, Toggle, layout } from "./ui";
import {
  base58,
  bountyAddresses,
  createWallet,
  parsePayUrl,
  restoreWallet,
  showPhrase,
  walletAddress,
  walletExists,
  wipeWallet,
  SOL_DECIMALS,
  USDC_DECIMALS,
  type PayRequest,
} from "./wallet.ts";
import {
  answerBountyOffer,
  confirmsPhrase,
  defaultWalletSettings,
  offerBounties,
  pickConfirmation,
  setCollectBounties,
  walletMessage,
  type WalletSettings,
} from "./wallet-settings.ts";
import { loadWalletSettings, saveWalletSettings } from "./wallet-store";

// Settings -> Wallet and Settings -> Network -> "Collect fork bounties" (plan §6.13,
// §10, D13). Addresses and balances come from the pinned RPC providers, never from
// Morse's servers.

const BOUNTY_TEXT =
  "If your phone ever catches Morse showing you a forked key log, the bounty goes to a new address in your wallet, never linked to your account.";
const BOUNTY_FOOTER = "Evidence is filed either way; this only decides whether your phone names an address for the bounty.";
const MOVE_NOTICE =
  "A move is as public as any transfer: anyone can see this bounty address send to the one you enter, and that your wallet address paid the fee, which links the two.";
const PAY_NOTICE =
  "This payment is as public as any on-chain payment: anyone can see your wallet address paid this one. Pay in batches, from a wallet you don’t mind being seen.";

type Balances = { sol: bigint; usdc: bigint };
type Bounty = { index: number; address: string; usdc: bigint | null };
type Phase =
  | { step: "loading" }
  | { step: "none" }
  | { step: "restore"; phrase: string }
  | { step: "phrase"; words: string[] }
  | { step: "confirm"; words: string[]; asked: [number, number]; typed: [string, string] }
  | { step: "offer" }
  | { step: "ready" };

function useWalletSettings(): [WalletSettings, (next: WalletSettings) => Promise<void>] {
  const [settings, setSettings] = useState(defaultWalletSettings);
  useEffect(() => { loadWalletSettings().then(setSettings, () => {}); }, []);
  const save = async (next: WalletSettings) => { setSettings(next); await saveWalletSettings(next); };
  return [settings, save];
}

const usdc = (amount: bigint) => `${formatUnits(amount, USDC_DECIMALS)} USDC`;
const sol = (amount: bigint) => `${formatUnits(amount, SOL_DECIMALS)} SOL`;
const shortAddress = (address: string) => `${address.slice(0, 4)}…${address.slice(-4)}`;
const openLink = (url: string) => { Linking.openURL(url).catch(() => Clipboard.setString(url)); };

// Settings -> Network: the Phase 4 bounty toggle. Off until turned on; needs the wallet.
export function CollectBountiesRow() {
  const [settings, save] = useWalletSettings();
  const [ready, setReady] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => { walletExists().then(setReady, () => setReady(false)); }, []);
  return (
    <Section title="Fork bounties" footer={problem ?? BOUNTY_FOOTER}>
      <RowGroup>
        <Row
          icon="shield"
          title="Collect fork bounties"
          subtitle={ready ? BOUNTY_TEXT : "Needs the in-app wallet: set it up in Settings → Wallet."}
          trailing={
            <Toggle
              label="Collect fork bounties"
              value={settings.collectBounties && ready}
              disabled={!ready && !settings.collectBounties}
              onValueChange={(on) => {
                try { void save(setCollectBounties(settings, ready, on)); setProblem(null); }
                catch (error) { setProblem(walletMessage(error)); }
              }}
            />
          }
        />
      </RowGroup>
    </Section>
  );
}

// The Phase 4 notice, once a proof this phone filed named one of the wallet's
// bounty addresses; follows it until the bounty lands.
export function BountyNoticeCard({ rpc }: { rpc?: Rpc | null }) {
  const { type } = useTheme();
  const [notice, setNotice] = useState<BountyNotice | null>(null);
  useEffect(() => {
    let live = true;
    const refresh = async () => {
      const proof = bountyProof(await loadTrustDetails(databasePath));
      if (!proof) {
        if (live) setNotice(null);
        return;
      }
      const chain = rpc === undefined ? await pinnedRpc() : rpc;
      const payout = proof.landed && !proof.paidElsewhere && proof.finder && chain
        ? await bountyPayout(chain, base58(proof.finder)).catch(() => null)
        : null;
      if (live) setNotice(bountyNotice(proof, payout));
    };
    void refresh().catch(() => {});
    const stop = onPublicRecordChecked(() => void refresh().catch(() => {}));
    return () => { live = false; stop(); };
  }, [rpc]);
  if (!notice) return null;
  return (
    <Card tone="accent">
      <View style={layout.stack}>
        <Text style={type.body}>{notice.text}</Text>
        {notice.details ? <Text style={type.footnote}>Details: {notice.details}</Text> : null}
        {notice.transaction ? (
          <Button label="View the transaction" variant="secondary" size="sm" icon="link" onPress={() => openLink(notice.transaction!)} />
        ) : null}
      </View>
    </Card>
  );
}

export function WalletScreen({ onBack }: { onBack: () => void }) {
  const { type } = useTheme();
  const [settings, save] = useWalletSettings();
  const [phase, setPhase] = useState<Phase>({ step: "loading" });
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [rpc, setRpc] = useState<Rpc | null | undefined>(undefined);
  const [address, setAddress] = useState<string | null>(null);
  const [held, setHeld] = useState<Balances | "unavailable" | null>(null);
  const [bounties, setBounties] = useState<Bounty[]>([]);
  const [phrase, setPhrase] = useState<string[] | null>(null);
  const [move, setMove] = useState<{ index: number; recipient: string; noticed: boolean } | null>(null);
  const [payment, setPayment] = useState<{ url: string; request: PayRequest | null; noticed: boolean } | null>(null);
  const [done, setDone] = useState<{ text: string; signature: string } | null>(null);

  const run = async (label: string, task: () => Promise<void>) => {
    setBusy(label);
    setProblem(null);
    try { await task(); } catch (error) { setProblem(walletMessage(error)); } finally { setBusy(null); }
  };

  const refresh = async (chain: Rpc | null) => {
    const own = await walletAddress();
    setAddress(own);
    const issued = await bountyAddresses();
    setBounties(issued.map((entry) => ({ ...entry, usdc: null })));
    if (!chain) return;
    setHeld(await balances(chain, own).catch(() => "unavailable" as const));
    const counted = await Promise.all(issued.map(async (entry) =>
      ({ ...entry, usdc: await balances(chain, entry.address).then((value) => value.usdc, () => null) })));
    setBounties(counted);
  };

  useEffect(() => {
    void (async () => {
      const chain = await pinnedRpc().catch(() => null);
      // A function passed to a state setter is an updater: wrap the RPC client.
      setRpc(() => chain);
      if (!(await walletExists().catch(() => false))) return setPhase({ step: "none" });
      setPhase({ step: "ready" });
      const kept = await loadWalletSettings();
      if (kept.bountyScanPending && chain) {
        await discoverBounties(chain);
        await save({ ...kept, bountyScanPending: false });
      }
      await refresh(chain);
    })().catch((error) => setProblem(walletMessage(error)));
  }, []);

  // D13: offered once, when the wallet is set up.
  const finishSetup = async (next: WalletSettings) => {
    await save(next);
    setPhase(offerBounties(next, true) ? { step: "offer" } : { step: "ready" });
    await refresh(rpc ?? null);
  };

  const body = (() => {
    if (phase.step === "loading") return <Text style={type.body}>Opening your wallet…</Text>;
    if (phase.step === "none") {
      return (
        <>
          <Text style={type.body}>
            A Solana wallet on this device, for bounties and payments. Only you hold its keys:
            Morse can’t see them or recover them.
          </Text>
          <Actions>
            <Button label="Create a wallet" disabled={busy !== null} onPress={() => void run("Creating…", async () => {
              const words = (await createWallet(12)).split(" ");
              setPhase({ step: "phrase", words });
            })} />
            <Button label="Restore from a recovery phrase" variant="secondary" onPress={() => setPhase({ step: "restore", phrase: "" })} />
          </Actions>
        </>
      );
    }
    if (phase.step === "restore") {
      return (
        <>
          <Field label="Recovery phrase" placeholder="12 or 24 words" multiline value={phase.phrase}
            onChangeText={(value) => setPhase({ step: "restore", phrase: value })} />
          <Actions>
            <Button label="Restore" disabled={busy !== null || !phase.phrase.trim()} onPress={() => void run("Restoring…", async () => {
              await restoreWallet(phase.phrase);
              // It may have handed out bounty addresses on another device.
              const next = { ...defaultWalletSettings, bountyScanPending: true };
              if (rpc) { await discoverBounties(rpc); next.bountyScanPending = false; }
              await finishSetup(next);
            })} />
            <Button label="Cancel" variant="ghost" onPress={() => setPhase({ step: "none" })} />
          </Actions>
        </>
      );
    }
    if (phase.step === "phrase") {
      return (
        <>
          <Notice tone="warning" text="Write these words down, in order, and keep them offline. Anyone with them can take what’s in your wallet, and Morse can’t recover them." />
          <PhraseWords words={phase.words} />
          <Actions>
            <Button label="I wrote them down" onPress={() =>
              setPhase({ step: "confirm", words: phase.words, asked: pickConfirmation(phase.words.length), typed: ["", ""] })} />
          </Actions>
        </>
      );
    }
    if (phase.step === "confirm") {
      const [first, second] = phase.asked;
      return (
        <>
          <Text style={type.body}>Type two of the words back, so you know the copy is right.</Text>
          <Field label={`Word ${first + 1}`} placeholder="" value={phase.typed[0]}
            onChangeText={(value) => setPhase({ ...phase, typed: [value, phase.typed[1]] })} />
          <Field label={`Word ${second + 1}`} placeholder="" value={phase.typed[1]}
            onChangeText={(value) => setPhase({ ...phase, typed: [phase.typed[0], value] })} />
          <Actions>
            <Button label="Confirm" disabled={!confirmsPhrase(phase.words, phase.asked, phase.typed)}
              onPress={() => void run("Saving…", () => finishSetup(defaultWalletSettings))} />
            <Button label="Show the words again" variant="ghost" onPress={() => setPhase({ step: "phrase", words: phase.words })} />
          </Actions>
        </>
      );
    }
    if (phase.step === "offer") {
      return (
        <Card>
          <View style={layout.stack}>
            <Text style={type.headline}>Collect fork bounties?</Text>
            <Text style={type.body}>{BOUNTY_TEXT}</Text>
            <Text style={type.footnote}>{BOUNTY_FOOTER} You can change this in Settings → Network.</Text>
            <Actions>
              <Button label="Turn on" onPress={() => void run("Saving…", async () => { await save(answerBountyOffer(settings, true)); setPhase({ step: "ready" }); })} />
              <Button label="Not now" variant="secondary" onPress={() => void run("Saving…", async () => { await save(answerBountyOffer(settings, false)); setPhase({ step: "ready" }); })} />
            </Actions>
          </View>
        </Card>
      );
    }
    return (
      <>
        <BountyNoticeCard rpc={rpc} />
        <Section title="Your address" footer={rpc === null ? "This build pins no Solana RPC provider, so balances and transfers are off." : "Balances come from Solana RPC providers this build pins. They see this address and your IP address; Morse sees neither."}>
          <RowGroup>
            <Row icon="key" title={address ? shortAddress(address) : "…"} subtitle={
              held === null ? (rpc === null ? "No balance without an RPC provider" : "Reading the balance…")
                : held === "unavailable" ? "Balance unavailable right now"
                  : `${sol(held.sol)} · ${usdc(held.usdc)}`}
              trailing={address ? <Button label="Copy" variant="ghost" size="sm" icon="copy" onPress={() => Clipboard.setString(address)} /> : null} />
          </RowGroup>
        </Section>
        <Section title="Bounty addresses" footer="Each fork proof names a new address, used once. A bounty stays there until you move it.">
          {bounties.length === 0 ? <Text style={type.footnote}>No bounty addresses yet.</Text> : (
            <RowGroup>
              {bounties.map((bounty) => (
                <Row key={bounty.index} icon="shield" title={shortAddress(bounty.address)}
                  subtitle={bounty.usdc === null ? "Balance unknown" : usdc(bounty.usdc)}
                  trailing={bounty.usdc ? <Button label="Move" variant="secondary" size="sm"
                    onPress={() => setMove({ index: bounty.index, recipient: "", noticed: settings.moveNoticeSeen })} /> : null} />
              ))}
            </RowGroup>
          )}
        </Section>
        {move ? (
          <Card>
            <View style={layout.stack}>
              {!move.noticed ? (
                <>
                  <Notice tone="warning" text={MOVE_NOTICE} />
                  <Button label="I understand" onPress={() => void run("Saving…", async () => {
                    await save({ ...settings, moveNoticeSeen: true });
                    setMove({ ...move, noticed: true });
                  })} />
                </>
              ) : (
                <>
                  <Field label="Send the bounty to" placeholder="Solana address" value={move.recipient}
                    onChangeText={(recipient) => setMove({ ...move, recipient: recipient.trim() })} />
                  <Actions>
                    <Button label="Move the bounty" disabled={busy !== null || !move.recipient || !rpc} onPress={() => void run("Moving…", async () => {
                      const signature = await moveBounty(rpc!, move.index, move.recipient);
                      setMove(null);
                      setDone({ text: "Moved.", signature });
                      await refresh(rpc!);
                    })} />
                    <Button label="Cancel" variant="ghost" onPress={() => setMove(null)} />
                  </Actions>
                </>
              )}
            </View>
          </Card>
        ) : null}
        <Section title="Pay">
          {payment === null ? (
            <RowGroup>
              <Row icon="link" title="Pay a Solana Pay link" subtitle="SOL or USDC, from this wallet"
                onPress={rpc ? () => setPayment({ url: "", request: null, noticed: settings.payNoticeSeen }) : undefined} />
            </RowGroup>
          ) : (
            <Card>
              <View style={layout.stack}>
                <Field label="Payment link" placeholder="solana:…" value={payment.url}
                  onChangeText={(url) => setPayment({ ...payment, url: url.trim(), request: null })} />
                {payment.request ? <PaySummary request={payment.request} usdcMint={rpc?.usdcMint} /> : null}
                {payment.request && !payment.noticed ? <Notice tone="warning" text={PAY_NOTICE} /> : null}
                <Actions>
                  {payment.request ? (
                    <Button label={payment.noticed ? "Pay" : "I understand, pay"} disabled={busy !== null} onPress={() => void run("Paying…", async () => {
                      if (!payment.noticed) await save({ ...settings, payNoticeSeen: true });
                      const signature = await pay(rpc!, payment.request!);
                      setPayment(null);
                      setDone({ text: "Paid.", signature });
                      await refresh(rpc!);
                    })} />
                  ) : (
                    <Button label="Check the link" disabled={!payment.url} onPress={() => void run("Reading…", async () => {
                      setPayment({ ...payment, request: await parsePayUrl(payment.url) });
                    })} />
                  )}
                  <Button label="Cancel" variant="ghost" onPress={() => setPayment(null)} />
                </Actions>
              </View>
            </Card>
          )}
        </Section>
        {done ? (
          <Notice text={`${done.text} Transaction ${done.signature.slice(0, 8)}…`} onDismiss={() => setDone(null)} />
        ) : null}
        <Section title="Recovery phrase" footer="Anyone with these words can take what’s in the wallet.">
          {phrase ? <PhraseWords words={phrase} /> : (
            <RowGroup>
              <Row icon="lock" title="Show recovery phrase" onPress={() => void run("Checking…", async () => setPhrase((await showPhrase()).split(" ")))} />
            </RowGroup>
          )}
        </Section>
        <Section>
          <RowGroup>
            <Row icon="warning" tone="danger" emphasis="danger" title="Delete this wallet"
              subtitle="Removes it from this device. Without the recovery phrase, what’s in it is gone for good."
              onPress={() => void run("Deleting…", async () => {
                await wipeWallet();
                await save(defaultWalletSettings);
                setPhrase(null);
                setAddress(null);
                setHeld(null);
                setBounties([]);
                setPhase({ step: "none" });
              })} />
          </RowGroup>
        </Section>
      </>
    );
  })();

  return (
    <Page header={<Header title="Wallet" onBack={onBack} />}>
      <ScrollView contentContainerStyle={layout.content}>
        {body}
        {busy ? <Text style={type.footnote}>{busy}</Text> : null}
        {problem ? <Notice tone="error" text={problem} onDismiss={() => setProblem(null)} /> : null}
      </ScrollView>
    </Page>
  );
}

function PhraseWords({ words }: { words: string[] }) {
  const { type } = useTheme();
  return (
    <Card>
      <View style={layout.wrap}>
        {words.map((word, index) => (
          <Text key={index} selectable style={[type.mono, { minWidth: 120 }]}>{`${index + 1}. ${word}`}</Text>
        ))}
      </View>
    </Card>
  );
}

function PaySummary({ request, usdcMint }: { request: PayRequest; usdcMint?: string }) {
  const { type } = useTheme();
  const amount = request.amount
    ? `${formatUnits(request.amount.mantissa, request.amount.scale)} ${request.splToken === usdcMint ? "USDC" : request.splToken ? "of another token" : "SOL"}`
    : "No amount";
  return (
    <View style={layout.stack}>
      <Text style={type.headline}>{amount}</Text>
      <Text style={type.footnote}>To {request.recipient}</Text>
      {request.label ? <Text style={type.body}>{request.label}</Text> : null}
      {request.message ? <Text style={type.body}>{request.message}</Text> : null}
    </View>
  );
}
