import { useEffect, useState } from "react";
import { Clipboard, ScrollView, Text, View } from "react-native";
import QRCode from "react-native-qrcode-svg";

import {
  buyStorage,
  collectCredits,
  loadCredits,
  onCreditQuestion,
  onCreditsChanged,
  payFromWallet,
  quoteCredits,
  refreshCreditKeys,
  resumePurchases,
  setInboxPrice,
  waitForCredits,
  type CreditQuestion,
} from "./credits";
import {
  ASSETS,
  COOLDOWN_NOTICE,
  INBOX_PRICES,
  OPERATOR_NOTICE,
  OPERATOR_RETRY_REFUSED,
  PACKS,
  PUBLIC_PURCHASE_NOTICE,
  STORAGE_PERIOD_CREDITS,
  STORAGE_PERIOD_DAYS,
  balanceLine,
  credits,
  formatAmount,
  inboxPriceLabel,
  outcomeMessage,
  packLabel,
  purchaseActions,
  purchaseLine,
  type CreditsStatus,
  type IssueOutcome,
  type Purchase,
} from "./credits-model.ts";
import { databasePath } from "./storage";
import { useTheme } from "./theme";
import { Actions, Button, Card, Dialog, Header, Notice, Page, Row, RowGroup, Section, Segmented, layout } from "./ui";
import { walletExists } from "./wallet.ts";

// Settings -> Credits (plan §10): the balance, buying with the in-app wallet,
// another wallet or Lightning, what each purchase came to (kept on this device
// only), and longer storage. Credits are never needed to message anyone.

const hex = (value: Uint8Array) => Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
const clock = (at: number) => new Date(at).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
const day = (at: number) => new Date(at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });

function useCredits(): [CreditsStatus | null, () => void] {
  const [status, setStatus] = useState<CreditsStatus | null>(null);
  const reload = () => { loadCredits(databasePath).then(setStatus, () => {}); };
  useEffect(() => {
    reload();
    return onCreditsChanged(reload);
  }, []);
  return [status, reload];
}

function friendly(error: unknown): string {
  const text = String(error instanceof Error ? error.message : error);
  if (/credits_insufficient/.test(text)) return "Not enough credits for that yet.";
  if (/credits_quote_busy/.test(text)) return "Too many people are buying right now. Try again in a minute.";
  if (/credits_asset_unavailable/.test(text)) return "That way of paying isn’t offered right now. Try another.";
  if (/credits_unavailable|credits_keys_unavailable|credits_keys_needed/.test(text)) return "Credits aren’t on sale right now.";
  if (/credits_network|rpc_unavailable/.test(text)) return "No connection. Try again.";
  if (/transaction_failed|transaction_expired/.test(text)) return "The payment didn’t go through. Nothing was paid.";
  return text.replace(/^Error:\s*/, "");
}

// Settings row: the balance, and the way into Credits.
export function CreditsRow({ onPress }: { onPress: () => void }) {
  const [status] = useCredits();
  if (!status?.sold) return null;
  return (
    <Row icon="sliders" title="Credits"
      subtitle={`${credits(status.spendable)}${status.cooling ? ` · ${status.cooling} on the way` : ""}`}
      onPress={onPress} />
  );
}

// Settings -> Privacy: what a stranger's first messages cost. Contacts, and
// group members once this device has handed them its contact address, never pay.
export function InboxPriceRow({ disabled = false }: { disabled?: boolean }) {
  const [status, reload] = useCredits();
  const [problem, setProblem] = useState<string | null>(null);
  if (!status?.sold) return null;
  const choose = (price: number) => {
    setProblem(null);
    setInboxPrice(databasePath, price).then(reload, (error) => setProblem(friendly(error)));
  };
  return (
    <Row
      icon="inbox"
      title="Message requests from strangers"
      subtitle={problem ?? (status.inboxPrice === 0 ? "Free" : `${credits(status.inboxPrice)} each, paid to the network`)}
      trailing={
        <Segmented
          label="Price for message requests"
          options={INBOX_PRICES.map((price) => ({ value: price as number, label: inboxPriceLabel(price), short: price === 0 ? "Free" : `${price}` }))}
          value={status.inboxPrice}
          onSelect={(price) => { if (!disabled) choose(price); }}
        />
      }
    />
  );
}

// Asks the person when credits would be spent for them: a stranger's price, or
// skipping a busy sign-up. Mounted once, by the app.
export function CreditPrompts() {
  const { type } = useTheme();
  const [asked, setAsked] = useState<{ question: CreditQuestion; answer: (yes: boolean) => void } | null>(null);
  useEffect(() => onCreditQuestion(setAsked), []);
  if (!asked) return null;
  const close = (yes: boolean) => { asked.answer(yes); setAsked(null); };
  const question = asked.question;
  const title = question.kind === "postage" ? question.title : "Sign-ups are busy";
  const body = question.kind === "postage"
    ? question.body
    : `This device can do more work to get in, which takes longer, or skip the wait for ${credits(question.credits)} (you have ${question.spendable}).`;
  const yes = question.kind === "postage" ? (question.affordable ? "Send" : "") : `Skip the wait for ${question.credits} credits`;
  return (
    <Dialog visible label={title} onClose={() => close(false)}>
      <View style={layout.stack}>
        <Text style={type.title2}>{title}</Text>
        <Text style={type.body}>{body}</Text>
        {question.kind === "postage" && !question.affordable
          ? <Text style={type.footnote}>Buy credits in Settings → Credits, then send again.</Text> : null}
        <Actions>
          {yes ? <Button label={yes} onPress={() => close(true)} /> : null}
          <Button label={question.kind === "postage" ? "Don’t send" : "Keep working"} variant="secondary" onPress={() => close(false)} />
        </Actions>
      </View>
    </Dialog>
  );
}

function PaymentCard({ purchase, method, onDone }: {
  purchase: Purchase;
  method: "wallet" | "other";
  onDone: (outcome: IssueOutcome) => void;
}) {
  const { type, colors } = useTheme();
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const inApp = method === "wallet" && purchase.asset !== 3;
  // Another wallet or Lightning: ask the issuer while this is on screen.
  useEffect(() => {
    if (inApp) return;
    let stopped = false;
    void waitForCredits(databasePath, purchase, "", () => stopped)
      .then((answer) => { if (!stopped && answer.outcome !== "pending") onDone(answer.outcome); }, () => {});
    return () => { stopped = true; };
  }, [purchase.id, inApp]);
  const link = purchase.asset === 3 ? `lightning:${purchase.paymentRequest}` : purchase.paymentRequest;
  return (
    <Card>
      <View style={layout.stack}>
        <Text style={type.headline}>{`Pay ${formatAmount(purchase.asset, purchase.amount)}`}</Text>
        <Text style={type.body}>{`for ${packLabel(purchase.pack)}. The quote holds until ${clock(purchase.expiresAt)}.`}</Text>
        {inApp ? (
          <Actions>
            <Button label="Pay from this wallet" disabled={busy !== null} onPress={() => {
              setBusy("Paying, then waiting for the payment to be final…");
              setProblem(null);
              payFromWallet(databasePath, purchase).then(
                (answer) => { setBusy(null); onDone(answer.outcome); },
                (error) => { setBusy(null); setProblem(friendly(error)); },
              );
            }} />
          </Actions>
        ) : (
          <>
            <View style={[layout.center, { backgroundColor: colors.paper, padding: 12, borderRadius: 12, alignSelf: "center" }]}>
              <QRCode value={link} size={220} backgroundColor={colors.paper} color={colors.ink} quietZone={0} />
            </View>
            <Text style={type.footnote}>
              {purchase.asset === 3
                ? "Scan with a Lightning wallet, or copy the invoice."
                : "Scan with a Solana wallet that reads Solana Pay, or copy the link."}
            </Text>
            <Actions>
              <Button label={purchase.asset === 3 ? "Copy invoice" : "Copy link"} variant="secondary" icon="copy"
                onPress={() => Clipboard.setString(purchase.paymentRequest)} />
              <Button label="I’ve paid, check now" variant="ghost" disabled={busy !== null} onPress={() => {
                setBusy("Checking…");
                collectCredits(databasePath, purchase).then(
                  (answer) => { setBusy(null); if (answer.outcome !== "pending") onDone(answer.outcome); else setProblem(outcomeMessage("pending")); },
                  (error) => { setBusy(null); setProblem(friendly(error)); },
                );
              }} />
            </Actions>
            <Text style={type.footnote}>Waiting for your payment…</Text>
          </>
        )}
        <Text style={type.footnote}>{OPERATOR_NOTICE}</Text>
        {busy ? <Text style={type.footnote}>{busy}</Text> : null}
        {problem ? <Notice tone="warning" text={problem} onDismiss={() => setProblem(null)} /> : null}
      </View>
    </Card>
  );
}

function PurchaseRow({ purchase, now, onPay, onCollect, onRetry }: {
  purchase: Purchase;
  now: number;
  onPay: () => void;
  onCollect: () => void;
  onRetry: () => void;
}) {
  const buttons = purchaseActions(purchase, now).map((action) =>
    action === "copy-reference"
      ? <Button key={action} label="Copy reference" variant="ghost" size="sm" icon="copy" onPress={() => Clipboard.setString(hex(purchase.quoteId))} />
      : action === "retry"
        ? <Button key={action} label="Try again" variant="secondary" size="sm" onPress={onRetry} />
        : action === "pay"
          ? <Button key={action} label="Pay" variant="secondary" size="sm" onPress={onPay} />
          : <Button key={action} label="Collect" variant="secondary" size="sm" onPress={onCollect} />);
  const trailing = buttons.length ? <View style={layout.row}>{buttons}</View> : null;
  return (
    <Row
      icon={purchase.state === "issued" ? "check" : purchase.state === "operator" || purchase.state === "unpaid" ? "warning" : "clock"}
      tone={purchase.state === "operator" || purchase.state === "unpaid" ? "danger" : "accent"}
      title={`${packLabel(purchase.pack)} · ${formatAmount(purchase.asset, purchase.amount)}`}
      subtitle={`${day(purchase.createdAt)} · ${purchaseLine(purchase, now)}`}
      trailing={trailing}
    />
  );
}

export function CreditsScreen({ onBack }: { onBack: () => void }) {
  const { type } = useTheme();
  const [status, reload] = useCredits();
  const [pack, setPack] = useState<number>(1);
  const [asset, setAsset] = useState<number>(1);
  const [method, setMethod] = useState<"wallet" | "other">("wallet");
  const [hasWallet, setHasWallet] = useState(false);
  const [active, setActive] = useState<Purchase | null>(null);
  const [periods, setPeriods] = useState(1);
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const now = Date.now();

  useEffect(() => {
    walletExists().then((exists) => { setHasWallet(exists); if (!exists) setMethod("other"); }, () => setMethod("other"));
    refreshCreditKeys(databasePath).catch(() => {}).finally(() => { void resumePurchases(databasePath).catch(() => {}); });
  }, []);

  const run = (label: string, task: () => Promise<void>) => {
    setBusy(label);
    setProblem(null);
    setDone(null);
    task().catch((error) => setProblem(friendly(error))).finally(() => { setBusy(null); reload(); });
  };

  const finished = (outcome: IssueOutcome) => {
    setActive(null);
    const said = outcomeMessage(outcome);
    if (outcome === "issued") setDone(`Credits added. ${COOLDOWN_NOTICE}`);
    else if (said) setProblem(said);
    reload();
  };

  if (!status) {
    return (
      <Page header={<Header title="Credits" onBack={onBack} />}>
        <ScrollView contentContainerStyle={layout.content}><Text style={type.body}>Opening your credits…</Text></ScrollView>
      </Page>
    );
  }

  const payMethods = asset === 3
    ? [{ value: "other" as const, label: "Lightning invoice" }]
    : [
      ...(hasWallet ? [{ value: "wallet" as const, label: "This wallet" }] : []),
      { value: "other" as const, label: "Another wallet" },
    ];
  const chosenMethod = asset === 3 || !hasWallet ? "other" : method;
  const kept = status.retentionUntil > now;

  return (
    <Page header={<Header title="Credits" onBack={onBack} />}>
      <ScrollView contentContainerStyle={layout.content}>
        <Card tone="accent">
          <View style={layout.stack}>
            <Text style={type.largeTitle}>{credits(status.spendable)}</Text>
            <Text style={type.footnote}>
              {balanceLine(status, now) || "Credits pay for extras: files over 16 MB, longer storage, message requests to priced inboxes and busy sign-ups. Messaging never needs them."}
            </Text>
            {status.purpose === "test" ? <Text style={type.caption}>Test credits: this build uses Morse’s test issuer.</Text> : null}
          </View>
        </Card>
        {!status.sold ? <Notice text="This build doesn’t sell credits." /> : active ? (
          <PaymentCard purchase={active} method={chosenMethod} onDone={finished} />
        ) : (
          <Section title="Buy credits" footer={COOLDOWN_NOTICE}>
            <View style={layout.stack}>
              <Segmented label="Pack" value={pack} onSelect={setPack}
                options={PACKS.map((item) => ({ value: item.pack as number, label: `${item.credits.toLocaleString("en-US")} for $${item.usd}` }))} />
              <Segmented label="Pay with" value={asset} onSelect={setAsset}
                options={ASSETS.map((item) => ({ value: item.asset as number, label: item.label }))} />
              {payMethods.length > 1 ? (
                <Segmented label="From" value={chosenMethod} onSelect={setMethod} options={payMethods} />
              ) : <Text style={type.footnote}>{payMethods[0]!.label}</Text>}
              <Notice tone="warning" text={PUBLIC_PURCHASE_NOTICE} />
              <Actions>
                <Button label={`Buy ${packLabel(pack)}`} disabled={busy !== null} onPress={() => run("Getting a quote…", async () => {
                  setActive(await quoteCredits(databasePath, pack, asset));
                })} />
              </Actions>
            </View>
          </Section>
        )}
        {status.purchases.length ? (
          <Section title="Purchases" footer="Kept only on this device. Morse keeps no account of who bought what.">
            <RowGroup>
              {status.purchases.map((purchase) => (
                <PurchaseRow key={hex(purchase.id)} purchase={purchase} now={now}
                  onPay={() => setActive(purchase)}
                  onCollect={() => run("Collecting your credits…", async () => {
                    finished((await collectCredits(databasePath, purchase, purchase.payment)).outcome);
                  })}
                  onRetry={() => run("Trying again…", async () => {
                    const { outcome } = await collectCredits(databasePath, purchase, purchase.payment);
                    if (outcome === "operator") setProblem(OPERATOR_RETRY_REFUSED);
                    else finished(outcome);
                  })} />
              ))}
            </RowGroup>
          </Section>
        ) : null}
        {status.sold ? (
          <Section title="Keep messages longer"
            footer={`Messages waiting for this device are kept ${STORAGE_PERIOD_DAYS} days. Each ${STORAGE_PERIOD_DAYS} days more costs ${STORAGE_PERIOD_CREDITS} credits, up to 180 days. Each of your devices keeps its own.`}>
            <View style={layout.stack}>
              {kept ? <Text style={type.body}>{`Kept ${status.retentionDays} days, until ${day(status.retentionUntil)}.`}</Text> : null}
              <Segmented label="Longer by" value={periods} onSelect={setPeriods}
                options={[1, 2, 3, 4, 5].map((count) => ({ value: count, label: `${count * STORAGE_PERIOD_DAYS} days`, short: `+${count * STORAGE_PERIOD_DAYS}` }))} />
              <Actions>
                <Button label={`Keep ${STORAGE_PERIOD_DAYS + periods * STORAGE_PERIOD_DAYS} days · ${credits(periods * STORAGE_PERIOD_CREDITS)}`}
                  variant="secondary"
                  disabled={busy !== null || status.spendable < periods * STORAGE_PERIOD_CREDITS}
                  onPress={() => run("Buying storage…", async () => {
                    await buyStorage(databasePath, periods);
                    setDone(`Messages are kept ${STORAGE_PERIOD_DAYS + periods * STORAGE_PERIOD_DAYS} days now.`);
                  })} />
              </Actions>
            </View>
          </Section>
        ) : null}
        {busy ? <Text style={type.footnote}>{busy}</Text> : null}
        {done ? <Notice text={done} onDismiss={() => setDone(null)} /> : null}
        {problem ? <Notice tone="error" text={problem} onDismiss={() => setProblem(null)} /> : null}
      </ScrollView>
    </Page>
  );
}
