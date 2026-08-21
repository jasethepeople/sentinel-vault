import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { startLogin } from "@/const";
import { trpc } from "@/lib/trpc";
import { decryptVaultPayload, encryptVaultPayload, type VaultPayload } from "@/lib/vaultCrypto";
import { AlertTriangle, Check, ChevronRight, CircleDot, Clock3, FileKey2, Fingerprint, KeyRound, Loader2, LockKeyhole, Radio, ShieldAlert, Terminal, Trash2, UnlockKeyhole, Vault, Wifi } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

const stages = ["ARMED", "ALERT", "CRITICAL", "TRIGGERED"] as const;
type VaultKind = VaultPayload["kind"];

const stateColor: Record<string, string> = {
  ARMED: "text-primary border-primary/60 bg-primary/10",
  ALERT: "text-amber border-amber bg-amber/10",
  CRITICAL: "text-red-400 border-red-400/70 bg-red-950/30",
  TRIGGERED: "text-red-300 border-red-300 bg-red-950/60",
};

function formatRemaining(target?: Date | null) {
  if (!target) return "TERMINAL STATE";
  const total = Math.max(0, target.getTime() - Date.now());
  const hours = Math.floor(total / 3_600_000);
  const minutes = Math.floor((total % 3_600_000) / 60_000);
  const seconds = Math.floor((total % 60_000) / 1000);
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function localWipe() {
  Object.keys(localStorage).filter(key => key.startsWith("sentinel-") || key === "sidebar-width").forEach(key => localStorage.removeItem(key));
}

/**
 * All content in this page are only for example, replace with your own feature implementation
 * When building pages, remember your instructions in Frontend Workflow, Frontend Best Practices, Design Guide and Common Pitfalls
 */
export default function Home() {
  const { user, loading, isAuthenticated, logout } = useAuth();
  const utils = trpc.useUtils();
  const [now, setNow] = useState(() => Date.now());
  const [passphrase, setPassphrase] = useState("");
  const [vaultLabel, setVaultLabel] = useState("");
  const [vaultBody, setVaultBody] = useState("");
  const [vaultKind, setVaultKind] = useState<VaultKind>("SECRET");
  const [decrypted, setDecrypted] = useState<{ id: string; payload: VaultPayload } | null>(null);
  const [config, setConfig] = useState({ checkInIntervalMinutes: 1440, alertGraceMinutes: 120, criticalGraceMinutes: 120 });
  const [wipeConfirm, setWipeConfirm] = useState(false);
  const [holdProgress, setHoldProgress] = useState(0);
  const holdStart = useRef<number | null>(null);
  const holdFrame = useRef<number | null>(null);
  const { data, isLoading } = trpc.sentinel.overview.useQuery(undefined, { enabled: isAuthenticated, refetchInterval: 15_000 });

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!data?.profile) return;
    setConfig({
      checkInIntervalMinutes: data.profile.checkInIntervalMinutes,
      alertGraceMinutes: data.profile.alertGraceMinutes,
      criticalGraceMinutes: data.profile.criticalGraceMinutes,
    });
  }, [data?.profile?.id]);

  const refresh = () => utils.sentinel.overview.invalidate();
  const createVault = trpc.sentinel.createVault.useMutation({ onSuccess: () => { refresh(); setVaultLabel(""); setVaultBody(""); toast.success("Ciphertext committed to vault."); }, onError: error => toast.error(error.message) });
  const removeVault = trpc.sentinel.deleteVault.useMutation({ onSuccess: refresh, onError: error => toast.error(error.message) });
  const checkIn = trpc.sentinel.checkIn.useMutation({ onSuccess: () => { refresh(); toast.success("Liveness confirmation sealed."); }, onError: error => toast.error(error.message) });
  const configure = trpc.sentinel.configure.useMutation({ onSuccess: result => { refresh(); toast.success(result.scheduler === "ARMED" ? "Heartbeat evaluator armed." : "Policy saved. Scheduler activates after publication."); }, onError: error => toast.error(error.message) });
  const panicWipe = trpc.sentinel.panicWipe.useMutation({ onSuccess: () => { localWipe(); setPassphrase(""); setDecrypted(null); setWipeConfirm(false); setHoldProgress(0); refresh(); toast.success("Vault records and local vault session cleared."); }, onError: error => toast.error(error.message) });

  const beginHold = () => {
    holdStart.current = performance.now();
    const animate = (timestamp: number) => {
      const progress = Math.min(100, ((timestamp - (holdStart.current ?? timestamp)) / 2400) * 100);
      setHoldProgress(progress);
      if (progress >= 100) { panicWipe.mutate({ confirmation: "WIPE" }); return; }
      holdFrame.current = requestAnimationFrame(animate);
    };
    holdFrame.current = requestAnimationFrame(animate);
  };
  const cancelHold = () => { if (holdFrame.current) cancelAnimationFrame(holdFrame.current); holdFrame.current = null; holdStart.current = null; setHoldProgress(0); };
  const submitVault = async () => {
    try {
      if (!vaultLabel.trim() || !vaultBody.trim()) throw new Error("Provide a record identifier and encrypted content.");
      const encrypted = await encryptVaultPayload({ label: vaultLabel.trim(), kind: vaultKind, body: vaultBody, createdAt: new Date().toISOString() }, passphrase);
      createVault.mutate(encrypted);
    } catch (error) { toast.error(error instanceof Error ? error.message : "Encryption failed."); }
  };
  const unlockEntry = async (entry: { id: string; ciphertext: string; iv: string }) => {
    try { setDecrypted({ id: entry.id, payload: await decryptVaultPayload(entry.ciphertext, entry.iv, passphrase) }); }
    catch { toast.error("Decryption failed. Verify the memory-only vault passphrase."); }
  };

  if (loading) return <div className="min-h-screen grid place-items-center bg-background terminal-type"><Loader2 className="animate-spin text-primary" /></div>;
  if (!user) return <AccessGate />;
  const profile = data?.profile;
  const deadline = profile?.nextDeadlineAt ? new Date(profile.nextDeadlineAt) : null;

  return (
    <div className="scanlines min-h-screen overflow-x-hidden bg-background text-foreground">
      <div className="terminal-grid min-h-screen px-4 py-5 sm:px-7 lg:px-10">
        <header className="mx-auto flex max-w-[1600px] flex-col gap-4 border-b border-primary/35 pb-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className="grid h-11 w-11 place-items-center border border-primary bg-primary/10"><Fingerprint className="h-6 w-6 text-primary" /></div>
            <div><p className="terminal-type text-xs tracking-[0.26em] text-primary">SENTINEL // VAULT OPERATIONS</p><h1 className="blink-cursor text-xl tracking-wide sm:text-2xl">SOVEREIGN CONTINUITY PROTOCOL</h1></div>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-[10px] tracking-[0.14em] text-primary/80"><span className="flex items-center gap-2"><span className="h-2 w-2 animate-pulse bg-primary"/> CRYPTO LOCAL</span><span>OPERATOR: {user.name?.toUpperCase() ?? "UNKNOWN"}</span><button onClick={logout} className="text-amber hover:underline">SIGN OUT</button></div>
        </header>

        {isLoading || !profile ? <div className="grid min-h-[60vh] place-items-center"><Loader2 className="animate-spin text-primary" /></div> : <main className="mx-auto grid max-w-[1600px] gap-5 py-6 xl:grid-cols-[1.45fr_0.9fr]">
          <section className="space-y-5">
            <div className="terminal-panel border border-primary/45 bg-card/85 p-5 sm:p-7">
              <div className="mb-7 flex flex-wrap items-start justify-between gap-5"><div><p className="terminal-type text-xs tracking-[0.2em] text-primary/75">ESCALATION STATE // LIVE</p><div className="mt-3 flex items-center gap-3"><span className={`terminal-type border px-3 py-1 text-xl tracking-[0.2em] ${stateColor[profile.state]}`}>{profile.state}</span><span className="text-xs text-muted-foreground">CURRENT DEFCON</span></div></div><div className="text-right"><p className="text-[10px] tracking-[0.14em] text-muted-foreground">NEXT THRESHOLD IN</p><p className="terminal-type mt-1 text-3xl text-primary sm:text-4xl">{formatRemaining(deadline)}</p><p className="mt-1 text-[10px] text-muted-foreground">{deadline ? deadline.toLocaleString() : "NO FURTHER ESCALATION"}</p></div></div>
              <div className="grid gap-2 sm:grid-cols-4">{stages.map((stage, index) => { const active = stages.indexOf(profile.state) >= index; const current = profile.state === stage; return <div key={stage} className={`relative border px-3 py-4 ${active ? stateColor[stage] : "border-border bg-black/20 text-muted-foreground"}`}><span className="terminal-type text-[10px]">0{index + 1}</span><p className="mt-2 text-sm tracking-[0.12em]">{stage}</p>{current && <span className="absolute right-2 top-2 h-2 w-2 animate-pulse bg-current"/>}</div>; })}</div>
              <div className="mt-6 flex flex-col gap-3 border-t border-primary/20 pt-5 sm:flex-row sm:items-center sm:justify-between"><div className="text-xs text-muted-foreground">LAST VERIFIED: <span className="text-primary">{new Date(profile.lastCheckInAt).toLocaleString()}</span></div><Button onClick={() => checkIn.mutate()} disabled={checkIn.isPending} className="terminal-type rounded-none bg-primary px-6 text-xs font-bold tracking-[0.14em] text-primary-foreground hover:bg-primary/85"><Check className="mr-2 h-4 w-4" />{checkIn.isPending ? "SEALING..." : "CONFIRM LIVENESS"}</Button></div>
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
              <Panel title="CIPHER VAULT" code="CRYPTOGRAPHIC PAYLOADS" icon={<Vault className="h-4 w-4"/>}>
                <p className="mb-4 text-xs leading-relaxed text-muted-foreground">All fields below are encrypted with AES-GCM in this browser. The remote ledger receives only ciphertext, a random IV, and an embedded salt.</p>
                <label className="terminal-label">MEMORY-ONLY VAULT PASSPHRASE</label><Input type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="minimum 12 characters" className="terminal-input mb-4" />
                <label className="terminal-label">RECORD IDENTIFIER</label><Input value={vaultLabel} onChange={e => setVaultLabel(e.target.value)} placeholder="e.g. CONTINGENCY LETTER" className="terminal-input mb-3" />
                <label className="terminal-label">PAYLOAD TYPE</label><select value={vaultKind} onChange={e => setVaultKind(e.target.value as VaultKind)} className="terminal-input mb-3 w-full"><option value="SECRET">SECRET</option><option value="MESSAGE">MESSAGE</option><option value="FILE_REFERENCE">FILE REFERENCE</option></select>
                <label className="terminal-label">PLAINTEXT (ENCRYPTED BEFORE COMMIT)</label><Textarea value={vaultBody} onChange={e => setVaultBody(e.target.value)} placeholder="Never sent in plaintext." className="terminal-input min-h-28" />
                <Button onClick={submitVault} disabled={createVault.isPending} className="mt-4 w-full rounded-none border border-primary bg-transparent text-xs tracking-[0.14em] text-primary hover:bg-primary hover:text-primary-foreground"><LockKeyhole className="mr-2 h-4 w-4" />{createVault.isPending ? "ENCRYPTING..." : "ENCRYPT + COMMIT"}</Button>
              </Panel>
              <Panel title="HEARTBEAT POLICY" code="CONFIGURABLE GRACE WINDOWS" icon={<Clock3 className="h-4 w-4"/>}>
                <NumberField label="CHECK-IN INTERVAL / MIN" value={config.checkInIntervalMinutes} onChange={value => setConfig({ ...config, checkInIntervalMinutes: value })}/>
                <NumberField label="ALERT GRACE / MIN" value={config.alertGraceMinutes} onChange={value => setConfig({ ...config, alertGraceMinutes: value })}/>
                <NumberField label="CRITICAL GRACE / MIN" value={config.criticalGraceMinutes} onChange={value => setConfig({ ...config, criticalGraceMinutes: value })}/>
                <p className="mt-4 border-l-2 border-amber pl-3 text-[11px] leading-relaxed text-amber">The evaluator checks every five minutes once this application is published. Policy updates in preview are preserved and armed on the deployed site.</p>
                <Button onClick={() => configure.mutate(config)} disabled={configure.isPending} className="mt-5 w-full rounded-none bg-primary text-xs font-bold tracking-[0.14em] text-primary-foreground hover:bg-primary/85">{configure.isPending ? "WRITING POLICY..." : "SAVE + ARM POLICY"}</Button>
              </Panel>
            </div>

            <Panel title="ENCRYPTED ENTRY INDEX" code={`${data.entries.length.toString().padStart(2, "0")} CIPHERTEXT RECORDS`} icon={<FileKey2 className="h-4 w-4"/>} wide>
              <div className="divide-y divide-primary/15">{data.entries.length === 0 ? <Empty label="No ciphertext records committed."/> : data.entries.map(entry => <div key={entry.id} className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between"><div><p className="terminal-type text-xs text-primary">{entry.id}</p><p className="mt-1 text-[11px] text-muted-foreground">AES-GCM-256 / {entry.encryptionVersion} / {new Date(entry.createdAt).toLocaleString()}</p></div><div className="flex gap-2"><Button variant="outline" onClick={() => unlockEntry(entry)} className="h-8 rounded-none border-primary/50 bg-transparent text-[10px] text-primary hover:bg-primary hover:text-primary-foreground"><UnlockKeyhole className="mr-1 h-3 w-3"/>DECRYPT VIEW</Button><Button variant="outline" onClick={() => removeVault.mutate({ id: entry.id })} className="h-8 rounded-none border-red-400/40 bg-transparent text-[10px] text-red-300 hover:bg-red-950"><Trash2 className="h-3 w-3"/></Button></div></div>)}</div>
              {decrypted && <div className="mt-4 border border-amber bg-amber/5 p-4"><div className="mb-2 flex items-center justify-between"><span className="terminal-type text-xs text-amber">LOCAL DECRYPTION BUFFER // {decrypted.payload.kind}</span><button onClick={() => setDecrypted(null)} className="text-[10px] text-amber hover:underline">CLEAR BUFFER</button></div><p className="text-sm font-bold text-amber">{decrypted.payload.label}</p><pre className="mt-3 whitespace-pre-wrap break-words text-xs leading-6 text-amber/85">{decrypted.payload.body}</pre></div>}
            </Panel>
          </section>
          <aside className="space-y-5">
            <Panel title="SIGNAL DISPATCH" code="SIMULATED MULTI-CHANNEL" icon={<Radio className="h-4 w-4"/>}>
              <p className="mb-3 text-[11px] leading-relaxed text-muted-foreground">Escalations write simulation evidence for secure webhooks, automated email dispatch, and decentralized mesh pings. No third-party transmission is issued by this prototype.</p>
              <div className="space-y-2">{data.triggers.length === 0 ? <Empty label="No escalation channels dispatched."/> : data.triggers.slice(0, 8).map(event => <div key={event.id} className="border-l-2 border-amber bg-black/20 px-3 py-2"><div className="flex items-center justify-between gap-2"><span className="terminal-type text-[11px] text-amber">{event.channel.replace("_", " ")}</span><span className="text-[9px] text-muted-foreground">{event.escalationState}</span></div><p className="mt-1 text-[9px] text-muted-foreground">{new Date(event.dispatchedAt).toLocaleString()} // {event.status}</p></div>)}</div>
            </Panel>
            <Panel title="CHAIN OF CUSTODY" code="AUDIT EVENT STREAM" icon={<Terminal className="h-4 w-4"/>}>
              <div className="space-y-0">{data.audit.length === 0 ? <Empty label="Awaiting first protocol event."/> : data.audit.map(event => <div key={event.id} className="relative border-l border-primary/25 py-3 pl-5 before:absolute before:-left-[4px] before:top-4 before:h-2 before:w-2 before:bg-primary"><p className="terminal-type text-[11px] text-primary">{event.eventKind.replace("_", " ")}</p><p className="mt-1 text-[10px] text-muted-foreground">{event.fromState && `${event.fromState} → ${event.toState}`} {new Date(event.createdAt).toLocaleString()}</p></div>)}</div>
            </Panel>
            <div className={`terminal-panel border p-5 ${wipeConfirm ? "border-red-400 bg-red-950/35" : "border-red-400/50 bg-red-950/15"}`}><div className="flex items-center gap-2 text-red-300"><ShieldAlert className="h-5 w-5"/><p className="terminal-type text-sm tracking-[0.12em]">PANIC WIPE OVERRIDE</p></div><p className="mt-3 text-xs leading-relaxed text-red-200/70">Destroys every encrypted vault record, removes the scheduled evaluator, and clears local sentinel state. This cannot be reversed.</p>{!wipeConfirm ? <Button onClick={() => setWipeConfirm(true)} variant="outline" className="mt-4 w-full rounded-none border-red-400/60 bg-transparent text-xs text-red-300 hover:bg-red-950">INITIALIZE DESTRUCT SEQUENCE</Button> : <><button onPointerDown={beginHold} onPointerUp={cancelHold} onPointerLeave={cancelHold} onPointerCancel={cancelHold} disabled={panicWipe.isPending} className="relative mt-4 h-12 w-full overflow-hidden border border-red-300 bg-black text-xs tracking-[0.15em] text-red-200"><span className="hold-progress absolute inset-y-0 left-0 bg-red-700/60" style={{ width: `${holdProgress}%` }}/><span className="relative">{panicWipe.isPending ? "SHREDDING..." : "HOLD 2.4S TO WIPE"}</span></button><button onClick={() => { cancelHold(); setWipeConfirm(false); }} className="mt-3 w-full text-[10px] text-red-200/60 hover:text-red-200">ABORT SEQUENCE</button></>}</div>
          </aside>
        </main>}
        <footer className="mx-auto flex max-w-[1600px] items-center justify-between border-t border-primary/25 py-4 text-[9px] tracking-[0.14em] text-muted-foreground"><span>ZERO-KNOWLEDGE INTERFACE // PLAINTEXT NEVER LEAVES THIS DEVICE</span><span className="hidden sm:block">SYSTEM TIME: {new Date(now).toLocaleTimeString()}</span></footer>
      </div>
    </div>
  );
}

function AccessGate() { return <div className="scanlines grid min-h-screen place-items-center bg-background p-5"><div className="terminal-panel w-full max-w-lg border border-primary/50 bg-card/85 p-8 text-center"><Fingerprint className="mx-auto h-10 w-10 text-primary"/><p className="terminal-type mt-6 text-xs tracking-[0.2em] text-primary">IDENTITY VERIFICATION REQUIRED</p><h1 className="mt-3 text-2xl">SENTINEL // SOVEREIGN VAULT</h1><p className="mx-auto mt-4 max-w-sm text-sm leading-relaxed text-muted-foreground">Authenticate through the secured operator gateway to initialize an owner-scoped vault and liveness protocol.</p><Button onClick={() => startLogin()} className="mt-7 w-full rounded-none bg-primary font-bold tracking-[0.14em] text-primary-foreground hover:bg-primary/85">AUTHORIZE OPERATOR <ChevronRight className="ml-1 h-4 w-4"/></Button></div></div> }
function Panel({ title, code, icon, children, wide = false }: { title: string; code: string; icon: React.ReactNode; children: React.ReactNode; wide?: boolean }) { return <section className={`terminal-panel border border-primary/35 bg-card/85 p-5 ${wide ? "" : ""}`}><div className="mb-5 flex items-center justify-between border-b border-primary/20 pb-3"><div className="flex items-center gap-2 text-primary">{icon}<h2 className="terminal-type text-sm tracking-[0.14em]">{title}</h2></div><span className="text-[9px] tracking-[0.1em] text-muted-foreground">{code}</span></div>{children}</section> }
function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) { return <label className="mb-3 block"><span className="terminal-label">{label}</span><Input type="number" min={1} value={value} onChange={e => onChange(Number(e.target.value))} className="terminal-input" /></label> }
function Empty({ label }: { label: string }) { return <div className="grid place-items-center border border-dashed border-primary/25 py-7 text-center text-[11px] text-muted-foreground"><CircleDot className="mb-2 h-4 w-4 text-primary/50"/>{label}</div> }
