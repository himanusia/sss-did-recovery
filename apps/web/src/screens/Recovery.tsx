import { useEffect, useMemo, useState } from 'react';
import { verifyShareProof } from '@sss/crypto';
import type { DIDDocument } from '../api';
import { api, ApiError } from '../api';
import type { PendingRecovery, Store } from '../identity';
import {
  beginRecovery,
  cancelRecovery,
  completeRecovery,
  downloadEnvelope,
  type RecoveryOutcome,
  type RecoveryStep,
} from '../identity';
import { Card, Countdown, Empty, Hash, KeyValue, Pill, ShareCard, StepList } from '../components';

const STEPS = [
  { id: 'verify', label: 'Verifikasi share', detail: 'cek bukti Merkle terhadap root on-chain' },
  { id: 'reconstruct', label: 'Rekonstruksi secret', detail: 'interpolasi Lagrange di browser' },
  { id: 'signature', label: 'Tanda tangan rotasi', detail: 'recovery key menandatangani kunci baru' },
  { id: 'relay', label: 'Eksekusi on-chain', detail: 'auth key lama dicabut, versi naik' },
];

export function RecoveryScreen({
  store,
  onStore,
  toast,
  goAuth,
}: {
  store: Store;
  onStore: (next: Store) => void;
  toast: (message: string, tone?: 'ok' | 'warn' | 'danger') => void;
  goAuth: () => void;
}) {
  const identity = store.identity;
  const pending = store.pending;

  const [threshold, setThreshold] = useState(identity ? Math.min(identity.threshold, 3) : 3);
  const [shareCount, setShareCount] = useState(identity ? identity.shareCount : 5);
  const [document, setDocument] = useState<DIDDocument | null>(null);
  const [delaySeconds, setDelaySeconds] = useState<number | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [busy, setBusy] = useState<'start' | 'execute' | 'cancel' | null>(null);
  const [step, setStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RecoveryOutcome | null>(null);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [, setTick] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => setTick((value) => value + 1), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!identity) return;
    let cancelled = false;
    api
      .getDid(identity.did)
      .then((response) => {
        if (cancelled) return;
        setDocument(response.document);
        setDelaySeconds(response.recoveryDelay);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [identity?.did, identity?.version, pending?.requestId]);

  const verifiedShares = useMemo(() => {
    const map = new Map<number, boolean | null>();
    if (!identity || !document) return map;
    for (const guardian of identity.guardians) {
      map.set(guardian.envelope.index, verifyShareProof(guardian.envelope.proof, document.shareRoot));
    }
    return map;
  }, [identity?.shareRoot, document?.shareRoot]);

  if (!identity) {
    return (
      <Empty title="Belum ada identitas">
        Terbitkan identitas dulu. Pemulihan bekerja dengan merekonstruksi secret dari share yang tersebar.
      </Empty>
    );
  }

  const owner = identity;
  const ready = pending ? pending.executeAfter * 1000 <= Date.now() : false;
  const isPending = Boolean(pending);

  async function start() {
    setBusy('start');
    setError(null);
    setResult(null);
    try {
      const next = await beginRecovery(owner, threshold, shareCount);
      onStore({ ...store, pending: next });
      toast('Permintaan pemulihan terbuka. Timelock berjalan.', 'ok');
    } catch (cause) {
      setError(cause instanceof ApiError ? `${cause.code}: ${cause.message}` : String(cause));
    } finally {
      setBusy(null);
    }
  }

  async function execute() {
    if (!pending) return;
    setBusy('execute');
    setError(null);
    setStep('verify');
    try {
      const guardians = owner.guardians.filter((guardian) => selected.includes(guardian.envelope.index));
      const outcome = await completeRecovery(owner, pending, guardians, (next: RecoveryStep) => setStep(next));
      setResult(outcome);
      onStore({ identity: outcome.identity, pending: null });
      setSelected([]);
      setDocument(outcome.document);
      toast('Akun dipulihkan. Auth key lama sudah dicabut.', 'ok');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
      setStep(null);
    }
  }

  async function cancel() {
    if (!pending) return;
    setBusy('cancel');
    setError(null);
    try {
      await cancelRecovery(owner, pending);
      onStore({ ...store, pending: null });
      setConfirmCancel(false);
      const refreshed = await api.getDid(owner.did);
      setDocument(refreshed.document);
      toast('Permintaan dibatalkan oleh kunci lama', 'ok');
    } catch (cause) {
      setError(cause instanceof ApiError ? `${cause.code}: ${cause.message}` : String(cause));
    } finally {
      setBusy(null);
    }
  }

  if (result) {
    return (
      <div className="stack">
        <Card className="success-card">
          <div className="success-head">
            <span className="success-mark">✓</span>
            <div>
              <h2>Akun dipulihkan</h2>
              <p className="muted">
                Auth key dirotasi ke kunci baru, versi dokumen naik ke {result.document.version}. Kunci lama
                sudah tidak berlaku di semua aplikasi.
              </p>
            </div>
            <Pill tone="ok">v{result.document.version}</Pill>
          </div>
          <div className="kv-grid">
            <KeyValue label="Auth key baru">
              <Hash value={result.document.authKey} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Recovery key baru">
              <Hash value={result.document.recoveryKey} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Share root baru">
              <Hash value={result.document.shareRoot} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Transaksi">
              <Hash value={result.txHash} head={10} tail={6} />
            </KeyValue>
          </div>
          <p className="footnote">
            Recovery key tidak perlu disimpan: satu-satunya backup adalah share di bawah. Tanpa share,
            pemulihan berikutnya tidak mungkin.
          </p>
        </Card>

        <Card
          title="Share set baru"
          subtitle="Secret lama sudah tidak dipakai. Bagikan set baru ini ke guardian, lewat kanal terpisah."
        >
          <div className="share-grid">
            {result.identity.guardians.map((guardian) => (
              <ShareCard
                key={guardian.envelope.index}
                guardian={guardian}
                onDownload={() => downloadEnvelope(guardian)}
              />
            ))}
          </div>
          <div className="actions">
            <button className="btn btn-primary" onClick={goAuth}>
              Bagikan share baru, lanjut ke autentikasi
            </button>
            <span className="hint">Set lama sudah tidak bisa dipakai lagi.</span>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="stack">
      {!owner.authPrivateKey && !isPending && (
        <div className="banner banner-warn">
          <div>
            <strong>Perangkat hilang.</strong> Mulai permintaan pemulihan, lalu kumpulkan minimal{' '}
            {owner.threshold} share dari guardian.
          </div>
        </div>
      )}

      <Card
        title="Permintaan pemulihan"
        subtitle="Dua fase: permintaan terbuka untuk siapa saja, eksekusi hanya dengan tanda tangan recovery key."
        action={
          isPending ? (
            ready ? (
              <Pill tone="accent">siap dieksekusi</Pill>
            ) : (
              <Pill tone="warn">menunggu timelock</Pill>
            )
          ) : (
            <Pill>idle</Pill>
          )
        }
      >
        {!isPending ? (
          <>
            <div className="config">
              <label className="field">
                <span>Ambang set baru (k)</span>
                <select
                  value={threshold}
                  disabled={busy !== null}
                  onChange={(event) => {
                    const next = Number(event.target.value);
                    setThreshold(next);
                    if (next > shareCount) setShareCount(next);
                  }}
                >
                  {[2, 3, 4].map((value) => (
                    <option key={value} value={value}>
                      {value} share
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Total share baru (n)</span>
                <select
                  value={shareCount}
                  disabled={busy !== null}
                  onChange={(event) => setShareCount(Number(event.target.value))}
                >
                  {[3, 4, 5].map((value) => (
                    <option key={value} value={value} disabled={value < threshold}>
                      {value} guardian
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <p className="muted recovery-copy">
              Sistem membuat kunci autentikasi baru dan recovery secret baru di perangkat ini. Registry hanya
              menerima alamat publik dan root share. Eksekusi menunggu timelock
              {delaySeconds !== null ? ` ${delaySeconds} detik` : ''} — jendela pembatalan untuk kunci lama.
            </p>
            <div className="actions">
              <button className="btn btn-primary" onClick={start} disabled={busy !== null}>
                {busy === 'start' ? 'Membuka permintaan…' : 'Mulai permintaan pemulihan'}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="recovery-meta">
              <div>
                <span className="label">Request</span>
                <span className="mono">#{pending?.requestId}</span>
              </div>
              <div>
                <span className="label">Kunci baru</span>
                <Hash value={pending?.newAuthAddress ?? ''} head={10} tail={6} />
              </div>
              <div>
                <span className="label">Transaksi</span>
                <Hash value={pending?.initiateTx ?? ''} head={10} tail={6} />
              </div>
            </div>
            {!ready && pending && <Countdown from={pending.initiatedAt} to={pending.executeAfter} />}
            {ready && (
              <p className="ready-note">
                Timelock selesai. Kumpulkan share di bawah, rekonstruksi secret di browser, lalu tanda tangani
                rotasi.
              </p>
            )}
            <div className="actions">
              {confirmCancel ? (
                <div className="confirm">
                  <span>Batalkan dengan kunci lama?</span>
                  <button className="btn btn-small btn-danger" onClick={cancel} disabled={busy !== null}>
                    {busy === 'cancel' ? 'Membatalkan…' : 'Ya, batalkan'}
                  </button>
                  <button className="btn btn-small btn-ghost" onClick={() => setConfirmCancel(false)}>
                    Tidak
                  </button>
                </div>
              ) : (
                <button
                  className="btn btn-small btn-ghost"
                  onClick={() => setConfirmCancel(true)}
                  disabled={!owner.authPrivateKey || busy !== null}
                >
                  Batalkan permintaan
                </button>
              )}
            </div>
          </>
        )}
        {error && <p className="error-box">{error}</p>}
      </Card>

      {isPending && (
        <div className="grid two">
          <Card
            title="Kumpulkan share"
            subtitle={`Butuh minimal ${owner.threshold} share valid. Share tidak dikirim ke server.`}
            action={
              <span className={`pill ${selected.length >= owner.threshold ? 'pill-ok' : ''}`}>
                {selected.length} dari {owner.threshold} share
              </span>
            }
          >
            <div className="share-grid dense">
              {owner.guardians.map((guardian) => (
                <ShareCard
                  key={guardian.envelope.index}
                  guardian={guardian}
                  selectable
                  selected={selected.includes(guardian.envelope.index)}
                  verified={verifiedShares.get(guardian.envelope.index) ?? null}
                  onToggle={() =>
                    setSelected((current) =>
                      current.includes(guardian.envelope.index)
                        ? current.filter((value) => value !== guardian.envelope.index)
                        : [...current, guardian.envelope.index],
                    )
                  }
                />
              ))}
            </div>
            <div className="actions">
              <button
                className="btn btn-primary"
                onClick={execute}
                disabled={!ready || selected.length < owner.threshold || busy !== null}
              >
                {busy === 'execute' ? 'Memulihkan…' : 'Rekonstruksi & pulihkan akun'}
              </button>
              {!ready && <span className="hint">Tombol aktif setelah timelock selesai.</span>}
            </div>
            {step && <StepList steps={STEPS} current={step} errorAt={error ? step : null} />}
          </Card>

          <Card title="Material baru" subtitle="Disiapkan di perangkat sebelum eksekusi.">
            <div className="kv-grid single">
              <KeyValue label="Auth key baru">
                <Hash value={pending?.newAuthAddress ?? ''} head={10} tail={6} />
              </KeyValue>
              <KeyValue label="Recovery key baru">
                <Hash value={pending?.newRecoveryAddress ?? ''} head={10} tail={6} />
              </KeyValue>
              <KeyValue label="Share root baru">
                <Hash value={pending?.newShareRoot ?? ''} head={10} tail={6} />
              </KeyValue>
              <KeyValue label="Threshold baru">
                <span className="mono">
                  {pending?.newThreshold}-of-{pending?.newShareCount}
                </span>
              </KeyValue>
            </div>
            <p className="footnote">
              Setelah eksekusi, share lama mati bersama auth key lama. Pemulihan berikutnya memakai set baru ini.
            </p>
          </Card>
        </div>
      )}

      {!isPending && (
        <Card title="Kenapa k-of-n" subtitle="Apa yang bisa dan tidak bisa dilakukan penyerang.">
          <div className="grid two">
            <div className="fact">
              <h3>k − 1 share</h3>
              <p className="muted">
                Tidak memberi informasi tentang secret: setiap nilai secret tetap mungkin untuk setiap kombinasi
                share yang kurang dari ambang.
              </p>
            </div>
            <div className="fact">
              <h3>k share atau lebih</h3>
              <p className="muted">
                Cukup untuk interpolasi polinomial dan membentuk kembali recovery key — hanya di perangkat yang
                menjalankan rekonstruksi.
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
