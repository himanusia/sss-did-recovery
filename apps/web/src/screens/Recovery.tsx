import { useEffect, useState } from 'react';
import type { DIDDocument } from '../api';
import { api, ApiError } from '../api';
import type { PendingRecovery, Store } from '../identity';
import { beginRecovery, cancelRecovery, completeRecovery, type RecoveryOutcome, type RecoveryStep } from '../identity';
import { Card, Countdown, Empty, Hash, KeyValue, Pill, StepList } from '../components';

const STEPS = [
  { id: 'request', label: 'Minta share ke jaringan', detail: 'k guardian acak, dijawab ke kunci transport' },
  { id: 'verify', label: 'Verifikasi share', detail: 'buka envelope, cek bukti Merkle on-chain' },
  { id: 'reconstruct', label: 'Rekonstruksi secret', detail: 'interpolasi Lagrange di browser' },
  { id: 'signature', label: 'Tanda tangan rotasi', detail: 'recovery key menandatangani kunci baru' },
  { id: 'relay', label: 'Eksekusi on-chain', detail: 'auth key lama dicabut, versi naik' },
  { id: 'distribute', label: 'Sebar set share baru', detail: 'set lama mati bersama kunci lama' },
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
    setStep('request');
    try {
      const outcome = await completeRecovery(owner, pending, (next: RecoveryStep) => setStep(next));
      setResult(outcome);
      onStore({ identity: outcome.identity, pending: null });
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
                Auth key dirotasi ke kunci baru, versi dokumen naik ke {result.document.version}. Kunci lama sudah
                tidak berlaku di semua aplikasi.
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
            Set share baru sudah disegel ke guardian sebelum halaman ini tampil. Tanpa share, pemulihan berikutnya
            tidak mungkin.
          </p>
        </Card>

        <Card
          title="Share set baru"
          subtitle="Secret lama sudah tidak dipakai. Set baru sudah tersebar otomatis dengan root yang tercatat di dokumen."
        >
          <div className="grid three">
            <div className="metric">
              <span className="metric-label">Share tersegel</span>
              <span className="metric-value">{result.identity.shareCount}</span>
              <span className="metric-note">satu per guardian, acak</span>
            </div>
            <div className="metric">
              <span className="metric-label">Threshold</span>
              <span className="metric-value">
                {result.identity.threshold}-of-{result.identity.shareCount}
              </span>
              <span className="metric-note">berlaku untuk pemulihan berikutnya</span>
            </div>
            <div className="metric">
              <span className="metric-label">Set lama</span>
              <span className="metric-value">mati</span>
              <span className="metric-note">root lama tidak lagi cocok</span>
            </div>
          </div>
          <div className="actions">
            <button className="btn btn-primary" onClick={goAuth}>
              Lanjut ke autentikasi
            </button>
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
            <strong>Perangkat hilang.</strong> Mulai permintaan pemulihan, lalu jaringan akan mengirim {owner.threshold}{' '}
            share terenkripsi ke perangkat ini.
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
              Sistem membuat kunci autentikasi baru dan recovery secret baru di perangkat ini, lalu menyegel share-nya
              untuk guardian. Registry hanya menerima alamat publik dan root share. Eksekusi menunggu timelock
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
                Timelock selesai. Minta share dari jaringan, rekonstruksi secret di browser, lalu tanda tangani
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
            subtitle={`Jaringan memilih ${owner.threshold} guardian secara acak dan membungkus ulang share-nya ke kunci transport perangkat ini.`}
            action={<span className="pill">{owner.threshold} share</span>}
          >
            <div className="grid three">
              <div className="metric">
                <span className="metric-label">Guardian diminta</span>
                <span className="metric-value">{owner.threshold}</span>
                <span className="metric-note">dipilih acak oleh jaringan</span>
              </div>
              <div className="metric">
                <span className="metric-label">Envelope</span>
                <span className="metric-value">tersegel</span>
                <span className="metric-note">hanya bisa dibuka perangkat ini</span>
              </div>
              <div className="metric">
                <span className="metric-label">Share ke server</span>
                <span className="metric-value">0</span>
                <span className="metric-note">server hanya memindahkan ciphertext</span>
              </div>
            </div>
            <div className="actions">
              <button className="btn btn-primary" onClick={execute} disabled={!ready || busy !== null}>
                {busy === 'execute' ? 'Memulihkan…' : 'Minta share, rekonstruksi & pulihkan'}
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
              <KeyValue label="Envelope baru">
                <span className="mono">{pending?.newEnvelopes.length ?? 0} tersegel</span>
              </KeyValue>
            </div>
            <p className="footnote">
              Envelope baru sudah disegel ke guardian dan baru dikirim setelah rotasi, karena root-nya harus cocok
              dengan dokumen yang baru.
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
