import { useEffect, useState } from 'react';
import type { Store } from '../identity';
import { createIdentity, type CreateStep } from '../identity';
import { api } from '../api';
import { Card, Hash, KeyValue, Pill, StepList, short } from '../components';

const STEPS = [
  { id: 'auth-key', label: 'Buat kunci autentikasi', detail: 'secp256k1, dibuat di perangkat' },
  { id: 'shares', label: 'Bagi recovery secret', detail: 'Shamir k-of-n, secret tidak disimpan' },
  { id: 'commitment', label: 'Komit root share', detail: 'Merkle root, bukan nilai share' },
  { id: 'signature', label: 'Tanda tangani registrasi', detail: 'EIP-191 atas digest kontrak' },
  { id: 'relay', label: 'Kirim ke registry', detail: 'relayer bayar gas, kunci tetap milik user' },
  { id: 'distribute', label: 'Sebar share terenkripsi', detail: 'disegel per guardian, urutan acak' },
];

export function IdentityScreen({
  store,
  onStore,
  toast,
  goRecovery,
}: {
  store: Store;
  onStore: (next: Store) => void;
  toast: (message: string, tone?: 'ok' | 'warn' | 'danger') => void;
  goRecovery: () => void;
}) {
  const [threshold, setThreshold] = useState(3);
  const [shareCount, setShareCount] = useState(5);
  const [running, setRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmLost, setConfirmLost] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [distributed, setDistributed] = useState<number | null>(null);

  const identity = store.identity;

  useEffect(() => {
    if (!identity) return;
    let cancelled = false;
    api
      .shareStatus(identity.did)
      .then((status) => {
        if (!cancelled) setDistributed(status.count);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [identity?.did, identity?.version]);

  async function handleCreate() {
    setRunning(true);
    setError(null);
    setCurrentStep('auth-key');
    try {
      const record = await createIdentity(threshold, shareCount, (step: CreateStep) => setCurrentStep(step));
      setCurrentStep(null);
      onStore({ identity: record, pending: null });
      toast('Identitas terbit, share tersegel ke jaringan', 'ok');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      toast('Registrasi gagal', 'danger');
    } finally {
      setRunning(false);
    }
  }

  function markLost() {
    if (!identity) return;
    onStore({ ...store, identity: { ...identity, authPrivateKey: null } });
    setConfirmLost(false);
    toast('Perangkat ditandai hilang. Autentikasi nonaktif sampai pemulihan selesai.', 'warn');
  }

  function reset() {
    localStorage.removeItem('sss-did-demo-v2');
    onStore({ identity: null, pending: null });
    setConfirmReset(false);
    toast('State demo dihapus dari perangkat ini', 'ok');
  }

  if (!identity) {
    return (
      <div className="stack">
        <div className="grid two start">
          <Card
            title="Terbitkan identitas"
            subtitle="Satu DID untuk semua aplikasi. Pemulihan tidak bergantung pada satu perangkat."
          >
            <div className="config">
              <label className="field">
                <span>Ambang pemulihan (k)</span>
                <select
                  value={threshold}
                  disabled={running}
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
                <span>Total share (n)</span>
                <select
                  value={shareCount}
                  disabled={running}
                  onChange={(event) => setShareCount(Number(event.target.value))}
                >
                  {[3, 4, 5].map((value) => (
                    <option key={value} value={value} disabled={value < threshold}>
                      {value} share
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <p className="hint config-hint">
              Share tidak dipilih manual: setiap share disegel ke kunci publik satu guardian, urutannya diacak, dan
              perangkat ini tidak menyimpan share setelah distribusi.
            </p>

            <div className="actions">
              <button className="btn btn-primary" onClick={handleCreate} disabled={running}>
                {running ? 'Menerbitkan…' : `Buat identitas ${threshold}-of-${shareCount}`}
              </button>
              <span className="hint">Kunci privat tidak pernah dikirim ke server.</span>
            </div>
            {error && <p className="error-box">{error}</p>}
          </Card>

          <Card title="Alur penerbitan" subtitle="Semua langkah kripto berjalan di browser ini.">
            <StepList steps={STEPS} current={currentStep} errorAt={error ? currentStep : null} />
          </Card>
        </div>

        <Card title="Kenapa dipisah" className="explain">
          <div className="grid three">
            <div className="explain-item">
              <span className="explain-num">01</span>
              <h3>Kunci autentikasi</h3>
              <p className="muted">
                Dipakai menandatangani challenge login. Boleh hilang tanpa ikut menghilangkan identitas.
              </p>
            </div>
            <div className="explain-item">
              <span className="explain-num">02</span>
              <h3>Recovery secret</h3>
              <p className="muted">
                Rahasia terpisah, dipecah dengan Shamir. Tidak ada satu perangkat pun yang menyimpan utuh.
              </p>
            </div>
            <div className="explain-item">
              <span className="explain-num">03</span>
              <h3>Commitment on-chain</h3>
              <p className="muted">
                Registry hanya menyimpan root share dan alamat recovery key, bukan share atau secret.
              </p>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="stack">
      {!identity.authPrivateKey && (
        <div className="banner banner-warn">
          <div>
            <strong>Perangkat ditandai hilang.</strong> Login nonaktif sampai pemulihan selesai.
          </div>
          <button className="btn btn-small btn-primary" onClick={goRecovery}>
            Buka pemulihan
          </button>
        </div>
      )}

      <div className="grid two">
        <Card
          title="Dokumen identitas"
          subtitle="Nilai yang tersimpan di registry, dibaca ulang dari chain."
          action={<Pill tone="ok">aktif · v{identity.version}</Pill>}
        >
          <div className="did-block">
            <span className="label">DID</span>
            <Hash value={identity.did} head={18} tail={10} />
          </div>
          <div className="kv-grid">
            <KeyValue label="Auth key">
              <Hash value={identity.authAddress} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Recovery key">
              <Hash value={identity.recoveryAddress} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Share root">
              <Hash value={identity.shareRoot} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Threshold">
              <span className="mono">
                {identity.threshold}-of-{identity.shareCount}
              </span>
            </KeyValue>
            <KeyValue label="Registrasi">
              <Hash value={identity.registerTx} head={10} tail={6} />
            </KeyValue>
            <KeyValue label="Dibuat">
              <span className="mono">{new Date(identity.createdAt).toLocaleString('id-ID')}</span>
            </KeyValue>
          </div>
        </Card>

        <Card title="Pemilik kunci" subtitle="Status perangkat yang memegang material rahasia.">
          <ul className="checklist">
            <li>
              <span className={`dot ${identity.authPrivateKey ? 'dot-on' : 'dot-off'}`} />
              <div>
                <strong>Kunci autentikasi</strong>
                <span className="muted">
                  {identity.authPrivateKey ? 'ada di perangkat ini' : 'hilang bersama perangkat'}
                </span>
              </div>
            </li>
            <li>
              <span className="dot dot-on" />
              <div>
                <strong>Recovery secret</strong>
                <span className="muted">tidak tersimpan utuh di mana pun</span>
              </div>
            </li>
            <li>
              <span className={`dot ${distributed ? 'dot-on' : 'dot-off'}`} />
              <div>
                <strong>{distributed ?? identity.shareCount} share tersegel</strong>
                <span className="muted">tersebar acak ke guardian, terenkripsi per penerima</span>
              </div>
            </li>
            <li>
              <span className="dot dot-on" />
              <div>
                <strong>Relayer</strong>
                <span className="muted">mengirim transaksi dan membayar gas, tanpa memegang kunci</span>
              </div>
            </li>
          </ul>
          <div className="actions actions-end">
            {identity.authPrivateKey ? (
              confirmLost ? (
                <div className="confirm">
                  <span>Tandai perangkat hilang?</span>
                  <button className="btn btn-small btn-danger" onClick={markLost}>
                    Ya, hilang
                  </button>
                  <button className="btn btn-small btn-ghost" onClick={() => setConfirmLost(false)}>
                    Batal
                  </button>
                </div>
              ) : (
                <button className="btn btn-small btn-ghost" onClick={() => setConfirmLost(true)}>
                  Simulasikan perangkat hilang
                </button>
              )
            ) : null}
            {confirmReset ? (
              <div className="confirm">
                <span>Hapus identitas demo?</span>
                <button className="btn btn-small btn-danger" onClick={reset}>
                  Hapus
                </button>
                <button className="btn btn-small btn-ghost" onClick={() => setConfirmReset(false)}>
                  Batal
                </button>
              </div>
            ) : (
              <button className="btn btn-small btn-ghost" onClick={() => setConfirmReset(true)}>
                Reset demo
              </button>
            )}
          </div>
        </Card>
      </div>

      <Card
        title="Distribusi share"
        subtitle="Satu share per guardian, disegel dengan kunci publik guardian itu. Urutan penempatan diacak di browser."
      >
        <div className="grid three">
          <div className="metric">
            <span className="metric-label">Envelope tersimpan</span>
            <span className="metric-value">{distributed ?? '—'}</span>
            <span className="metric-note">ciphertext, bukan nilai share</span>
          </div>
          <div className="metric">
            <span className="metric-label">Share di perangkat</span>
            <span className="metric-value">0</span>
            <span className="metric-note">tidak ada salinan lokal setelah distribusi</span>
          </div>
          <div className="metric">
            <span className="metric-label">Pemetaan share ↔ guardian</span>
            <span className="metric-value">acak</span>
            <span className="metric-note">jaringan tidak tahu isi kotak yang dipegang siapa</span>
          </div>
        </div>
        <p className="footnote">
          Guardian di demo ini adalah layanan yang berjalan bersama API supaya seluruh cerita bisa dijalankan di satu
          mesin. Kotaknya nyata: tanpa kunci privat guardian, isi envelope tidak bisa dibuka, termasuk oleh server.
        </p>
      </Card>

      <Card title="Ringkasan teknis" subtitle="Yang benar-benar dikirim ke chain saat registrasi.">
        <div className="grid three">
          <div className="metric">
            <span className="metric-label">Byte on-chain</span>
            <span className="metric-value">~96</span>
            <span className="metric-note">dokumen + root, tanpa share</span>
          </div>
          <div className="metric">
            <span className="metric-label">Operasi klien</span>
            <span className="metric-value">5</span>
            <span className="metric-note">keygen, split, seal, commit, sign</span>
          </div>
          <div className="metric">
            <span className="metric-label">Auth key di server</span>
            <span className="metric-value">0</span>
            <span className="metric-note">relayer hanya menerima signature</span>
          </div>
        </div>
        <div className="actions">
          <button className="btn btn-ghost" onClick={goRecovery} disabled={!identity.authPrivateKey && !store.pending}>
            Lihat alur pemulihan
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => {
              navigator.clipboard.writeText(identity.did);
              toast('DID disalin', 'ok');
            }}
          >
            Salin DID
          </button>
        </div>
        <p className="footnote mono">did hash · {short(identity.didHash, 20, 8)}</p>
      </Card>
    </div>
  );
}
