import { useState } from 'react';
import { Wallet, getBytes } from 'ethers';
import { api, ApiError, type Challenge, type Session } from '../api';
import type { Store } from '../identity';
import { Card, Empty, Hash, KeyValue, Pill, short } from '../components';

interface AppSession {
  session: Session;
  latencyMs: number;
  challenge: Challenge;
  signature: string;
  checkedAt: number | null;
}

export function AuthScreen({
  store,
  health,
  goRecovery,
}: {
  store: Store;
  health: { apps: Record<string, string> } | null;
  goRecovery: () => void;
}) {
  const identity = store.identity;
  const [sessions, setSessions] = useState<Record<string, AppSession>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const apps = health?.apps ?? { klinik: 'Portal Klinik', market: 'Pasar Digital' };

  async function login(appId: string) {
    if (!identity?.authPrivateKey) return;
    setBusy(appId);
    setError(null);
    const started = performance.now();
    try {
      const challenge = await api.challenge(identity.did, appId);
      const wallet = new Wallet(identity.authPrivateKey);
      const signature = await wallet.signTypedData(
        challenge.typedData.domain,
        challenge.typedData.types,
        challenge.typedData.message,
      );
      const verified = await api.verify(challenge.challengeId, signature);
      setSessions((current) => ({
        ...current,
        [appId]: {
          session: verified.session,
          latencyMs: Math.round(performance.now() - started),
          challenge,
          signature,
          checkedAt: null,
        },
      }));
    } catch (cause) {
      setError(cause instanceof ApiError ? `${cause.code}: ${cause.message}` : String(cause));
    } finally {
      setBusy(null);
    }
  }

  async function logout(appId: string) {
    const current = sessions[appId];
    if (!current) return;
    try {
      await api.logout(current.session.token);
    } catch {
      // the local session is dropped either way; a dead token is not an error for the user
    }
    setSessions((previous) => {
      const next = { ...previous };
      delete next[appId];
      return next;
    });
  }

  async function check(appId: string) {
    const current = sessions[appId];
    if (!current) return;
    setBusy(appId);
    try {
      const { document } = await api.session(current.session.token);
      setSessions((previous) => ({
        ...previous,
        [appId]: {
          ...previous[appId],
          checkedAt: Date.now(),
          session: { ...previous[appId].session, authKey: document.authKey },
        },
      }));
    } catch (cause) {
      setError(cause instanceof ApiError ? `${cause.code}: ${cause.message}` : String(cause));
    } finally {
      setBusy(null);
    }
  }

  if (!identity) {
    return (
      <Empty title="Belum ada identitas">
        Terbitkan identitas dulu di tab Identitas. Login memakai DID dan tanda tangan kunci autentikasi, bukan
        password.
      </Empty>
    );
  }

  return (
    <div className="stack">
      {!identity.authPrivateKey && (
        <div className="banner banner-warn">
          <div>
            <strong>Kunci autentikasi tidak ada di perangkat ini.</strong> Login tidak mungkin sampai pemulihan
            selesai.
          </div>
          <button className="btn btn-small btn-primary" onClick={goRecovery}>
            Pulihkan akun
          </button>
        </div>
      )}

      <div className="auth-intro">
        <div>
          <span className="label">DID aktif</span>
          <Hash value={identity.did} head={22} tail={10} />
        </div>
        <p className="muted">
          Satu DID, dua aplikasi. Setiap challenge terikat ke <span className="mono">app</span>, chain, dan
          alamat registry, jadi signature untuk satu aplikasi tidak bisa dipakai di aplikasi lain.
        </p>
      </div>

      {error && <p className="error-box">{error}</p>}

      <div className="grid two">
        {Object.entries(apps).map(([appId, appName]) => {
          const result = sessions[appId];
          return (
            <Card key={appId} className="app-card">
              <div className="app-head">
                <div className="app-id">
                  <span className="app-mark">
                    {appName
                      .split(' ')
                      .map((word) => word[0])
                      .slice(0, 2)
                      .join('')}
                  </span>
                  <div>
                    <h2 className="card-title">{appName}</h2>
                    <span className="mono dim">{appId}</span>
                  </div>
                </div>
                {result ? <Pill tone="ok">sesi aktif</Pill> : <Pill>belum login</Pill>}
              </div>

              {result ? (
                <div className="session">
                  <div className="session-row">
                    <KeyValue label="Latency">
                      <span className="mono">{result.latencyMs} ms</span>
                    </KeyValue>
                    <KeyValue label="Auth key DID">
                      <Hash value={result.session.authKey} head={10} tail={6} />
                    </KeyValue>
                  </div>
                  <div className="session-row">
                    <KeyValue label="Token">
                      <span className="mono">{short(result.session.token, 12, 8)}</span>
                    </KeyValue>
                    <KeyValue label="Kedaluwarsa">
                      <span className="mono">
                        {new Date(result.session.expiresAt).toLocaleTimeString('id-ID')} ·{' '}
                        {Math.max(0, Math.round((result.session.expiresAt - Date.now()) / 60000))} mnt
                      </span>
                    </KeyValue>
                  </div>
                  <details className="details">
                    <summary>Detail challenge</summary>
                    <div className="details-body">
                      <KeyValue label="Nonce">
                        <span className="mono">{short(result.challenge.typedData.message.nonce, 14, 10)}</span>
                      </KeyValue>
                      <KeyValue label="App (bound)">
                        <span className="mono">{result.challenge.typedData.message.app}</span>
                      </KeyValue>
                      <KeyValue label="Signature">
                        <span className="mono">{short(result.signature, 18, 10)}</span>
                      </KeyValue>
                      <KeyValue label="Sesi dicek">
                        <span className="mono">
                          {result.checkedAt ? new Date(result.checkedAt).toLocaleTimeString('id-ID') : '—'}
                        </span>
                      </KeyValue>
                    </div>
                  </details>
                  <div className="actions">
                    <button className="btn btn-small btn-ghost" onClick={() => check(appId)} disabled={busy === appId}>
                      {busy === appId ? 'Memeriksa…' : 'Cek sesi aktif'}
                    </button>
                    <button className="btn btn-small btn-ghost" onClick={() => login(appId)} disabled={busy === appId}>
                      Login ulang
                    </button>
                    <button className="btn btn-small btn-ghost" onClick={() => logout(appId)} disabled={busy === appId}>
                      Keluar
                    </button>
                  </div>
                </div>
              ) : (
                <div className="app-body">
                  <p className="muted">
                    Server menerbitkan nonce sekali pakai. Perangkat menandatangani payload EIP-712 dengan kunci
                    autentikasi, server memverifikasi terhadap DID on-chain.
                  </p>
                  <button
                    className="btn btn-primary btn-block"
                    onClick={() => login(appId)}
                    disabled={!identity.authPrivateKey || busy === appId}
                  >
                    {busy === appId ? 'Menandatangani…' : `Masuk ke ${appName}`}
                  </button>
                </div>
              )}
            </Card>
          );
        })}
      </div>

      <Card title="Yang diverifikasi server" subtitle="Empat pemeriksaan sebelum sesi diterbitkan; semua lulus untuk sesi di atas.">
        <div className="grid four">
          <div className="verify-item">
            <span className="verify-num">✓ 1</span>
            <strong>DID terdaftar</strong>
            <span className="muted">resolusi dokumen dari registry</span>
          </div>
          <div className="verify-item">
            <span className="verify-num">✓ 2</span>
            <strong>Signature valid</strong>
            <span className="muted">ecrecover terhadap auth key aktif</span>
          </div>
          <div className="verify-item">
            <span className="verify-num">✓ 3</span>
            <strong>Nonce baru</strong>
            <span className="muted">sekali pakai, kedaluwarsa 120 detik</span>
          </div>
          <div className="verify-item">
            <span className="verify-num">✓ 4</span>
            <strong>Domain cocok</strong>
            <span className="muted">app id + chain + registry</span>
          </div>
        </div>
      </Card>
    </div>
  );
}
