import { useEffect, useState } from 'react';
import { api, type Health } from './api';
import { loadStore, saveStore, type Store } from './identity';
import { short } from './components';
import { IdentityScreen } from './screens/Identity';
import { AuthScreen } from './screens/Auth';
import { RecoveryScreen } from './screens/Recovery';
import { AuditScreen } from './screens/Audit';

type Tab = 'identity' | 'auth' | 'recovery' | 'audit';

const TABS: { id: Tab; label: string; title: string; subtitle: string; index: string }[] = [
  {
    id: 'identity',
    label: 'Identitas',
    title: 'Identitas & share',
    subtitle: 'Terbitkan DID, bagi recovery secret, simpan commitment on-chain',
    index: '01',
  },
  {
    id: 'auth',
    label: 'Autentikasi',
    title: 'Autentikasi lintas platform',
    subtitle: 'Satu DID, dua aplikasi, challenge yang terikat konteks',
    index: '02',
  },
  {
    id: 'recovery',
    label: 'Pemulihan',
    title: 'Pemulihan akun',
    subtitle: 'Rekonstruksi secret dari share, rotasi kunci tanpa pihak ketiga',
    index: '03',
  },
  {
    id: 'audit',
    label: 'Audit',
    title: 'Audit trail',
    subtitle: 'Event registrasi, rotasi, dan pemulihan langsung dari chain',
    index: '04',
  },
];

function Icon({ name }: { name: Tab }) {
  const common = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' as const };
  return (
    <svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true">
      {name === 'identity' && (
        <>
          <circle cx="12" cy="9" r="3.4" {...common} />
          <path d="M5.5 19c1.2-3.1 3.6-4.6 6.5-4.6s5.3 1.5 6.5 4.6" {...common} />
          <path d="M4 12a8 8 0 1 1 16 0" {...common} opacity="0.35" />
        </>
      )}
      {name === 'auth' && (
        <>
          <circle cx="8.5" cy="12" r="3.5" {...common} />
          <path d="M12 12h8M17 12v3M20 12v2.5" {...common} />
        </>
      )}
      {name === 'recovery' && (
        <>
          <path d="M12 3.5 5.5 6v5.2c0 4 2.7 7.3 6.5 9.3 3.8-2 6.5-5.3 6.5-9.3V6L12 3.5Z" {...common} />
          <path d="M12 9v4M12 15.6v.2" {...common} />
        </>
      )}
      {name === 'audit' && (
        <>
          <path d="M5 7h14M5 12h14M5 17h9" {...common} />
          <circle cx="3" cy="7" r="0.6" fill="currentColor" />
          <circle cx="3" cy="12" r="0.6" fill="currentColor" />
          <circle cx="3" cy="17" r="0.6" fill="currentColor" />
        </>
      )}
    </svg>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>('identity');
  const [store, setStore] = useState<Store>(() => loadStore());
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; tone: string; id: number } | null>(null);

  useEffect(() => {
    saveStore(store);
  }, [store]);

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const next = await api.health();
        if (!alive) return;
        setHealth(next);
        setHealthError(null);
      } catch (cause) {
        if (!alive) return;
        setHealthError(cause instanceof Error ? cause.message : String(cause));
      }
    }
    load();
    const timer = window.setInterval(load, 8000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  function notify(message: string, tone: 'ok' | 'warn' | 'danger' = 'ok') {
    setToast({ message, tone, id: Date.now() });
  }

  const active = TABS.find((item) => item.id === tab) ?? TABS[0];

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <span className="brand-mark">
            <span>S</span>
          </span>
          <div className="brand-text">
            <strong>SSS / DID</strong>
            <span>recovery console</span>
          </div>
        </div>

        <nav className="nav">
          {TABS.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${item.id === tab ? 'active' : ''}`}
              onClick={() => setTab(item.id)}
            >
              <span className="nav-icon">
                <Icon name={item.id} />
              </span>
              <span className="nav-label">{item.label}</span>
              <span className="nav-index mono">{item.index}</span>
            </button>
          ))}
        </nav>

        <div className="rail-note">
          <span className="tag">prototype riset</span>
          <p>IF4035 Blockchain · Digital Identity</p>
        </div>

        <div className="rail-foot">
          <div className={`chain-dot ${health ? 'online' : 'offline'}`} />
          <div className="chain-meta">
            <span className="mono">{health ? `chain ${health.chainId}` : healthError ? 'rpc offline' : 'connecting'}</span>
            <span className="mono dim">{health ? short(health.registry, 8, 6) : '—'}</span>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="topbar-text">
            <span className="crumb mono">{active.index} / 04</span>
            <h1>{active.title}</h1>
            <p className="muted">{active.subtitle}</p>
          </div>
          <div className="topbar-side">
            {store.identity ? (
              <div className="did-chip" title={store.identity.did}>
                <span className={`dot ${store.identity.authPrivateKey ? 'dot-on' : 'dot-off'}`} />
                <span className="mono">{short(store.identity.did, 14, 6)}</span>
                <span className="did-version">v{store.identity.version}</span>
              </div>
            ) : (
              <span className="pill">belum ada identitas</span>
            )}
          </div>
        </header>

        <div className="page">
          <div className="tab-panel" hidden={tab !== 'identity'}>
            <IdentityScreen store={store} onStore={setStore} toast={notify} goRecovery={() => setTab('recovery')} />
          </div>
          <div className="tab-panel" hidden={tab !== 'auth'}>
            <AuthScreen store={store} health={health} goRecovery={() => setTab('recovery')} />
          </div>
          <div className="tab-panel" hidden={tab !== 'recovery'}>
            <RecoveryScreen store={store} onStore={setStore} toast={notify} goAuth={() => setTab('auth')} />
          </div>
          <div className="tab-panel" hidden={tab !== 'audit'}>
            <AuditScreen store={store} health={health} />
          </div>

          <footer className="page-foot">
            <span>Prototype penelitian, bukan produk. Kunci demo disimpan di localStorage perangkat ini.</span>
            <span className="mono">{health ? `relayer ${short(health.relayer, 6, 4)}` : 'tanpa koneksi'}</span>
          </footer>
        </div>
      </main>

      {toast && (
        <div className={`toast toast-${toast.tone}`} key={toast.id}>
          <span className="toast-dot" />
          {toast.message}
        </div>
      )}
    </div>
  );
}
