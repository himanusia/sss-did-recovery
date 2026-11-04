import { useEffect, useState } from 'react';
import { api, type AuditEvent } from '../api';
import type { Store } from '../identity';
import { Card, Empty, Hash, Pill, short } from '../components';

const LABELS: Record<AuditEvent['type'], { title: string; tone: 'ok' | 'warn' | 'danger' | 'accent' | 'neutral' }> = {
  registered: { title: 'DID terdaftar', tone: 'ok' },
  'recovery-initiated': { title: 'Permintaan pemulihan dibuka', tone: 'warn' },
  'recovery-cancelled': { title: 'Pemulihan dibatalkan', tone: 'neutral' },
  'recovery-executed': { title: 'Pemulihan dieksekusi', tone: 'accent' },
  'key-rotated': { title: 'Auth key dirotasi', tone: 'accent' },
};

function formatValue(key: string, value: string | number): string {
  if (/(At|After)$/.test(key) && typeof value === 'number') {
    return new Date(value * 1000).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' });
  }
  return String(value);
}

function detailRows(event: AuditEvent): { label: string; value: string }[] {
  return Object.entries(event.data).map(([key, value]) => ({
    label: key.replace(/([A-Z])/g, ' $1').replace(/^./, (char) => char.toUpperCase()),
    value: formatValue(key, value),
  }));
}

function fullTime(seconds: number | null): string {
  if (!seconds) return '—';
  return new Date(seconds * 1000).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'medium' });
}

export function AuditScreen({ store, health }: { store: Store; health: { chainId: number; registry: string } | null }) {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const identity = store.identity;

  async function load() {
    if (!identity) return;
    setLoading(true);
    setError(null);
    try {
      const response = await api.audit(identity.did);
      setEvents(response.events);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identity?.did, identity?.version]);

  if (!identity) {
    return (
      <Empty title="Belum ada identitas">
        Audit trail dibaca langsung dari event registry. Terbitkan identitas dulu.
      </Empty>
    );
  }

  const counts = (events ?? []).reduce<Record<string, number>>((accumulator, event) => {
    accumulator[event.type] = (accumulator[event.type] ?? 0) + 1;
    return accumulator;
  }, {});

  return (
    <div className="stack">
      <div className="grid three">
        <Card className="mini">
          <span className="metric-label">Event on-chain</span>
          <span className="metric-value">{events?.length ?? '—'}</span>
          <span className="metric-note">registrasi, rotasi, pemulihan</span>
        </Card>
        <Card className="mini">
          <span className="metric-label">Rotasi kunci</span>
          <span className="metric-value">{counts['key-rotated'] ?? 0}</span>
          <span className="metric-note">setiap versi dokumen naik</span>
        </Card>
        <Card className="mini">
          <span className="metric-label">Registry</span>
          <span className="metric-value small mono">{health ? short(health.registry, 8, 6) : '—'}</span>
          <span className="metric-note">chain {health?.chainId ?? '—'}</span>
        </Card>
      </div>

      <Card
        title="Audit trail"
        subtitle="Setiap perubahan verification method tercatat sebagai event, bukan sekadar baris database."
        action={
          <button className="btn btn-small btn-ghost" onClick={load} disabled={loading}>
            {loading ? 'Memuat…' : 'Muat ulang'}
          </button>
        }
      >
        {error && <p className="error-box">{error}</p>}
        {!events && !error && <p className="muted">Memuat event…</p>}
        {events && events.length === 0 && <p className="muted">Belum ada event.</p>}
        {events && events.length > 0 && (
          <ol className="timeline">
            {events.map((event, index) => {
              const meta = LABELS[event.type];
              const sameTransaction = index > 0 && events[index - 1].txHash === event.txHash;
              return (
                <li key={`${event.txHash}-${event.logIndex}`} className="event">
                  <span className={`event-dot event-${meta.tone}`} />
                  <div className="event-body">
                    <div className="event-head">
                      <strong>{meta.title}</strong>
                      <Pill tone={meta.tone}>blok {event.blockNumber}</Pill>
                    </div>
                    {sameTransaction ? (
                      <span className="event-same">lanjutan dari transaksi yang sama</span>
                    ) : (
                      <div className="event-meta">
                        <span className="mono dim">{fullTime(event.timestamp)}</span>
                        <Hash value={event.txHash} head={8} tail={6} />
                      </div>
                    )}
                    <div className="event-data">
                      {detailRows(event).map((row) => (
                        <span key={row.label}>
                          <span className="dim">{row.label}</span>
                          <span className="mono">{short(row.value, 14, 6)}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </Card>

      <Card title="Kenapa on-chain" subtitle="Audit yang tidak bergantung pada operator layanan.">
        <div className="grid three">
          <div className="fact">
            <h3>Urutan bisa diperiksa</h3>
            <p className="muted">Event memberi urutan dan bukti waktu untuk registrasi, pembatalan, dan rotasi.</p>
          </div>
          <div className="fact">
            <h3>Tanpa data pribadi</h3>
            <p className="muted">Hanya hash DID, alamat publik, root share, dan versi yang disimpan.</p>
          </div>
          <div className="fact">
            <h3>Lintas aplikasi</h3>
            <p className="muted">Semua aplikasi membaca dokumen yang sama, jadi rotasi langsung berlaku di mana-mana.</p>
          </div>
        </div>
      </Card>
    </div>
  );
}
