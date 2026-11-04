import { useState, type ReactNode } from 'react';

export function short(value: string, head = 8, tail = 6): string {
  if (!value) return '';
  if (value.length <= head + tail + 2) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function Hash({
  value,
  head = 10,
  tail = 6,
  label,
}: {
  value: string;
  head?: number;
  tail?: number;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="hash"
      title={value}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
      }}
    >
      <span>{label ? `${label} ` : ''}{short(value, head, tail)}</span>
      <span className="hash-copy">{copied ? 'tersalin' : 'salin'}</span>
    </button>
  );
}

export function Pill({
  tone = 'neutral',
  children,
}: {
  tone?: 'neutral' | 'ok' | 'warn' | 'danger' | 'accent';
  children: ReactNode;
}) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function Card({
  children,
  className = '',
  title,
  subtitle,
  action,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <header className="card-head">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {subtitle && <p className="card-sub">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function KeyValue({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="kv">
      <span className="kv-label">{label}</span>
      <div className="kv-value">{children}</div>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-mark">◇</div>
      <h3>{title}</h3>
      <p className="muted">{children}</p>
    </div>
  );
}

export type StepStatus = 'idle' | 'active' | 'done' | 'error';

export function ShareCard({
  guardian,
  selectable = false,
  selected = false,
  verified,
  onToggle,
  onDownload,
}: {
  guardian: { name: string; token: string; envelope: { index: number } };
  selectable?: boolean;
  selected?: boolean;
  verified?: boolean | null;
  onToggle?: () => void;
  onDownload?: () => void;
}) {
  return (
    <div
      className={`share ${selected ? 'share-selected' : ''} ${selectable ? 'share-selectable' : ''}`}
      onClick={selectable ? onToggle : undefined}
      role={selectable ? 'button' : undefined}
      tabIndex={selectable ? 0 : undefined}
      onKeyDown={
        selectable
          ? (event) => {
              if (event.key === 'Enter' || event.key === ' ') onToggle?.();
            }
          : undefined
      }
    >
      <div className="share-top">
        <span className="share-index">{String(guardian.envelope.index).padStart(2, '0')}</span>
        <span className="share-name">{guardian.name}</span>
        {selectable ? (
          <span className={`check ${selected ? 'check-on' : ''}`}>{selected ? '✓' : ''}</span>
        ) : (
          <span className="share-tag">share</span>
        )}
      </div>
      <div className="share-token mono">{short(guardian.token, 22, 8)}</div>
      <div className="share-foot">
        <span className="share-state">
          {verified === true && <span className="ok-text">✓ commitment cocok</span>}
          {verified === false && <span className="danger-text">✕ tidak cocok</span>}
          {verified == null && <span className="dim">belum diverifikasi</span>}
        </span>
        {onDownload && (
          <button
            type="button"
            className="link"
            onClick={(event) => {
              event.stopPropagation();
              onDownload();
            }}
          >
            unduh
          </button>
        )}
      </div>
    </div>
  );
}

export function Countdown({ from, to }: { from: number; to: number }) {
  const now = Date.now();
  const remaining = Math.max(0, to * 1000 - now);
  const total = Math.max(1, to * 1000 - from);
  const elapsed = Math.min(total, Math.max(0, now - from));
  const minutes = Math.floor(remaining / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);
  return (
    <div className="countdown">
      <div className="countdown-row">
        <span className="countdown-label">timelock</span>
        <span className="countdown-value mono">
          {remaining === 0 ? 'selesai' : `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`}
        </span>
      </div>
      <div className="meter">
        <span style={{ width: `${Math.min(100, (elapsed / total) * 100)}%` }} />
      </div>
      <p className="countdown-note">
        Jendela pembatalan: kunci lama masih bisa membatalkan permintaan sampai timelock habis.
      </p>
    </div>
  );
}

export function StepList({
  steps,
  current,
  errorAt,
}: {
  steps: { id: string; label: string; detail: string }[];
  current: string | null;
  errorAt: string | null;
}) {
  const currentIndex = current ? steps.findIndex((step) => step.id === current) : -1;
  return (
    <ol className="steps">
      {steps.map((step, index) => {
        let status: StepStatus = 'idle';
        if (errorAt === step.id) status = 'error';
        else if (currentIndex > index) status = 'done';
        else if (current === step.id) status = index === steps.length - 1 ? 'active' : 'active';
        return (
          <li className={`step step-${status}`} key={step.id}>
            <span className="step-dot">{status === 'done' ? '✓' : index + 1}</span>
            <div>
              <span className="step-label">{step.label}</span>
              <span className="step-detail">{step.detail}</span>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
