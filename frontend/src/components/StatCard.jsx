export default function StatCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div
      className="interactive-card"
      style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderLeft: `3px solid ${color || 'var(--border)'}`,
        borderRadius: 'var(--radius-lg)', padding: '18px 20px',
        position: 'relative', overflow: 'hidden',
      }}
    >
      {/* Subtle glow strip at bottom matching card color */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${color || 'transparent'}, transparent)`,
        opacity: 0.4,
      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          {label}
        </span>
        {Icon && <Icon size={14} color={color || 'var(--text-muted)'} />}
      </div>

      {/* Number animates in */}
      <div
        key={String(value)}
        className="animate-count-up"
        style={{ fontFamily: 'var(--font-mono)', fontSize: 28, fontWeight: 900, color: color || 'var(--text-primary)', lineHeight: 1 }}
      >
        {value ?? '—'}
      </div>

      {sub && <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6 }}>{sub}</div>}
    </div>
  )
}