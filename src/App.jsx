import { useState, useEffect, useRef } from 'react';
import {
  Search,
  X,
  ChevronRight,
  ChevronLeft,
  Activity,
  ListChecks,
  Radio,
  GitMerge,
  Server,
  Database,
  FileText,
  Settings as SettingsIcon,
  Check,
  Loader2,
  AlertTriangle,
  RefreshCw,
  Link2,
  Bug,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Data — grounded in the actual Aegis architecture (Semgrep / Trivy /
// Gitleaks / ZAP scan layer, Cowrie honeypot, CWE-based correlation engine)
// Content, IA and functionality are unchanged from the previous pass — this
// file only revises presentation (layout, type, spacing, motion, iconography).
// ---------------------------------------------------------------------------

const NAV = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'findings', label: 'Findings', icon: ListChecks },
  { id: 'honeypot', label: 'Honeypot intel', icon: Radio },
  { id: 'correlation', label: 'Correlation engine', icon: GitMerge },
  { id: 'assets', label: 'Assets', icon: Server },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
];

const FINDINGS = [
  {
    id: 'AEG-1042',
    title: 'SQL injection in /rest/products/search',
    cwe: 'CWE-89',
    tool: 'Semgrep',
    sev: 'critical',
    status: 'Open',
    correlated: true,
  },
  {
    id: 'AEG-1039',
    title: 'Hardcoded AWS credentials in deploy script',
    cwe: 'CWE-798',
    tool: 'Gitleaks',
    sev: 'critical',
    status: 'Open',
    correlated: false,
  },
  {
    id: 'AEG-1035',
    title: 'Reflected XSS in feedback form',
    cwe: 'CWE-79',
    tool: 'Semgrep',
    sev: 'high',
    status: 'Open',
    correlated: true,
  },
  {
    id: 'AEG-1031',
    title: 'Vulnerable dependency — lodash 4.17.15',
    cwe: 'CWE-1321',
    tool: 'Trivy',
    sev: 'high',
    status: 'Open',
    correlated: false,
  },
  {
    id: 'AEG-1028',
    title: 'Broken access control on /api/admin/users',
    cwe: 'CWE-284',
    tool: 'ZAP',
    sev: 'critical',
    status: 'Open',
    correlated: true,
  },
  {
    id: 'AEG-1024',
    title: 'XML external entity in /file/upload',
    cwe: 'CWE-611',
    tool: 'ZAP',
    sev: 'medium',
    status: 'Open',
    correlated: false,
  },
  {
    id: 'AEG-1019',
    title: 'Insecure deserialization in session handler',
    cwe: 'CWE-502',
    tool: 'Semgrep',
    sev: 'high',
    status: 'Triaged',
    correlated: false,
  },
  {
    id: 'AEG-1015',
    title: 'Server-side request forgery in /api/preview',
    cwe: 'CWE-918',
    tool: 'Semgrep',
    sev: 'medium',
    status: 'Open',
    correlated: false,
  },
  {
    id: 'AEG-1011',
    title: 'Sensitive data exposure in error responses',
    cwe: 'CWE-200',
    tool: 'ZAP',
    sev: 'low',
    status: 'Open',
    correlated: false,
  },
  {
    id: 'AEG-1006',
    title: 'Missing CSRF token on /api/profile/update',
    cwe: 'CWE-352',
    tool: 'ZAP',
    sev: 'medium',
    status: 'Resolved',
    correlated: false,
  },
];

const SESSIONS = [
  {
    ip: '185.220.101.42',
    proto: 'SSH',
    dur: '14m 22s',
    detail:
      'Credential harvesting — tried default creds (root/toor, admin/admin)',
    tag: 'Brute-force login',
    time: '09:14',
    live: true,
  },
  {
    ip: '45.155.205.19',
    proto: 'HTTP',
    dur: '—',
    detail: 'Canary hit: /wp-admin → IP flagged in Redis',
    tag: 'Automated scanner sweep',
    time: '08:52',
    live: true,
  },
  {
    ip: '91.219.237.4',
    proto: 'SSH',
    dur: '6m 03s',
    detail:
      'Read fake /etc/shadow, attempted escalation via decoy sudoers misconfig',
    tag: 'Privilege escalation probing',
    time: '08:40',
    live: true,
  },
  {
    ip: '103.74.19.61',
    proto: 'HTTP',
    dur: '—',
    detail: 'Canary hits: /.env then /phpmyadmin',
    tag: 'Credential & config harvesting',
    time: '07:58',
    live: false,
  },
  {
    ip: '185.220.101.42',
    proto: 'SSH',
    dur: '9m 47s',
    detail: 'Injected SQL into decoy internal DB shell exposed on fake host',
    tag: 'SQL injection replicated',
    time: '07:31',
    live: false,
  },
  {
    ip: '194.61.24.102',
    proto: 'Telnet',
    dur: '2m 10s',
    detail: 'Scripted payload against decoy internal admin panel',
    tag: 'XSS payload injection',
    time: '06:45',
    live: false,
  },
];

const PAIRS = [
  {
    finding: 'AEG-1042',
    title: 'SQL injection',
    cwe: 'CWE-89',
    history: ['Medium', 'High', 'Critical'],
    via: 'SQL injection replicated in decoy DB shell',
    ip: '185.220.101.42',
    time: '07:31',
  },
  {
    finding: 'AEG-1028',
    title: 'Broken access control',
    cwe: 'CWE-284',
    history: ['High', 'Critical'],
    via: 'Privilege-escalation probing via decoy sudoers path',
    ip: '91.219.237.4',
    time: '08:40',
  },
  {
    finding: 'AEG-1035',
    title: 'Reflected XSS',
    cwe: 'CWE-79',
    history: ['Medium', 'High'],
    via: 'XSS payload injection against decoy admin panel',
    ip: '194.61.24.102',
    time: '06:45',
  },
];

const ACTIONS = {
  'AEG-1042':
    'Review /rest/products/search and confirm parameterized queries are used for all user input.',
  'AEG-1039':
    'Rotate the exposed AWS keys and move deploy secrets into the secrets manager.',
  'AEG-1035':
    'Sanitize and encode output in the feedback form before rendering.',
  'AEG-1031':
    'Bump lodash to 4.17.21 or later to patch the prototype pollution path.',
  'AEG-1028':
    'Add role checks to /api/admin/users and audit existing sessions for misuse.',
  'AEG-1024':
    'Disable external entity resolution in the XML parser used by /file/upload.',
  'AEG-1019':
    'Replace raw deserialization in the session handler with a signed, typed format.',
  'AEG-1015': 'Restrict /api/preview to an allowlist of internal hosts.',
  'AEG-1011': 'Strip stack traces from production error responses.',
  'AEG-1006': 'Resolved — CSRF token is now required on /api/profile/update.',
};

const ASSETS = [
  {
    name: 'Juice Shop',
    type: 'Web application',
    icon: Server,
    status: 'at-risk',
    findings: 3,
    sevTop: 'critical',
    lastScanned: '14m ago',
  },
  {
    name: 'API Gateway',
    type: 'API',
    icon: Server,
    status: 'monitored',
    findings: 2,
    sevTop: 'medium',
    lastScanned: '14m ago',
  },
  {
    name: 'Admin Portal',
    type: 'Internal tool',
    icon: Server,
    status: 'at-risk',
    findings: 1,
    sevTop: 'critical',
    lastScanned: '14m ago',
  },
  {
    name: 'CI/CD pipeline',
    type: 'GitHub Actions',
    icon: GitMerge,
    status: 'at-risk',
    findings: 1,
    sevTop: 'critical',
    lastScanned: '1d ago',
  },
  {
    name: 'PostgreSQL',
    type: 'Database',
    icon: Database,
    status: 'clear',
    findings: 0,
    sevTop: null,
    lastScanned: '2h ago',
  },
  {
    name: 'Redis',
    type: 'Cache / flag store',
    icon: Database,
    status: 'clear',
    findings: 0,
    sevTop: null,
    lastScanned: '6h ago',
  },
];

const SEV_LABEL = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

function pairForSession(session) {
  return PAIRS.find((p) => p.ip === session.ip && p.time === session.time);
}

// ---------------------------------------------------------------------------
// Small presentational pieces
// ---------------------------------------------------------------------------

function SeverityTag({ level, large }) {
  const key = level.toLowerCase();
  return (
    <span className={`sev sev-${key} ${large ? 'sev-lg' : ''}`}>
      <span className="sev-dot" />
      {SEV_LABEL[key] || level}
    </span>
  );
}

function Chip({ children }) {
  return <span className="chip">{children}</span>;
}

function CweTag({ cwe }) {
  return <span className="cwe">{cwe}</span>;
}

function StatusText({ status }) {
  const key = status.toLowerCase();
  return (
    <span className={`status-ind status-${key}`}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

function LiveDot({ active }) {
  return <span className={`dot ${active ? 'dot-live' : ''}`} />;
}

function Sparkline({ points, width = 68, height = 20 }) {
  const max = Math.max(...points);
  const min = Math.min(...points);
  const range = max - min || 1;
  const step = width / (points.length - 1);
  const d = points
    .map(
      (p, i) =>
        `${i === 0 ? 'M' : 'L'} ${i * step} ${
          height - ((p - min) / range) * height
        }`
    )
    .join(' ');
  return (
    <svg width={width} height={height} className="sparkline">
      <path d={d} fill="none" stroke="var(--sev-high)" strokeWidth="1.5" />
    </svg>
  );
}

function DistBar({ segments }) {
  const total = segments.reduce((a, s) => a + s.value, 0) || 1;
  return (
    <div className="distbar">
      <div className="distbar-track">
        {segments.map((s) => (
          <div
            key={s.label}
            className="distbar-seg"
            style={{
              width: `${(s.value / total) * 100}%`,
              background: s.color,
            }}
            title={`${s.label}: ${s.value}`}
          />
        ))}
      </div>
      <div className="distbar-legend">
        {segments.map((s) => (
          <span key={s.label} className="distbar-legend-item">
            <span className="distbar-dot" style={{ background: s.color }} />{' '}
            {s.label} {s.value}
          </span>
        ))}
      </div>
    </div>
  );
}

function BarList({ items }) {
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="barlist">
      {items.map((i) => (
        <div className="barlist-row" key={i.label}>
          <span className="barlist-label muted">{i.label}</span>
          <div className="barlist-track">
            <div
              className="barlist-fill"
              style={{ width: `${(i.value / max) * 100}%` }}
            />
          </div>
          <span className="barlist-value mono">{i.value}</span>
        </div>
      ))}
    </div>
  );
}

function Timeline({ steps, size }) {
  return (
    <div className={`timeline ${size === 'lg' ? 'timeline-lg' : ''}`}>
      {steps.map((s, i) => {
        const last = i === steps.length - 1;
        return (
          <div className="timeline-step" key={i}>
            <span
              className={`timeline-dot timeline-dot-${s.toLowerCase()} ${
                last ? 'timeline-dot-current' : ''
              }`}
            />
            <span
              className={`timeline-label ${
                last ? 'timeline-label-current' : ''
              }`}
            >
              {s}
            </span>
            {!last && <span className="timeline-connector" />}
          </div>
        );
      })}
    </div>
  );
}

function Toggle({ checked, onChange }) {
  return (
    <button
      className={`toggle ${checked ? 'on' : ''}`}
      onClick={() => onChange(!checked)}
      aria-pressed={checked}
    >
      <span className="toggle-knob" />
    </button>
  );
}

function Segmented({ options, value, onChange }) {
  return (
    <div className="segmented">
      {options.map((o) => (
        <button
          key={o}
          className={`segmented-item ${value === o ? 'active' : ''}`}
          onClick={() => onChange(o)}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

function ConnectorRow({ pair, featured, onOpenFinding, onOpenSession }) {
  return (
    <div className={`connector ${featured ? 'connector-featured' : ''}`}>
      <div className="connector-cols">
        <button
          className="node node-clickable"
          onClick={() => onOpenFinding(pair.finding)}
        >
          <div className="node-kicker">
            <Bug size={12} strokeWidth={1.75} />
            {featured ? 'Application finding' : 'Finding'}
          </div>
          <div className="node-title mono">{pair.finding}</div>
          <div className="node-sub">{pair.title}</div>
          <CweTag cwe={pair.cwe} />
        </button>

        <div className="link">
          <div className="link-caption">matched via {pair.cwe}</div>
          <div className="link-line">
            <span className="link-track" />
            {featured && <span className="link-pulse" />}
          </div>
          <div className="link-marker" />
          {featured && <div className="link-evidence">+ evidence</div>}
        </div>

        <button
          className="node node-clickable node-align-right"
          onClick={() => onOpenSession(pair)}
        >
          <div className="node-kicker node-kicker-right">
            {featured ? 'Live attack signal' : 'Honeypot session'}
            <Radio size={12} strokeWidth={1.75} />
          </div>
          <div className="node-title mono">{pair.ip}</div>
          <div className="node-sub">{pair.via}</div>
          <span className="feed-time">{pair.time}</span>
        </button>
      </div>

      <div className="delta">
        <Timeline steps={pair.history} size={featured ? 'lg' : undefined} />
        <span className="delta-note">re-prioritized</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

function Overview({ findings, onOpenFinding, onOpenSession, selectedId }) {
  const open = findings.filter((f) => f.status !== 'Resolved');
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  const critical = open.filter((f) => f.sev === 'critical').length;
  const high = open.filter((f) => f.sev === 'high').length;
  const medium = open.filter((f) => f.sev === 'medium').length;
  const low = open.filter((f) => f.sev === 'low').length;
  const liveCount = SESSIONS.filter((s) => s.live).length;
  const topPair = PAIRS[0];
  const otherPairs = PAIRS.slice(1);
  const topFindings = [...open]
    .sort((a, b) => rank[a.sev] - rank[b.sev])
    .slice(0, 5);

  const segments = [
    { label: 'Critical', value: critical, color: 'var(--sev-critical)' },
    { label: 'High', value: high, color: 'var(--sev-high)' },
    { label: 'Medium', value: medium, color: 'var(--sev-medium)' },
    { label: 'Low', value: low, color: 'var(--sev-low)' },
  ];

  return (
    <>
      <div className="posture">
        <div className="posture-title-row">
          <span className="posture-context">Security posture · staging</span>
          <span className="posture-updated">Updated 14m ago</span>
        </div>

        <div className="posture-main">
          <div className="risk-score">
            <div className="risk-score-value mono">68</div>
            <div className="risk-score-label">Risk score</div>
            <div className="risk-score-trend">
              <Sparkline points={[38, 44, 41, 52, 49, 60, 68]} />
              <span className="risk-score-delta">+12 this week</span>
            </div>
          </div>

          <div className="posture-stats">
            <div className="posture-stat">
              <AlertTriangle
                size={14}
                strokeWidth={1.75}
                className="stat-icon stat-icon-critical"
              />
              <div>
                <div className="posture-stat-value mono">{critical}</div>
                <div className="posture-stat-label">Critical findings</div>
              </div>
            </div>
            <div className="posture-stat">
              <Radio
                size={14}
                strokeWidth={1.75}
                className="stat-icon stat-icon-signal"
              />
              <div>
                <div className="posture-stat-value mono">{liveCount}</div>
                <div className="posture-stat-label">Active attacks</div>
              </div>
            </div>
            <div className="posture-stat">
              <GitMerge
                size={14}
                strokeWidth={1.75}
                className="stat-icon stat-icon-signal"
              />
              <div>
                <div className="posture-stat-value mono">{PAIRS.length}</div>
                <div className="posture-stat-label">Correlated threats</div>
              </div>
            </div>
          </div>
        </div>

        <DistBar segments={segments} />
      </div>

      <div className="panel panel-signal panel-hero">
        <div className="panel-header">
          <span>Live correlation</span>
          <span className="panel-header-sub">
            Reassessed as attacker behavior matches known findings
          </span>
        </div>
        <div className="hero-body">
          <ConnectorRow
            pair={topPair}
            featured
            onOpenFinding={onOpenFinding}
            onOpenSession={onOpenSession}
          />
          {otherPairs.length > 0 && (
            <div className="hero-more">
              <div className="hero-more-label">Also matched today</div>
              {otherPairs.map((p) => (
                <button
                  key={p.finding}
                  className="hero-more-row"
                  onClick={() => onOpenFinding(p.finding)}
                >
                  <span className="mono">{p.finding}</span>
                  <span className="hero-more-title">{p.title}</span>
                  <SeverityTag level={p.history[p.history.length - 1]} />
                  <ChevronRight
                    size={14}
                    strokeWidth={1.75}
                    className="hero-more-chevron"
                  />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="split-grid">
        <div className="panel panel-support">
          <div className="panel-header">
            <span>Top findings</span>
            <span className="panel-header-sub">supporting</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Finding</th>
                <th>CWE</th>
                <th>Severity</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((f) => (
                <tr
                  key={f.id}
                  className={`row-clickable ${
                    selectedId === f.id ? 'row-selected' : ''
                  }`}
                  onClick={() => onOpenFinding(f.id)}
                >
                  <td className="mono muted">{f.id}</td>
                  <td>{f.title}</td>
                  <td>
                    <CweTag cwe={f.cwe} />
                  </td>
                  <td>
                    <SeverityTag level={f.sev} />
                  </td>
                  <td>
                    <ChevronRight
                      size={14}
                      strokeWidth={1.75}
                      className="row-chevron"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel panel-support">
          <div className="panel-header">
            <span>Honeypot activity</span>
            <span className="panel-header-sub">live</span>
          </div>
          <div className="feed">
            {SESSIONS.slice(0, 4).map((s, i) => (
              <div
                className="feed-row feed-row-clickable"
                key={i}
                onClick={() => onOpenSession(s)}
              >
                <div className="feed-top">
                  <span className="mono">{s.ip}</span>
                  <span className="feed-time">{s.time}</span>
                </div>
                <div className="feed-detail">{s.detail}</div>
                <div className="feed-tag">
                  <LiveDot active={s.live} /> {s.tag}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}

function FindingsView({ findings, search, onOpenFinding, selectedId }) {
  const q = search.trim().toLowerCase();
  const rows = q
    ? findings.filter(
        (f) =>
          f.id.toLowerCase().includes(q) ||
          f.title.toLowerCase().includes(q) ||
          f.cwe.toLowerCase().includes(q)
      )
    : findings;

  return (
    <div className="panel">
      <div className="panel-header">
        <span>All findings</span>
        <span className="panel-header-sub">
          {rows.length} of {findings.length}
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Finding</th>
            <th>CWE</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Live match</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => (
            <tr
              key={f.id}
              className={`row-clickable ${
                selectedId === f.id ? 'row-selected' : ''
              }`}
              onClick={() => onOpenFinding(f.id)}
            >
              <td className="mono muted">{f.id}</td>
              <td>{f.title}</td>
              <td>
                <CweTag cwe={f.cwe} />
              </td>
              <td className="muted">{f.tool}</td>
              <td>
                <SeverityTag level={f.sev} />
              </td>
              <td>
                <StatusText status={f.status} />
              </td>
              <td>
                {f.correlated ? (
                  <span className="corr-yes">
                    <LiveDot active /> matched
                  </span>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td>
                <ChevronRight
                  size={14}
                  strokeWidth={1.75}
                  className="row-chevron"
                />
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={8} className="empty-row muted">
                No findings match "{search}"
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function HoneypotView({ onOpenSession, onOpenFinding }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span>Session log</span>
        <span className="panel-header-sub">
          Cowrie · deception depth: credentials, topology, escalation paths
        </span>
      </div>
      <div className="feed feed-wide">
        {SESSIONS.map((s, i) => {
          const pair = pairForSession(s);
          return (
            <div
              className="feed-row feed-row-clickable"
              key={i}
              onClick={() => onOpenSession(s)}
            >
              <div className="feed-top">
                <span className="mono">{s.ip}</span>
                <Chip>{s.proto}</Chip>
                <span className="muted">{s.dur}</span>
                <span className="feed-time">{s.time}</span>
              </div>
              <div className="feed-detail">{s.detail}</div>
              <div className="feed-bottom">
                <span className="feed-tag">
                  <LiveDot active={s.live} /> {s.tag}
                </span>
                {pair && (
                  <button
                    className="linked-chip"
                    onClick={(e) => {
                      e.stopPropagation();
                      onOpenFinding(pair.finding, {
                        kind: 'session',
                        session: s,
                      });
                    }}
                  >
                    <Link2 size={11} strokeWidth={1.75} /> Linked ·{' '}
                    {pair.finding}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CorrelationView({ onOpenFinding, onOpenSession }) {
  return (
    <div className="panel panel-signal">
      <div className="panel-header">
        <span>Correlation engine</span>
        <span className="panel-header-sub">
          {PAIRS.length} open findings re-prioritized by live attacker activity
        </span>
      </div>
      <p className="lede">
        When a CWE tag observed in a honeypot session matches an open finding,
        the finding is re-scored and moved up the queue — independent of whether
        a CVE has been published for it yet. Select a finding or a session to
        see the evidence.
      </p>
      <div className="corr-list-full">
        {PAIRS.map((p) => (
          <ConnectorRow
            key={p.finding}
            pair={p}
            onOpenFinding={onOpenFinding}
            onOpenSession={onOpenSession}
          />
        ))}
      </div>
    </div>
  );
}

function AssetsView() {
  return (
    <div className="panel">
      <div className="panel-header">
        <span>Assets</span>
        <span className="panel-header-sub">{ASSETS.length} monitored</span>
      </div>
      <div className="asset-list">
        {ASSETS.map((a) => (
          <div className="asset-row" key={a.name}>
            <a.icon size={16} strokeWidth={1.75} className="asset-icon" />
            <div className="asset-main">
              <div className="asset-name">{a.name}</div>
              <div className="asset-type muted">{a.type}</div>
            </div>
            <div className={`asset-status asset-status-${a.status}`}>
              <span className="asset-status-dot" />
              {a.status === 'at-risk'
                ? 'At risk'
                : a.status === 'monitored'
                ? 'Monitored'
                : 'Clear'}
            </div>
            <div className="asset-findings">
              {a.findings > 0 ? (
                <span className={`badge badge-${a.sevTop}`}>
                  {a.findings} open
                </span>
              ) : (
                <span className="muted">No open findings</span>
              )}
            </div>
            <div className="asset-scanned muted">{a.lastScanned}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportsView({ findings, pushToast }) {
  const [generating, setGenerating] = useState(false);
  const [reports, setReports] = useState([
    { name: 'Weekly summary — Sep 5', size: '212 KB' },
    { name: 'Weekly summary — Aug 29', size: '198 KB' },
  ]);

  const open = findings.filter((f) => f.status !== 'Resolved');
  const sevCounts = ['critical', 'high', 'medium', 'low'].map((s) => ({
    label: SEV_LABEL[s],
    value: open.filter((f) => f.sev === s).length,
    color: `var(--sev-${s})`,
  }));
  const toolCounts = ['Semgrep', 'Trivy', 'Gitleaks', 'ZAP'].map((t) => ({
    label: t,
    value: findings.filter((f) => f.tool === t).length,
  }));

  function generate() {
    if (generating) return;
    setGenerating(true);
    setTimeout(() => {
      setGenerating(false);
      setReports((r) => [
        { name: 'Weekly summary — Sep 12', size: '224 KB' },
        ...r,
      ]);
      pushToast('Report generated — aegis-report-2026-09-12.pdf', 'signal');
    }, 1300);
  }

  return (
    <div className="reports-grid">
      <div className="panel">
        <div className="panel-header">
          <span>Last scan</span>
        </div>
        <div className="drawer-section" style={{ padding: '14px 18px' }}>
          <div className="drawer-row">
            <span className="drawer-row-label">Completed</span>
            <span>14 minutes ago</span>
          </div>
          <div className="drawer-row">
            <span className="drawer-row-label">Duration</span>
            <span>3m 42s</span>
          </div>
          <div className="drawer-row">
            <span className="drawer-row-label">Tools run</span>
            <span>Semgrep, Trivy, Gitleaks, ZAP</span>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Findings by severity</span>
        </div>
        <div style={{ padding: '14px 18px' }}>
          <DistBar segments={sevCounts} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Findings by source</span>
        </div>
        <div style={{ padding: '14px 18px' }}>
          <BarList items={toolCounts} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Correlation summary</span>
        </div>
        <div className="drawer-section" style={{ padding: '14px 18px' }}>
          <div className="drawer-row">
            <span className="drawer-row-label">Matches this week</span>
            <span>{PAIRS.length}</span>
          </div>
          <div className="drawer-row">
            <span className="drawer-row-label">Avg. re-prioritization</span>
            <span>+1.3 severity levels</span>
          </div>
        </div>
      </div>

      <div className="panel reports-panel-wide">
        <div className="panel-header">
          <span>Generate report</span>
          <button className="btn-run" onClick={generate} disabled={generating}>
            {generating ? (
              <>
                <Loader2 size={13} strokeWidth={1.75} className="spin" />{' '}
                Generating…
              </>
            ) : (
              <>
                <FileText size={13} strokeWidth={1.75} /> Generate report
              </>
            )}
          </button>
        </div>
        <div className="report-list">
          {reports.map((r, i) => (
            <div className="report-row" key={i}>
              <FileText size={14} strokeWidth={1.75} className="asset-icon" />
              <span>{r.name}</span>
              <span className="muted">{r.size}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SettingsView() {
  const [autoScan, setAutoScan] = useState(true);
  const [depth, setDepth] = useState('High');
  const [sensitivity, setSensitivity] = useState('Medium');

  const scanners = [
    { name: 'Semgrep', version: 'v1.78.0', status: 'Operational' },
    { name: 'Trivy', version: 'v0.52.0', status: 'Operational' },
    { name: 'Gitleaks', version: 'v8.18.2', status: 'Operational' },
    { name: 'ZAP', version: 'v2.15.0', status: 'Queued' },
  ];

  return (
    <div className="settings-grid">
      <div className="panel">
        <div className="panel-header">
          <span>Scan schedule</span>
        </div>
        <div className="settings-row">
          <div>
            <div className="settings-row-title">Automatic scanning</div>
            <div className="settings-row-sub muted">
              Full scan every 6 hours. Next run in 5h 46m.
            </div>
          </div>
          <Toggle checked={autoScan} onChange={setAutoScan} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Scanner status</span>
        </div>
        {scanners.map((s) => (
          <div className="settings-row settings-row-compact" key={s.name}>
            <div className="settings-row-main">
              <LiveDot active={s.status === 'Operational'} />
              <span>{s.name}</span>
              <span className="muted mono">{s.version}</span>
            </div>
            <span className="muted">{s.status}</span>
          </div>
        ))}
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Honeypot status</span>
        </div>
        <div className="settings-row">
          <div className="settings-row-main">
            <LiveDot active /> Cowrie
          </div>
          <span className="muted">
            Running · 14d 6h uptime · 3 active sessions
          </span>
        </div>
        <div className="settings-row">
          <div>
            <div className="settings-row-title">Deception depth</div>
            <div className="settings-row-sub muted">
              Fake credentials, topology, and near-miss escalation paths.
            </div>
          </div>
          <Segmented
            options={['Low', 'Medium', 'High']}
            value={depth}
            onChange={setDepth}
          />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Correlation sensitivity</span>
        </div>
        <div className="settings-row">
          <div>
            <div className="settings-row-title">Match threshold</div>
            <div className="settings-row-sub muted">
              How closely a honeypot technique must match a finding's CWE before
              it's re-prioritized.
            </div>
          </div>
          <Segmented
            options={['Low', 'Medium', 'High']}
            value={sensitivity}
            onChange={setSensitivity}
          />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Drawer
// ---------------------------------------------------------------------------

function Drawer({
  drawer,
  findings,
  onClose,
  onMarkTriaged,
  onOpenFinding,
  onOpenSession,
}) {
  const open = !!drawer;
  let content = null;

  if (drawer && drawer.kind === 'finding') {
    const finding = findings.find((f) => f.id === drawer.id);
    const pair = finding ? PAIRS.find((p) => p.finding === finding.id) : null;
    if (finding) {
      content = (
        <>
          <div className="drawer-header">
            <div>
              <div className="drawer-id mono">{finding.id}</div>
              <div className="drawer-title">{finding.title}</div>
            </div>
            <button className="drawer-close" onClick={onClose}>
              <X size={16} strokeWidth={1.75} />
            </button>
          </div>
          <div className="drawer-tags">
            <SeverityTag level={finding.sev} large />
            <CweTag cwe={finding.cwe} />
          </div>

          <div className="drawer-divider" />

          <div className="drawer-section">
            <div className="drawer-section-title">Why this matters</div>
            <div className="drawer-row">
              <span className="drawer-row-label">Detected by</span>
              <span>{finding.tool}</span>
            </div>
            <div className="drawer-row drawer-row-block">
              <span className="drawer-row-label">Live attacker evidence</span>
              {pair ? (
                <div className="evidence">
                  <div className="evidence-top">
                    <LiveDot active /> <span className="mono">{pair.ip}</span>
                  </div>
                  <div className="evidence-detail">{pair.via}</div>
                </div>
              ) : (
                <span className="muted">No live match yet</span>
              )}
            </div>
          </div>

          <div className="drawer-divider" />

          <div className="drawer-section">
            <div className="drawer-section-title">Risk history</div>
            <Timeline
              steps={
                pair
                  ? pair.history
                  : [finding.sev.charAt(0).toUpperCase() + finding.sev.slice(1)]
              }
            />
          </div>

          <div className="drawer-divider" />

          <div className="drawer-section">
            <div className="drawer-section-title">Recommended action</div>
            <p className="drawer-action-text">{ACTIONS[finding.id]}</p>
          </div>

          <div className="drawer-actions">
            <button
              className="btn-secondary"
              disabled={
                finding.status === 'Triaged' || finding.status === 'Resolved'
              }
              onClick={() => onMarkTriaged(finding.id)}
            >
              {finding.status === 'Triaged' ? (
                <>
                  <Check size={13} strokeWidth={1.75} /> Triaged
                </>
              ) : (
                'Mark triaged'
              )}
            </button>
            <button
              className="btn-ghost"
              disabled={!pair}
              onClick={() =>
                pair && onOpenSession(pair, { kind: 'finding', id: finding.id })
              }
            >
              View evidence
            </button>
          </div>
        </>
      );
    }
  }

  if (drawer && drawer.kind === 'session') {
    const session = drawer.session;
    const pair = session ? pairForSession(session) : null;
    if (session) {
      content = (
        <>
          <div className="drawer-header">
            <div>
              <div className="drawer-id mono">{session.ip}</div>
              <div className="drawer-title">Honeypot session</div>
            </div>
            <button className="drawer-close" onClick={onClose}>
              <X size={16} strokeWidth={1.75} />
            </button>
          </div>
          <div className="drawer-tags">
            <Chip>{session.proto}</Chip>
            {session.live && (
              <span className="corr-yes">
                <LiveDot active /> live
              </span>
            )}
          </div>

          <div className="drawer-divider" />

          <div className="drawer-section">
            <div className="drawer-row">
              <span className="drawer-row-label">Duration</span>
              <span>{session.dur}</span>
            </div>
            <div className="drawer-row">
              <span className="drawer-row-label">Observed</span>
              <span>{session.time}</span>
            </div>
            <div className="drawer-row drawer-row-block">
              <span className="drawer-row-label">Behavior</span>
              <span>{session.detail}</span>
            </div>
            <div className="drawer-row">
              <span className="drawer-row-label">Technique</span>
              <span>{session.tag}</span>
            </div>
          </div>

          {pair && (
            <>
              <div className="drawer-divider" />
              <div className="drawer-section">
                <div className="drawer-section-title">Linked finding</div>
                <button
                  className="linked-finding"
                  onClick={() =>
                    onOpenFinding(pair.finding, { kind: 'session', session })
                  }
                >
                  <span className="mono">{pair.finding}</span>
                  <span className="linked-finding-title">{pair.title}</span>
                  <ChevronRight size={14} strokeWidth={1.75} />
                </button>
              </div>
            </>
          )}
        </>
      );
    }
  }

  return (
    <>
      <div className={`overlay ${open ? 'open' : ''}`} onClick={onClose} />
      <aside className={`drawer ${open ? 'open' : ''}`}>
        {drawer && drawer.returnTo && (
          <button
            className="drawer-back"
            onClick={() => {
              const rt = drawer.returnTo;
              if (rt.kind === 'session') onOpenSession(rt.session, null);
              else onOpenFinding(rt.id, null);
            }}
          >
            <ChevronLeft size={13} strokeWidth={1.75} /> Back to{' '}
            {drawer.returnTo.kind === 'session'
              ? drawer.returnTo.session.ip
              : drawer.returnTo.id}
          </button>
        )}
        {content}
      </aside>
    </>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export default function AegisWireframe() {
  const [view, setView] = useState('overview');
  const [findings, setFindings] = useState(FINDINGS);
  const [drawer, setDrawer] = useState(null);
  const [search, setSearch] = useState('');
  const [toasts, setToasts] = useState([]);
  const [scanState, setScanState] = useState('idle');
  const [scanStep, setScanStep] = useState(0);
  const searchRef = useRef(null);
  const scanTools = ['Semgrep', 'Trivy', 'Gitleaks', 'ZAP'];

  useEffect(() => {
    function handler(e) {
      const tag = document.activeElement && document.activeElement.tagName;
      const typing = tag === 'INPUT' || tag === 'TEXTAREA';
      if (e.key === '/' && !typing) {
        e.preventDefault();
        searchRef.current && searchRef.current.focus();
      }
      if (e.key === 'Escape') setDrawer(null);
    }
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  function pushToast(message, tone) {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  }

  function markTriaged(id) {
    setFindings((fs) =>
      fs.map((f) => (f.id === id ? { ...f, status: 'Triaged' } : f))
    );
    pushToast(`${id} marked as triaged`, 'default');
  }

  function openFinding(id, returnTo) {
    setDrawer({ kind: 'finding', id, returnTo: returnTo || null });
  }

  function openSession(ref, returnTo) {
    const session =
      SESSIONS.find((s) => s.ip === ref.ip && s.time === ref.time) || ref;
    setDrawer({ kind: 'session', session, returnTo: returnTo || null });
  }

  function closeDrawer() {
    setDrawer(null);
  }

  function runScan() {
    if (scanState === 'running') return;
    setScanState('running');
    setScanStep(0);
    let i = 0;
    const iv = setInterval(() => {
      i++;
      setScanStep(i);
      if (i >= scanTools.length) {
        clearInterval(iv);
        setTimeout(() => {
          setScanState('done');
          pushToast('Scan complete — 1 finding re-prioritized', 'signal');
          setTimeout(() => setScanState('idle'), 1600);
        }, 400);
      }
    }, 550);
  }

  const current = NAV.find((n) => n.id === view);
  const selectedId = drawer && drawer.kind === 'finding' ? drawer.id : null;
  const navPrimary = NAV.slice(0, 4);
  const navSecondary = NAV.slice(4);

  return (
    <div className="aegis">
      <style>{`
        .aegis {
          --bg: #14161A;
          --surface: #1A1D22;
          --surface-raised: #20242A;
          --border: #292D34;
          --border-strong: #383D46;
          --text-primary: #ECEDEE;
          --text-secondary: #98A0AB;
          --text-tertiary: #575E68;
          --signal: #4FA090;
          --sev-critical: #C1503A;
          --sev-high: #C98A44;
          --sev-medium: #A69350;
          --sev-low: #5C7A94;
          --ease: cubic-bezier(0.4, 0, 0.2, 1);

          font-family: 'IBM Plex Sans', -apple-system, sans-serif;
          background: var(--bg);
          color: var(--text-primary);
          display: flex;
          min-height: 640px;
          border: 1px solid var(--border);
          font-size: 13px;
          line-height: 1.45;
          position: relative;
          overflow: hidden;
          -webkit-font-smoothing: antialiased;
        }
        .aegis * { box-sizing: border-box; }
        .aegis *:focus-visible { outline: 2px solid var(--signal); outline-offset: 2px; }
        .mono { font-family: 'IBM Plex Mono', monospace; font-variant-numeric: tabular-nums; }
        .muted { color: var(--text-secondary); }

        /* -------- sidebar -------- */
        .sidebar { width: 204px; flex-shrink: 0; border-right: 1px solid var(--border); padding: 18px 0; display: flex; flex-direction: column; }
        .brand { display: flex; align-items: center; gap: 9px; padding: 0 20px 18px 20px; margin-bottom: 10px; border-bottom: 1px solid var(--border); }
        .brand-mark { width: 7px; height: 7px; background: var(--signal); flex-shrink: 0; }
        .brand-name { font-family: 'IBM Plex Mono', monospace; font-size: 13px; letter-spacing: 0.07em; font-weight: 500; }
        .nav { display: flex; flex-direction: column; gap: 1px; }
        .nav-item {
          display: flex; align-items: center; gap: 10px; text-align: left; background: none;
          border: none; border-left: 2px solid transparent; color: var(--text-secondary);
          font-family: inherit; font-size: 13px; padding: 7px 20px; cursor: pointer;
          transition: background-color .13s var(--ease), color .13s var(--ease), border-color .13s var(--ease);
        }
        .nav-item:hover { color: var(--text-primary); background: var(--surface); }
        .nav-item.active { color: var(--text-primary); border-left-color: var(--text-primary); background: var(--surface-raised); font-weight: 500; }
        .nav-icon { flex-shrink: 0; opacity: 0.6; transition: opacity .13s var(--ease); }
        .nav-item:hover .nav-icon, .nav-item.active .nav-icon { opacity: 0.95; }
        .nav-divider { height: 1px; background: var(--border); margin: 9px 20px; }

        /* -------- main -------- */
        .main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
        .topbar { display: flex; align-items: center; justify-content: space-between; height: 54px; padding: 0 24px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
        .topbar-left { display: flex; align-items: center; gap: 12px; }
        .topbar-title { font-size: 14.5px; font-weight: 600; letter-spacing: -0.01em; }
        .topbar-divider { width: 1px; height: 13px; background: var(--border-strong); }
        .topbar-env { font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; color: var(--text-tertiary); }
        .topbar-right { display: flex; align-items: center; gap: 10px; }
        .search-wrap { position: relative; display: flex; align-items: center; }
        .search-icon { position: absolute; left: 9px; color: var(--text-tertiary); pointer-events: none; }
        .search {
          width: 216px; background: var(--surface); border: 1px solid var(--border); color: var(--text-primary);
          font-family: inherit; font-size: 12.5px; padding: 6px 30px 6px 28px;
          transition: border-color .13s var(--ease), background-color .13s var(--ease);
        }
        .search::placeholder { color: var(--text-tertiary); }
        .search:hover { border-color: var(--border-strong); }
        .search:focus { outline: none; border-color: var(--border-strong); background: var(--surface-raised); }
        .kbd-hint { position: absolute; right: 8px; font-size: 10px; color: var(--text-tertiary); border: 1px solid var(--border-strong); padding: 1px 5px; pointer-events: none; font-family: 'IBM Plex Mono', monospace; }
        .btn-run {
          display: flex; align-items: center; gap: 7px; background: var(--surface-raised); border: 1px solid var(--border-strong);
          color: var(--text-primary); font-family: inherit; font-size: 12.5px; font-weight: 500; padding: 7px 13px; cursor: pointer;
          transition: border-color .13s var(--ease), color .13s var(--ease);
        }
        .btn-run:hover:not(:disabled) { border-color: var(--signal); }
        .btn-run:disabled { cursor: default; color: var(--text-secondary); }

        .content { padding: 28px; overflow-y: auto; flex: 1; }

        /* -------- posture -------- */
        .posture { padding-bottom: 22px; margin-bottom: 24px; border-bottom: 1px solid var(--border); }
        .posture-title-row { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 20px; }
        .posture-context { font-size: 12.5px; color: var(--text-secondary); }
        .posture-updated { font-size: 11px; color: var(--text-tertiary); }
        .posture-main { display: flex; align-items: flex-start; gap: 44px; margin-bottom: 18px; flex-wrap: wrap; }
        .risk-score { display: flex; flex-direction: column; min-width: 130px; }
        .risk-score-value { font-size: 32px; font-weight: 600; line-height: 1; color: var(--text-primary); letter-spacing: -0.01em; }
        .risk-score-label { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-tertiary); margin-top: 7px; }
        .risk-score-trend { display: flex; align-items: center; gap: 8px; margin-top: 11px; }
        .risk-score-delta { font-size: 11px; color: var(--sev-high); }
        .posture-stats { display: flex; gap: 34px; padding-top: 3px; flex-wrap: wrap; }
        .posture-stat { display: flex; align-items: flex-start; gap: 9px; }
        .stat-icon { margin-top: 3px; }
        .stat-icon-critical { color: var(--sev-critical); }
        .stat-icon-signal { color: var(--signal); }
        .posture-stat-value { font-size: 20px; font-weight: 600; letter-spacing: -0.01em; }
        .posture-stat-label { font-size: 10.5px; color: var(--text-tertiary); margin-top: 3px; }

        .distbar { margin-top: 4px; }
        .distbar-track { display: flex; height: 4px; width: 100%; background: var(--border); overflow: hidden; }
        .distbar-seg { height: 100%; }
        .distbar-legend { display: flex; gap: 18px; margin-top: 9px; flex-wrap: wrap; }
        .distbar-legend-item { font-size: 11px; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; }
        .distbar-dot { width: 6px; height: 6px; display: inline-block; }

        .barlist { display: flex; flex-direction: column; gap: 11px; }
        .barlist-row { display: grid; grid-template-columns: 70px 1fr 24px; align-items: center; gap: 10px; }
        .barlist-label { font-size: 11.5px; }
        .barlist-track { height: 4px; background: var(--border); }
        .barlist-fill { height: 100%; background: var(--signal); }
        .barlist-value { font-size: 11.5px; text-align: right; }

        /* -------- panels -------- */
        .split-grid { display: grid; grid-template-columns: 1.5fr 1fr; gap: 18px; margin-bottom: 18px; }
        .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 3px; }
        .panel-signal { border-color: rgba(79,160,144,0.4); position: relative; }
        .panel-signal::before { content: ""; position: absolute; top: -1px; left: -1px; right: -1px; height: 2px; background: var(--signal); border-radius: 3px 3px 0 0; }
        .panel-hero { margin-bottom: 18px; }
        .panel-header { display: flex; justify-content: space-between; align-items: center; padding: 13px 18px; border-bottom: 1px solid var(--border); font-size: 13px; font-weight: 600; letter-spacing: -0.01em; gap: 12px; }
        .panel-header-sub { font-size: 11px; font-weight: 400; letter-spacing: 0; color: var(--text-tertiary); }
        .panel-support .panel-header { font-size: 12px; font-weight: 500; color: var(--text-secondary); }
        .lede { padding: 15px 18px 0 18px; color: var(--text-secondary); font-size: 12.5px; max-width: 70ch; }

        .hero-body { padding: 18px; }
        .hero-more { margin-top: 16px; border-top: 1px solid var(--border); padding-top: 12px; }
        .hero-more-label { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-tertiary); margin-bottom: 6px; }
        .hero-more-row {
          width: 100%; display: flex; align-items: center; gap: 12px; background: none; border: none;
          padding: 9px 8px; font-family: inherit; font-size: 12.5px; color: var(--text-primary); cursor: pointer; text-align: left;
          transition: background-color .13s var(--ease);
        }
        .hero-more-row:hover { background: var(--surface-raised); }
        .hero-more-title { flex: 1; color: var(--text-secondary); }
        .hero-more-chevron { color: var(--text-tertiary); }

        /* -------- correlation connector -------- */
        .connector { padding: 16px; background: var(--surface-raised); border: 1px solid var(--border); border-radius: 3px; }
        .connector-featured { padding: 26px; background: rgba(79,160,144,0.035); border: 1px solid rgba(79,160,144,0.25); }
        .connector-cols { display: grid; grid-template-columns: 1fr 150px 1fr; align-items: center; gap: 14px; }
        .connector-featured .connector-cols { grid-template-columns: 1fr 190px 1fr; }
        .node { width: 100%; text-align: left; background: none; border: 1px solid transparent; padding: 9px; border-radius: 2px; font-family: inherit; color: inherit; cursor: pointer; transition: background-color .13s var(--ease), border-color .13s var(--ease); }
        .node-clickable:hover { background: var(--surface); border-color: var(--border-strong); }
        .node-align-right { text-align: right; }
        .node-kicker { display: flex; align-items: center; gap: 6px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-tertiary); margin-bottom: 9px; }
        .node-kicker-right { justify-content: flex-end; }
        .node-title { font-size: 12.5px; font-weight: 500; margin-bottom: 3px; }
        .connector-featured .node-title { font-size: 15px; }
        .node-sub { font-size: 11.5px; color: var(--text-secondary); margin-bottom: 6px; }
        .link { display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .link-caption { font-size: 9.5px; color: var(--text-tertiary); margin-bottom: 5px; text-align: center; white-space: nowrap; }
        .link-line { width: 100%; height: 1px; position: relative; }
        .link-track { position: absolute; inset: 0; background: var(--border-strong); }
        .link-pulse { position: absolute; top: -1.5px; left: 0; width: 4px; height: 4px; border-radius: 50%; background: var(--signal); box-shadow: 0 0 4px rgba(79,160,144,0.7); }
        @media (prefers-reduced-motion: no-preference) { .link-pulse { animation: travel 2.6s linear infinite; } }
        @keyframes travel { 0% { left: 0%; opacity: 0; } 8% { opacity: 1; } 92% { opacity: 1; } 100% { left: calc(100% - 4px); opacity: 0; } }
        .link-marker { width: 6px; height: 6px; background: var(--signal); transform: rotate(45deg); margin-top: -3.5px; }
        .link-evidence { font-size: 10px; color: var(--signal); margin-top: 9px; }
        .delta { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--border); flex-wrap: wrap; }
        .delta-note { font-size: 10.5px; color: var(--text-tertiary); font-style: italic; }
        .corr-list-full { display: flex; flex-direction: column; gap: 20px; padding: 18px; }

        /* -------- severity / status / chips -------- */
        .sev { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 500; }
        .sev-lg { font-size: 13px; gap: 7px; }
        .sev-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex-shrink: 0; }
        .sev-lg .sev-dot { width: 7px; height: 7px; }
        .sev-critical { color: var(--sev-critical); }
        .sev-high { color: var(--sev-high); }
        .sev-medium { color: var(--sev-medium); }
        .sev-low { color: var(--sev-low); }

        .chip { display: inline-block; font-size: 10.5px; padding: 2px 7px; border: 1px solid var(--border-strong); color: var(--text-secondary); background: var(--surface); font-family: 'IBM Plex Mono', monospace; }

        .badge { font-size: 11px; padding: 2px 7px; border: 1px solid; border-radius: 2px; font-weight: 500; }
        .badge-critical { color: var(--sev-critical); border-color: var(--sev-critical); background: rgba(193,80,58,0.08); }
        .badge-high { color: var(--sev-high); border-color: var(--sev-high); background: rgba(201,138,68,0.08); }
        .badge-medium { color: var(--sev-medium); border-color: var(--sev-medium); background: rgba(166,147,80,0.08); }
        .badge-low { color: var(--sev-low); border-color: var(--sev-low); background: rgba(92,122,148,0.08); }

        .status-ind { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; }
        .status-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; }
        .status-open { color: var(--text-primary); }
        .status-triaged { color: var(--text-secondary); }
        .status-resolved { color: var(--text-tertiary); }

        .cwe { font-family: 'IBM Plex Mono', monospace; font-size: 10.5px; color: var(--text-secondary); border: 1px solid var(--border-strong); padding: 1px 6px; }
        .corr-yes { display: flex; align-items: center; gap: 6px; color: var(--signal); font-size: 12px; }
        .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--text-tertiary); display: inline-block; }
        .dot-live { background: var(--signal); }
        @media (prefers-reduced-motion: no-preference) { .dot-live { animation: pulse 2.2s ease-in-out infinite; } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
        .spin { animation: spin 0.9s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* -------- tables -------- */
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 9px 18px; font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-tertiary); border-bottom: 1px solid var(--border-strong); }
        td { padding: 10px 18px; border-bottom: 1px solid var(--border); font-size: 12.5px; vertical-align: middle; transition: background-color .12s var(--ease); }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--surface-raised); }
        tr.row-clickable { cursor: pointer; }
        tr.row-clickable td:first-child { border-left: 2px solid transparent; transition: background-color .12s var(--ease), border-color .12s var(--ease); }
        tr.row-selected td { background: var(--surface-raised); }
        tr.row-selected td:first-child { border-left-color: var(--signal); }
        .row-chevron { color: var(--text-tertiary); opacity: 0; transform: translateX(-4px); transition: opacity .15s var(--ease), transform .15s var(--ease); }
        tr.row-clickable:hover .row-chevron { opacity: 1; transform: translateX(0); }
        .empty-row { text-align: center; padding: 26px !important; }

        /* -------- feed -------- */
        .feed { display: flex; flex-direction: column; }
        .feed-row { padding: 11px 18px; border-bottom: 1px solid var(--border); border-left: 2px solid transparent; transition: background-color .12s var(--ease), border-color .12s var(--ease); }
        .feed-row:last-child { border-bottom: none; }
        .feed-row-clickable { cursor: pointer; }
        .feed-row-clickable:hover { background: var(--surface-raised); border-left-color: var(--signal); }
        .feed-top { display: flex; align-items: center; gap: 10px; font-size: 12px; margin-bottom: 5px; flex-wrap: wrap; }
        .feed-time { color: var(--text-tertiary); margin-left: auto; font-family: 'IBM Plex Mono', monospace; font-size: 11px; }
        .feed-detail { color: var(--text-secondary); font-size: 12px; margin-bottom: 6px; }
        .feed-tag { font-size: 11.5px; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; }
        .feed-bottom { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
        .feed-wide .feed-row { padding: 13px 18px; }
        .linked-chip { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; background: none; border: 1px solid var(--border-strong); color: var(--signal); padding: 3px 9px; cursor: pointer; font-family: inherit; transition: border-color .13s var(--ease); }
        .linked-chip:hover { border-color: var(--signal); }

        /* -------- drawer / overlay -------- */
        .overlay { position: fixed; inset: 0; background: rgba(8,9,11,0.6); opacity: 0; pointer-events: none; transition: opacity .2s var(--ease); z-index: 40; }
        .overlay.open { opacity: 1; pointer-events: auto; }
        .drawer {
          position: fixed; top: 0; right: 0; height: 100%; width: 400px; max-width: 92vw; background: var(--surface);
          border-left: 1px solid var(--border-strong); transform: translateX(100%); opacity: 0;
          transition: transform .26s var(--ease), opacity .2s var(--ease); z-index: 41; overflow-y: auto; padding: 24px;
        }
        .drawer.open { transform: translateX(0); opacity: 1; }
        .drawer-back { display: flex; align-items: center; gap: 4px; background: none; border: none; color: var(--text-secondary); font-family: inherit; font-size: 11.5px; cursor: pointer; padding: 0; margin-bottom: 18px; transition: color .13s var(--ease); }
        .drawer-back:hover { color: var(--text-primary); }
        .drawer-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
        .drawer-id { font-size: 11.5px; color: var(--text-tertiary); margin-bottom: 5px; }
        .drawer-title { font-size: 15px; font-weight: 600; line-height: 1.35; letter-spacing: -0.01em; }
        .drawer-close { background: none; border: none; color: var(--text-tertiary); cursor: pointer; padding: 3px; flex-shrink: 0; border-radius: 2px; transition: color .13s var(--ease), background-color .13s var(--ease); }
        .drawer-close:hover { color: var(--text-primary); background: var(--surface-raised); }
        .drawer-tags { display: flex; align-items: center; gap: 10px; margin-top: 12px; }
        .drawer-divider { height: 1px; background: var(--border); margin: 20px 0; }
        .drawer-section-title { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-tertiary); margin-bottom: 11px; }
        .drawer-row { display: flex; justify-content: space-between; gap: 12px; font-size: 12.5px; margin-bottom: 9px; }
        .drawer-row-block { flex-direction: column; align-items: flex-start; gap: 7px; }
        .drawer-row-label { color: var(--text-tertiary); flex-shrink: 0; }
        .evidence { width: 100%; background: var(--surface-raised); border-left: 2px solid var(--signal); padding: 10px 12px; }
        .evidence-top { display: flex; align-items: center; gap: 6px; font-size: 12px; margin-bottom: 5px; }
        .evidence-detail { font-size: 11.5px; color: var(--text-secondary); }
        .drawer-action-text { font-size: 12.5px; color: var(--text-secondary); max-width: 100%; }
        .drawer-actions { display: flex; gap: 8px; margin-top: 22px; }
        .btn-secondary { flex: 1; background: var(--surface-raised); border: 1px solid var(--border-strong); color: var(--text-primary); font-family: inherit; font-size: 12px; padding: 9px 10px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; transition: border-color .13s var(--ease); }
        .btn-secondary:hover:not(:disabled) { border-color: var(--signal); }
        .btn-secondary:disabled { opacity: 0.4; cursor: not-allowed; }
        .btn-ghost { flex: 1; background: transparent; border: 1px solid var(--border); color: var(--text-secondary); font-family: inherit; font-size: 12px; padding: 9px 10px; cursor: pointer; transition: border-color .13s var(--ease), color .13s var(--ease); }
        .btn-ghost:hover:not(:disabled) { border-color: var(--signal); color: var(--text-primary); }
        .btn-ghost:disabled { opacity: 0.4; cursor: not-allowed; }
        .linked-finding { width: 100%; display: flex; align-items: center; gap: 10px; background: var(--surface-raised); border: 1px solid var(--border); padding: 11px; font-family: inherit; color: inherit; cursor: pointer; transition: border-color .13s var(--ease); }
        .linked-finding:hover { border-color: var(--signal); }
        .linked-finding-title { flex: 1; text-align: left; font-size: 12px; color: var(--text-secondary); }

        /* -------- timeline -------- */
        .timeline { display: flex; align-items: center; flex-wrap: wrap; }
        .timeline-step { display: flex; align-items: center; gap: 6px; }
        .timeline-dot { width: 7px; height: 7px; border-radius: 50%; }
        .timeline-dot-current { box-shadow: 0 0 0 3px rgba(255,255,255,0.07); }
        .timeline-dot-critical { background: var(--sev-critical); }
        .timeline-dot-high { background: var(--sev-high); }
        .timeline-dot-medium { background: var(--sev-medium); }
        .timeline-dot-low { background: var(--sev-low); }
        .timeline-label { font-size: 12px; color: var(--text-secondary); }
        .timeline-label-current { color: var(--text-primary); font-weight: 600; }
        .timeline-connector { width: 20px; height: 1px; background: var(--border-strong); margin: 0 8px; }
        .timeline-lg .timeline-dot { width: 9px; height: 9px; }
        .timeline-lg .timeline-label { font-size: 13.5px; }
        .timeline-lg .timeline-connector { width: 28px; margin: 0 10px; }

        /* -------- toast -------- */
        .toast-stack { position: fixed; bottom: 18px; right: 18px; display: flex; flex-direction: column; gap: 8px; z-index: 60; }
        .toast { display: flex; align-items: center; gap: 9px; background: var(--surface-raised); border: 1px solid var(--border-strong); padding: 11px 15px; font-size: 12.5px; min-width: 240px; }
        .toast-signal { border-color: var(--signal); color: var(--signal); }
        @media (prefers-reduced-motion: no-preference) { .toast { animation: toast-in .18s var(--ease); } }
        @keyframes toast-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

        /* -------- assets -------- */
        .asset-list { display: flex; flex-direction: column; }
        .asset-row { display: grid; grid-template-columns: 20px 1fr 90px 110px 80px; align-items: center; gap: 14px; padding: 13px 18px; border-bottom: 1px solid var(--border); transition: background-color .12s var(--ease); }
        .asset-row:last-child { border-bottom: none; }
        .asset-row:hover { background: var(--surface-raised); }
        .asset-icon { color: var(--text-tertiary); flex-shrink: 0; }
        .asset-name { font-size: 12.5px; font-weight: 500; }
        .asset-type { font-size: 11.5px; margin-top: 2px; }
        .asset-status { font-size: 12px; display: flex; align-items: center; gap: 6px; }
        .asset-status-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; }
        .asset-status-at-risk { color: var(--sev-critical); }
        .asset-status-monitored { color: var(--text-secondary); }
        .asset-status-clear { color: var(--signal); }
        .asset-scanned { font-size: 11px; text-align: right; }

        /* -------- reports -------- */
        .reports-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
        .reports-panel-wide { grid-column: 1 / -1; }
        .report-list { display: flex; flex-direction: column; }
        .report-row { display: flex; align-items: center; gap: 10px; padding: 11px 18px; border-bottom: 1px solid var(--border); font-size: 12.5px; }
        .report-row:last-child { border-bottom: none; }

        /* -------- settings -------- */
        .settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
        .settings-row { display: flex; align-items: center; justify-content: space-between; padding: 15px 18px; border-bottom: 1px solid var(--border); gap: 16px; }
        .settings-row:last-child { border-bottom: none; }
        .settings-row-compact { padding: 11px 18px; }
        .settings-row-main { display: flex; align-items: center; gap: 8px; font-size: 12.5px; }
        .settings-row-title { font-size: 12.5px; font-weight: 500; }
        .settings-row-sub { font-size: 11.5px; margin-top: 3px; max-width: 38ch; }

        .toggle { width: 34px; height: 18px; background: var(--surface-raised); border: 1px solid var(--border-strong); border-radius: 10px; position: relative; cursor: pointer; padding: 0; flex-shrink: 0; transition: background-color .15s var(--ease), border-color .15s var(--ease); }
        .toggle.on { background: rgba(79,160,144,0.22); border-color: var(--signal); }
        .toggle-knob { position: absolute; top: 1px; left: 1px; width: 14px; height: 14px; border-radius: 50%; background: var(--text-secondary); transition: transform .15s var(--ease), background-color .15s var(--ease); }
        .toggle.on .toggle-knob { transform: translateX(16px); background: var(--signal); }
        .segmented { display: flex; border: 1px solid var(--border-strong); }
        .segmented-item { background: none; border: none; color: var(--text-secondary); font-family: inherit; font-size: 11.5px; padding: 6px 12px; cursor: pointer; border-right: 1px solid var(--border-strong); transition: background-color .13s var(--ease), color .13s var(--ease); }
        .segmented-item:last-child { border-right: none; }
        .segmented-item:hover { color: var(--text-primary); }
        .segmented-item.active { background: var(--surface-raised); color: var(--text-primary); }

        @media (max-width: 980px) {
          .split-grid, .reports-grid, .settings-grid { grid-template-columns: 1fr; }
          .posture-main { flex-direction: column; gap: 20px; }
          .connector-cols, .connector-featured .connector-cols { grid-template-columns: 1fr; }
          .link { flex-direction: row; padding: 10px 0; }
          .asset-row { grid-template-columns: 20px 1fr 80px; }
          .asset-findings, .asset-scanned { display: none; }
        }
        @media (max-width: 680px) {
          .aegis { flex-direction: column; }
          .sidebar { width: 100%; flex-direction: row; overflow-x: auto; padding: 12px 0; align-items: center; }
          .brand { border-bottom: none; border-right: 1px solid var(--border); padding: 0 16px; margin-bottom: 0; }
          .nav { flex-direction: row; }
          .nav-item { border-left: none; border-bottom: 2px solid transparent; white-space: nowrap; }
          .nav-item.active { border-left: none; border-bottom-color: var(--text-primary); }
          .nav-divider { width: 1px; height: 22px; margin: 0 6px; }
          .drawer { width: 100%; max-width: 100%; }
        }
      `}</style>

      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <style>{`@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');`}</style>

      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" />
          <span className="brand-name">AEGIS</span>
        </div>
        <nav className="nav">
          {navPrimary.map((n) => (
            <button
              key={n.id}
              className={`nav-item ${view === n.id ? 'active' : ''}`}
              onClick={() => setView(n.id)}
            >
              <n.icon size={14} strokeWidth={1.75} className="nav-icon" />
              {n.label}
            </button>
          ))}
          <div className="nav-divider" />
          {navSecondary.map((n) => (
            <button
              key={n.id}
              className={`nav-item ${view === n.id ? 'active' : ''}`}
              onClick={() => setView(n.id)}
            >
              <n.icon size={14} strokeWidth={1.75} className="nav-icon" />
              {n.label}
            </button>
          ))}
        </nav>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <span className="topbar-title">{current.label}</span>
            <span className="topbar-divider" />
            <span className="topbar-env">juice-shop · staging</span>
          </div>
          <div className="topbar-right">
            <div className="search-wrap">
              <Search size={13} strokeWidth={1.75} className="search-icon" />
              <input
                ref={searchRef}
                className="search"
                placeholder="Search findings, CWE, IP…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              {search === '' && <span className="kbd-hint">/</span>}
            </div>
            <button
              className="btn-run"
              onClick={runScan}
              disabled={scanState === 'running'}
            >
              {scanState === 'idle' && (
                <>
                  <RefreshCw size={13} strokeWidth={1.75} /> Run scan
                </>
              )}
              {scanState === 'running' && (
                <>
                  <Loader2 size={13} strokeWidth={1.75} className="spin" />{' '}
                  {scanTools[Math.max(0, scanStep - 1)] || 'Starting'}…
                </>
              )}
              {scanState === 'done' && (
                <>
                  <Check size={13} strokeWidth={1.75} /> Done
                </>
              )}
            </button>
          </div>
        </header>

        <div className="content">
          {view === 'overview' && (
            <Overview
              findings={findings}
              onOpenFinding={openFinding}
              onOpenSession={openSession}
              selectedId={selectedId}
            />
          )}
          {view === 'findings' && (
            <FindingsView
              findings={findings}
              search={search}
              onOpenFinding={openFinding}
              selectedId={selectedId}
            />
          )}
          {view === 'honeypot' && (
            <HoneypotView
              onOpenSession={openSession}
              onOpenFinding={openFinding}
            />
          )}
          {view === 'correlation' && (
            <CorrelationView
              onOpenFinding={openFinding}
              onOpenSession={openSession}
            />
          )}
          {view === 'assets' && <AssetsView />}
          {view === 'reports' && (
            <ReportsView findings={findings} pushToast={pushToast} />
          )}
          {view === 'settings' && <SettingsView />}
        </div>
      </div>

      <Drawer
        drawer={drawer}
        findings={findings}
        onClose={closeDrawer}
        onMarkTriaged={markTriaged}
        onOpenFinding={openFinding}
        onOpenSession={openSession}
      />

      <div className="toast-stack">
        {toasts.map((t) => (
          <div
            className={`toast ${t.tone === 'signal' ? 'toast-signal' : ''}`}
            key={t.id}
          >
            <Check size={14} strokeWidth={1.75} />
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
