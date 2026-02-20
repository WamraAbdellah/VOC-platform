import React, { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, PieChart, Pie, Cell, Legend, AreaChart, Area,
} from 'recharts';

// ─── Config API ──────────────────────────────────────────
const API = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = {
  get: async (path) => {
    const res = await fetch(`${API}${path}`);
    return res.json();
  },
  post: async (path, body) => {
    const res = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json();
  },
};

// ─── Colors ───────────────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#65a30d',
  INFO: '#0891b2',
};

const STATUS_COLORS = {
  NEW: '#7c3aed',
  IN_REMEDIATION: '#2563eb',
  RESOLVED: '#16a34a',
  ACCEPTED_RISK: '#9ca3af',
  FALSE_POSITIVE: '#6b7280',
};

// ─── Components ───────────────────────────────────────────
const Badge = ({ label, color }) => (
  <span style={{
    background: color + '20',
    color: color,
    border: `1px solid ${color}40`,
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: '600',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  }}>
    {label}
  </span>
);

const KPICard = ({ title, value, subtitle, color = '#2563eb', icon }) => (
  <div style={{
    background: '#fff',
    border: '1px solid #e5e7eb',
    borderRadius: '12px',
    padding: '20px',
    borderLeft: `4px solid ${color}`,
  }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
      <div>
        <p style={{ color: '#6b7280', fontSize: '13px', margin: 0 }}>{title}</p>
        <p style={{ color: '#111827', fontSize: '28px', fontWeight: '700', margin: '4px 0 0' }}>
          {value}
        </p>
        {subtitle && <p style={{ color: '#9ca3af', fontSize: '12px', margin: '4px 0 0' }}>{subtitle}</p>}
      </div>
      <span style={{ fontSize: '24px' }}>{icon}</span>
    </div>
  </div>
);

const VocScoreBar = ({ score }) => {
  const color = score >= 80 ? '#dc2626' : score >= 60 ? '#ea580c' : score >= 40 ? '#d97706' : '#65a30d';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <div style={{
        flex: 1, height: '8px', background: '#f3f4f6', borderRadius: '4px', overflow: 'hidden'
      }}>
        <div style={{
          width: `${score}%`, height: '100%', background: color, borderRadius: '4px'
        }} />
      </div>
      <span style={{ color, fontWeight: '700', fontSize: '13px', minWidth: '32px' }}>
        {Math.round(score)}
      </span>
    </div>
  );
};

// ─── Pages ────────────────────────────────────────────────

const Dashboard = ({ summary }) => {
  if (!summary) return <div style={{ padding: '40px', textAlign: 'center' }}>Chargement...</div>;

  const { summary: s, trend_30d, top_vulnerabilities, mttr_by_severity, kev_unpatched_count } = summary;

  const pieData = [
    { name: 'Critical', value: s.critical, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: s.high, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: s.medium, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: s.low, color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
        <KPICard title="Total Vulnérabilités" value={s.total} color="#7c3aed" icon="🎯" />
        <KPICard title="Critiques" value={s.critical} color={SEVERITY_COLORS.CRITICAL} icon="🔴" subtitle={`${s.high} HIGH en attente`} />
        <KPICard title="Résolues" value={s.resolved} color="#16a34a" icon="✅" subtitle={`${Math.round(s.resolved / Math.max(s.total, 1) * 100)}% du total`} />
        <KPICard title="CISA KEV Non Patchées" value={kev_unpatched_count} color="#dc2626" icon="⚠️" subtitle="Exploitation confirmée" />
        <KPICard title="En Remédiation" value={s.in_remediation} color="#2563eb" icon="🔧" />
        <KPICard title="Nouveau (7j)" value={s.new_vulns} color="#9333ea" icon="🆕" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Trend 30 jours */}
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '20px' }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '15px', color: '#374151' }}>📈 Évolution 30 jours</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trend_30d || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Area type="monotone" dataKey="discovered" name="Découvertes" stroke="#7c3aed" fill="#ede9fe" />
              <Area type="monotone" dataKey="resolved" name="Résolues" stroke="#16a34a" fill="#dcfce7" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Distribution par sévérité */}
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '20px' }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '15px', color: '#374151' }}>🎯 Distribution par Sévérité</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                {pieData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* MTTR */}
      {mttr_by_severity?.length > 0 && (
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '20px' }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '15px', color: '#374151' }}>⏱️ MTTR par Sévérité (jours)</h3>
          <ResponsiveContainer width="100%" height={150}>
            <BarChart data={mttr_by_severity}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="severity" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="avg_days" name="Jours moyens" fill="#2563eb" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Top Vulnérabilités */}
      <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '20px' }}>
        <h3 style={{ margin: '0 0 16px', fontSize: '15px', color: '#374151' }}>🔥 Top Vulnérabilités par VOC Score</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #f3f4f6' }}>
              {['CVE', 'Titre', 'Asset', 'Env', 'VOC Score', 'EPSS', 'KEV', 'Statut'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: '12px', color: '#6b7280', fontWeight: '600' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(top_vulnerabilities || []).map(v => (
              <tr key={v.id} style={{ borderBottom: '1px solid #f9fafb' }}>
                <td style={{ padding: '10px 12px' }}>
                  {v.cve_id ? <code style={{ fontSize: '12px', background: '#f3f4f6', padding: '2px 6px', borderRadius: '3px' }}>{v.cve_id}</code> : '—'}
                </td>
                <td style={{ padding: '10px 12px', fontSize: '13px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</td>
                <td style={{ padding: '10px 12px', fontSize: '13px' }}>{v.asset_name || '—'}</td>
                <td style={{ padding: '10px 12px' }}>
                  <Badge label={v.environment || 'PROD'} color={v.environment === 'PRODUCTION' ? '#dc2626' : '#d97706'} />
                </td>
                <td style={{ padding: '10px 12px', minWidth: '120px' }}>
                  <VocScoreBar score={v.voc_score || 0} />
                </td>
                <td style={{ padding: '10px 12px', fontSize: '12px', color: '#6b7280' }}>
                  {v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : '—'}
                </td>
                <td style={{ padding: '10px 12px' }}>
                  {v.is_in_kev && <Badge label="KEV" color="#dc2626" />}
                </td>
                <td style={{ padding: '10px 12px' }}>
                  <Badge label={v.status} color={STATUS_COLORS[v.status] || '#6b7280'} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const VulnerabilitiesPage = () => {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    setLoading(true);
    let url = `/api/vulnerabilities/?page=${page}&size=20&sort_by=voc_score`;
    if (filters.severity) url += `&severity=${filters.severity}`;
    if (filters.status) url += `&status=${filters.status}`;
    
    api.get(url).then(data => {
      setVulns(data.items || []);
      setTotal(data.total || 0);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [page, filters]);

  const [showScanForm, setShowScanForm] = useState(false);
  const [scanTarget, setScanTarget] = useState('');
  const [scanType, setScanType] = useState('NMAP');

  const launchScan = async () => {
    await api.post('/api/scans/', { target: scanTarget, scan_type: scanType });
    setShowScanForm(false);
    alert(`Scan ${scanType} lancé sur ${scanTarget} !`);
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2 style={{ margin: 0, fontSize: '20px' }}>Vulnérabilités ({total})</h2>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button onClick={() => setShowScanForm(!showScanForm)} style={{
            background: '#7c3aed', color: '#fff', border: 'none', borderRadius: '8px',
            padding: '8px 16px', cursor: 'pointer', fontWeight: '600',
          }}>
            🔍 Nouveau Scan
          </button>
        </div>
      </div>

      {showScanForm && (
        <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '20px', marginBottom: '20px' }}>
          <h3 style={{ margin: '0 0 16px' }}>Lancer un Scan</h3>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <input value={scanTarget} onChange={e => setScanTarget(e.target.value)}
              placeholder="Cible (IP, range, URL)" style={{ flex: 1, padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '8px' }} />
            <select value={scanType} onChange={e => setScanType(e.target.value)}
              style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '8px' }}>
              <option value="NMAP">Nmap (Infrastructure)</option>
              <option value="NUCLEI">Nuclei (Web)</option>
              <option value="TRIVY">Trivy (Container)</option>
              <option value="NIKTO">Nikto (Web Server)</option>
            </select>
            <button onClick={launchScan} style={{
              background: '#2563eb', color: '#fff', border: 'none', borderRadius: '8px',
              padding: '8px 16px', cursor: 'pointer',
            }}>Lancer</button>
          </div>
        </div>
      )}

      {/* Filtres */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
        {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
          <button key={sev} onClick={() => setFilters(f => ({ ...f, severity: sev }))}
            style={{
              padding: '6px 14px', borderRadius: '20px', border: '1px solid',
              cursor: 'pointer', fontSize: '12px', fontWeight: '600',
              background: filters.severity === sev ? (SEVERITY_COLORS[sev] || '#374151') : '#fff',
              color: filters.severity === sev ? '#fff' : (SEVERITY_COLORS[sev] || '#374151'),
              borderColor: SEVERITY_COLORS[sev] || '#d1d5db',
            }}>
            {sev || 'TOUS'}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>Chargement...</div>
      ) : (
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }}>
                {['CVE', 'Vulnérabilité', 'Sévérité', 'VOC Score', 'CVSS', 'EPSS', 'KEV', 'Statut', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '12px 16px', textAlign: 'left', fontSize: '12px', color: '#6b7280', fontWeight: '600' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id} style={{ borderBottom: '1px solid #f3f4f6', transition: 'background 0.1s' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#fafafa'}
                  onMouseLeave={e => e.currentTarget.style.background = ''}>
                  <td style={{ padding: '12px 16px' }}>
                    {v.cve_id ? <code style={{ fontSize: '11px', background: '#f3f4f6', padding: '2px 6px', borderRadius: '3px', color: '#1d4ed8' }}>{v.cve_id}</code> : <span style={{ color: '#9ca3af' }}>—</span>}
                  </td>
                  <td style={{ padding: '12px 16px', maxWidth: '250px' }}>
                    <div style={{ fontSize: '13px', fontWeight: '500', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</div>
                    {v.affected_component && <div style={{ fontSize: '11px', color: '#9ca3af' }}>{v.affected_component}</div>}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Badge label={v.severity} color={SEVERITY_COLORS[v.severity] || '#6b7280'} />
                  </td>
                  <td style={{ padding: '12px 16px', minWidth: '130px' }}>
                    <VocScoreBar score={v.voc_score || 0} />
                  </td>
                  <td style={{ padding: '12px 16px', fontSize: '13px', fontWeight: '600' }}>
                    {v.cvss_score?.toFixed(1) || '—'}
                  </td>
                  <td style={{ padding: '12px 16px', fontSize: '12px', color: v.epss_score > 0.5 ? '#dc2626' : '#6b7280' }}>
                    {v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : '—'}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    {v.is_in_kev ? <span title="CISA Known Exploited Vulnerability">🔴</span> : <span style={{ color: '#9ca3af' }}>—</span>}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Badge label={v.status} color={STATUS_COLORS[v.status] || '#6b7280'} />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button title="Créer ticket" style={{ padding: '4px 8px', fontSize: '11px', border: '1px solid #2563eb', color: '#2563eb', background: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                        🎫
                      </button>
                      <button title="Recalculer score" onClick={() => api.post(`/api/vulnerabilities/${v.id}/score`, {})} style={{ padding: '4px 8px', fontSize: '11px', border: '1px solid #7c3aed', color: '#7c3aed', background: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                        🔄
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          <div style={{ padding: '16px', display: 'flex', justifyContent: 'center', gap: '8px' }}>
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              style={{ padding: '6px 12px', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' }}>
              ← Précédent
            </button>
            <span style={{ padding: '6px 12px', color: '#6b7280' }}>Page {page}</span>
            <button onClick={() => setPage(p => p + 1)}
              style={{ padding: '6px 12px', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' }}>
              Suivant →
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const ScoringPage = () => {
  const [form, setForm] = useState({
    cvss_score: 7.5, is_internet_exposed: true,
    business_criticality: 4, environment: 'PRODUCTION',
    is_in_kev: false, exploit_available: false,
    exploit_maturity: null, epss_score: 0.15,
    greynoise_noise: false,
  });
  const [result, setResult] = useState(null);

  const calculate = async () => {
    // Simulation du calcul VOC côté client pour la démo
    const cvss_norm = form.cvss_score / 10;
    const exposure = form.is_internet_exposed ? 0.8 : 0.2;
    const business = (form.business_criticality - 1) / 4;
    let exploit = form.epss_score * 0.4;
    if (form.exploit_available) exploit += (form.exploit_maturity === 'FUNCTIONAL' ? 0.8 : 0.5) * 0.3;
    if (form.greynoise_noise) exploit += 0.3;
    const env_map = { PRODUCTION: 1.0, STAGING: 0.6, DEVELOPMENT: 0.3, TEST: 0.2 };
    const env = env_map[form.environment];

    let raw = 0.25 * cvss_norm + 0.25 * exposure + 0.20 * business + 0.20 * Math.min(exploit, 1) + 0.10 * env;
    if (form.is_in_kev) raw = Math.min(raw * 1.3, 1.0);
    const score = Math.round(raw * 100);

    const severity = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
    
    setResult({
      voc_score: score, severity,
      components: {
        cvss: Math.round(cvss_norm * 10 * 100) / 100,
        exposure: Math.round(exposure * 10 * 100) / 100,
        business: Math.round(business * 10 * 100) / 100,
        exploitability: Math.round(Math.min(exploit, 1) * 10 * 100) / 100,
        environment: Math.round(env * 10 * 100) / 100,
      },
      kev_applied: form.is_in_kev,
    });
  };

  const F = ({ label, children }) => (
    <div style={{ marginBottom: '16px' }}>
      <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', color: '#374151', marginBottom: '6px' }}>{label}</label>
      {children}
    </div>
  );

  const input_style = { width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' };

  return (
    <div>
      <h2 style={{ margin: '0 0 8px', fontSize: '20px' }}>🧠 Scoring Contextualisé VOC</h2>
      <p style={{ color: '#6b7280', margin: '0 0 24px' }}>Calculez le score de priorité réel au-delà du CVSS</p>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Formulaire */}
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '24px' }}>
          <h3 style={{ margin: '0 0 20px', fontSize: '16px' }}>Paramètres de la vulnérabilité</h3>

          <F label={`Score CVSS : ${form.cvss_score}`}>
            <input type="range" min="0" max="10" step="0.1" value={form.cvss_score}
              onChange={e => setForm(f => ({ ...f, cvss_score: parseFloat(e.target.value) }))}
              style={{ width: '100%' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#9ca3af' }}>
              <span>0 - Aucun</span><span>5 - Moyen</span><span>10 - Critique</span>
            </div>
          </F>

          <F label="Criticité Métier de l'Asset (1-5)">
            <select value={form.business_criticality} onChange={e => setForm(f => ({ ...f, business_criticality: parseInt(e.target.value) }))} style={input_style}>
              <option value={1}>1 - Minimal (test, sandbox)</option>
              <option value={2}>2 - Faible (outils internes)</option>
              <option value={3}>3 - Moyen (applications métier)</option>
              <option value={4}>4 - Élevé (systèmes critiques)</option>
              <option value={5}>5 - Mission Critical (production core)</option>
            </select>
          </F>

          <F label="Environnement">
            <select value={form.environment} onChange={e => setForm(f => ({ ...f, environment: e.target.value }))} style={input_style}>
              <option value="PRODUCTION">Production (×1.0)</option>
              <option value="STAGING">Staging (×0.6)</option>
              <option value="DEVELOPMENT">Développement (×0.3)</option>
              <option value="TEST">Test (×0.2)</option>
            </select>
          </F>

          <F label={`Score EPSS : ${(form.epss_score * 100).toFixed(0)}%`}>
            <input type="range" min="0" max="1" step="0.01" value={form.epss_score}
              onChange={e => setForm(f => ({ ...f, epss_score: parseFloat(e.target.value) }))}
              style={{ width: '100%' }} />
            <div style={{ fontSize: '11px', color: '#9ca3af' }}>Probabilité d'exploitation (30 jours) - Source: FIRST.org</div>
          </F>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            {[
              { key: 'is_internet_exposed', label: '🌐 Exposé sur internet' },
              { key: 'is_in_kev', label: '⚠️ Dans CISA KEV' },
              { key: 'exploit_available', label: '💣 Exploit disponible' },
              { key: 'greynoise_noise', label: '📡 GreyNoise actif' },
            ].map(({ key, label }) => (
              <label key={key} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px' }}>
                <input type="checkbox" checked={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.checked }))} />
                {label}
              </label>
            ))}
          </div>

          <button onClick={calculate} style={{
            width: '100%', marginTop: '20px', background: '#7c3aed', color: '#fff',
            border: 'none', borderRadius: '8px', padding: '12px', fontSize: '15px',
            fontWeight: '600', cursor: 'pointer',
          }}>
            Calculer le Score VOC →
          </button>
        </div>

        {/* Résultat */}
        <div>
          {result ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{
                background: '#fff', border: `3px solid ${SEVERITY_COLORS[result.severity]}`,
                borderRadius: '12px', padding: '24px', textAlign: 'center',
              }}>
                <div style={{ fontSize: '64px', fontWeight: '900', color: SEVERITY_COLORS[result.severity] }}>
                  {result.voc_score}
                </div>
                <div style={{ fontSize: '24px', fontWeight: '700', color: SEVERITY_COLORS[result.severity] }}>
                  {result.severity}
                </div>
                <div style={{ color: '#6b7280', marginTop: '8px' }}>Score VOC / 100</div>
                {result.kev_applied && (
                  <div style={{ marginTop: '12px', background: '#fee2e2', color: '#dc2626', padding: '8px', borderRadius: '8px', fontSize: '13px', fontWeight: '600' }}>
                    ⚠️ Boost KEV appliqué (+30% - exploitation confirmée CISA)
                  </div>
                )}
              </div>

              <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '20px' }}>
                <h4 style={{ margin: '0 0 16px', fontSize: '14px' }}>Détail des composantes</h4>
                {[
                  { label: 'CVSS (base technique)', key: 'cvss', weight: '25%', color: '#6366f1' },
                  { label: 'Exposition réseau', key: 'exposure', weight: '25%', color: '#f59e0b' },
                  { label: 'Criticité métier', key: 'business', weight: '20%', color: '#10b981' },
                  { label: 'Exploitabilité réelle', key: 'exploitability', weight: '20%', color: '#ef4444' },
                  { label: 'Environnement', key: 'environment', weight: '10%', color: '#8b5cf6' },
                ].map(({ label, key, weight, color }) => (
                  <div key={key} style={{ marginBottom: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                      <span style={{ color: '#374151' }}>{label}</span>
                      <span style={{ color: '#6b7280' }}>{weight} du score | <strong style={{ color }}>{result.components[key]}/10</strong></span>
                    </div>
                    <div style={{ height: '8px', background: '#f3f4f6', borderRadius: '4px', overflow: 'hidden' }}>
                      <div style={{ width: `${result.components[key] * 10}%`, height: '100%', background: color, borderRadius: '4px' }} />
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ background: '#fffbeb', border: '1px solid #fbbf24', borderRadius: '12px', padding: '16px' }}>
                <h4 style={{ margin: '0 0 8px', fontSize: '13px', color: '#92400e' }}>💡 Pourquoi ce score ?</h4>
                <p style={{ fontSize: '13px', color: '#78350f', margin: 0 }}>
                  {result.voc_score >= 80 && "Cette vulnérabilité doit être traitée IMMÉDIATEMENT. Elle combine plusieurs facteurs aggravants critiques."}
                  {result.voc_score >= 60 && result.voc_score < 80 && "Priorité haute. Planifier la remédiation dans les 7 jours."}
                  {result.voc_score >= 40 && result.voc_score < 60 && "Priorité modérée. Inclure dans le prochain sprint de remédiation."}
                  {result.voc_score < 40 && "Priorité basse. Peut être traitée dans le backlog standard."}
                </p>
              </div>
            </div>
          ) : (
            <div style={{
              background: '#f9fafb', border: '2px dashed #e5e7eb', borderRadius: '12px',
              padding: '60px', textAlign: 'center', color: '#9ca3af',
            }}>
              <div style={{ fontSize: '48px', marginBottom: '16px' }}>🎯</div>
              <p>Renseignez les paramètres et calculez le score VOC contextualisé</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ─── Main App ────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState('dashboard');
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    api.get('/api/dashboard/summary').then(setSummary).catch(() => {});
  }, []);

  const NAV = [
    { id: 'dashboard', label: '📊 Dashboard', },
    { id: 'vulnerabilities', label: '🔴 Vulnérabilités', },
    { id: 'scoring', label: '🧠 Scoring VOC', },
    { id: 'assets', label: '🖥️ Assets', },
  ];

  return (
    <div style={{ minHeight: '100vh', background: '#f8fafc', fontFamily: 'Inter, -apple-system, sans-serif' }}>
      {/* Header */}
      <header style={{ background: '#1e1b4b', color: '#fff', padding: '0 24px', display: 'flex', alignItems: 'center', gap: '24px', height: '56px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginRight: '24px' }}>
          <span style={{ fontSize: '20px' }}>🛡️</span>
          <span style={{ fontWeight: '800', fontSize: '16px', letterSpacing: '-0.5px' }}>VOC Platform</span>
        </div>
        {NAV.map(n => (
          <button key={n.id} onClick={() => setPage(n.id)} style={{
            background: page === n.id ? '#3730a3' : 'transparent',
            color: page === n.id ? '#fff' : '#a5b4fc',
            border: 'none', borderRadius: '6px', padding: '6px 14px',
            cursor: 'pointer', fontSize: '13px', fontWeight: '500',
            transition: 'all 0.1s',
          }}>
            {n.label}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#4ade80' }} />
          <span style={{ fontSize: '12px', color: '#a5b4fc' }}>VOC Opérationnel</span>
        </div>
      </header>

      {/* Main */}
      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '24px' }}>
        {page === 'dashboard' && <Dashboard summary={summary} />}
        {page === 'vulnerabilities' && <VulnerabilitiesPage />}
        {page === 'scoring' && <ScoringPage />}
        {page === 'assets' && (
          <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '12px', padding: '40px', textAlign: 'center', color: '#6b7280' }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>🖥️</div>
            <h3>Gestion des Assets</h3>
            <p>Inventaire des actifs, exposition réseau, criticité métier</p>
          </div>
        )}
      </main>
    </div>
  );
}
