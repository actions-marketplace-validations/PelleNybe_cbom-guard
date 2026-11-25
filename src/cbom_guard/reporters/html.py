"""Self-contained, offline-ready HTML PQC Readiness dashboard reporter."""

from __future__ import annotations

import html
from datetime import UTC, datetime

from cbom_guard import __version__
from cbom_guard.models import AssetType, Finding, ScanResult


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _compute_readiness_score(scan_result: ScanResult) -> int:
    total = len(scan_result.findings)
    if total == 0:
        return 100
    penalty = (scan_result.critical_count * 15) + (scan_result.warning_count * 5)
    return max(0, 100 - min(100, penalty))


def _render_finding_row(finding: Finding) -> str:
    risk = finding.risk_level.value
    threat = finding.quantum_vulnerability.value
    loc = f"{finding.file_path}:{finding.start_line}:{finding.start_col}"
    code_block = ""
    if finding.remediation.code_example.strip():
        code_block = (
            '<pre class="code-snippet"><code>'
            f"{_esc(finding.remediation.code_example.strip())}"
            "</code></pre>"
        )

    matched_snippet = ""
    if finding.snippet.strip():
        matched_snippet = (
            '<div class="detail-label">Detected AST / Artifact Context</div>'
            f'<pre class="code-snippet"><code>{_esc(finding.snippet.strip())}</code></pre>'
        )

    param_html = (
        f' <span class="muted">({_esc(finding.parameter_set)})</span>'
        if finding.parameter_set
        else ""
    )

    return (
        f'<tr class="finding-row" data-risk="{_esc(risk)}" '
        f'data-threat="{_esc(threat)}" data-lang="{_esc(finding.language.value)}">'
        f'<th><span class="badge badge-{_esc(risk)}">{_esc(risk.upper())}</span></th>'
        f"<td><code>{_esc(finding.rule_id)}</code></td>"
        f"<td><strong>{_esc(finding.algorithm)}</strong>{param_html}</td>"
        f'<td><span class="threat threat-{_esc(threat)}">{_esc(threat.upper())}</span></td>'
        f'<td class="loc-cell"><code>{_esc(loc)}</code></td>'
        f"<td>"
        f'<div class="target-title">{_esc(finding.remediation.hybrid_pqc_target)}</div>'
        f'<details class="remediation-details">'
        f"<summary>View remediation &amp; context</summary>"
        f'<div class="details-body">'
        f"<p>{_esc(finding.description)}</p>"
        f"{matched_snippet}"
        f'<div class="detail-label">Hybrid-PQC Migration Guidance ({_esc(finding.cwe)} | {_esc(finding.nist_pqc_status)})</div>'
        f"<p>{_esc(finding.remediation.summary)}</p>"
        f"{code_block}"
        f"</div>"
        f"</details>"
        f"</td>"
        f"</tr>"
    )


def _render_cert_section(findings: list[Finding]) -> str:
    certs = [f for f in findings if f.asset_type == AssetType.CERTIFICATE and f.certificate is not None]
    if not certs:
        return ""

    rows: list[str] = []
    for f in certs:
        cert = f.certificate
        assert cert is not None
        status = "EXPIRED" if cert.is_expired else "VALID"
        status_cls = "critical" if cert.is_expired else "info"
        rows.append(
            "<tr>"
            f"<th><code>{_esc(f.file_path)}</code></th>"
            f"<td>{_esc(cert.subject)}</td>"
            f"<td>{_esc(cert.public_key_algorithm)}-{_esc(cert.key_size or 'N/A')}</td>"
            f"<td>{_esc(cert.signature_hash_algorithm or 'N/A')}</td>"
            f'<td><span class="badge badge-{status_cls}">{status}</span> {_esc(cert.not_valid_after[:10])}</td>'
            f"<td><code>{_esc(cert.fingerprint_sha256[:16])}...</code></td>"
            "</tr>"
        )

    return (
        '<section class="card">'
        "<h2>X.509 Certificate Inventory</h2>"
        '<div tabindex="0" role="region" aria-labelledby="cert-table-caption" class="table-wrapper">'
        '<table class="cert-table">'
        '<caption id="cert-table-caption">Discovered X.509 certificates and quantum readiness</caption>'
        "<thead><tr>"
        "<th>File</th><th>Subject</th><th>Public Key</th>"
        "<th>Sig Hash</th><th>Validity</th><th>SHA-256</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table></div></section>"
    )


def generate_html_report(scan_result: ScanResult) -> str:
    """Render a self-contained, accessible HTML PQC Readiness dashboard."""
    generated_at = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    score = _compute_readiness_score(scan_result)
    score_cls = "good" if score >= 80 else ("warn" if score >= 50 else "bad")
    cert_count = sum(1 for f in scan_result.findings if f.asset_type == AssetType.CERTIFICATE)

    rows_html = "\n".join(_render_finding_row(f) for f in scan_result.findings)
    empty_state = (
        '<p class="empty-state">No cryptographic assets or PQC vulnerabilities detected.</p>'
        if not scan_result.findings
        else ""
    )
    cert_section = _render_cert_section(scan_result.findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>cbom-guard — Post-Quantum Cryptography Readiness Report</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg-light: #f6f8fa;
      --bg-dark: #0d1117;
      --surface-light: #ffffff;
      --surface-dark: #161b22;
      --surface-alt-light: #f0f3f6;
      --surface-alt-dark: #1f242c;
      --border-light: #d0d7de;
      --border-dark: #30363d;
      --text-light: #1f2328;
      --text-dark: #e6edf3;
      --muted-light: #59636e;
      --muted-dark: #8b949e;
      --brand-light: #6e40c9;
      --brand-dark: #a371f7;

      --bg: var(--bg-light);
      --surface: var(--surface-light);
      --surface-alt: var(--surface-alt-light);
      --border: var(--border-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --brand: var(--brand-light);
      --crit-bg: #ffebe9;
      --crit-fg: #cf222e;
      --warn-bg: #fff8c5;
      --warn-fg: #9a6700;
      --info-bg: #ddf4ff;
      --info-fg: #0969da;
      --good-fg: #1a7f37;
    }}

    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: var(--bg-dark);
        --surface: var(--surface-dark);
        --surface-alt: var(--surface-alt-dark);
        --border: var(--border-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --brand: var(--brand-dark);
        --crit-bg: rgba(248, 81, 73, 0.16);
        --crit-fg: #ff7b72;
        --warn-bg: rgba(210, 153, 34, 0.16);
        --warn-fg: #d29922;
        --info-bg: rgba(56, 139, 253, 0.16);
        --info-fg: #58a6ff;
        --good-fg: #3fb950;
      }}
    }}

    @supports (color: light-dark(white, black)) {{
      :root {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --surface: light-dark(var(--surface-light), var(--surface-dark));
        --surface-alt: light-dark(var(--surface-alt-light), var(--surface-alt-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --brand: light-dark(var(--brand-light), var(--brand-dark));
        accent-color: light-dark(var(--brand-light), var(--brand-dark));
      }}
    }}

    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 1.5rem;
    }}
    header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }}
    h1 {{ margin: 0; font-size: 1.5rem; }}
    h2 {{ margin: 0 0 1rem; font-size: 1.15rem; }}
    .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-top: 0.25rem; }}
    .score-pill {{
      padding: 0.6rem 1rem;
      border-radius: 10px;
      background: var(--surface);
      border: 1px solid var(--border);
      font-weight: 700;
      font-size: 1.05rem;
    }}
    .score-good {{ color: var(--good-fg); }}
    .score-warn {{ color: var(--warn-fg); }}
    .score-bad {{ color: var(--crit-fg); }}

    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .kpi {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
    }}
    .kpi-label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .kpi-value {{ font-size: 1.75rem; font-weight: 700; margin-top: 0.25rem; }}

    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }}

    .filters {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-bottom: 1rem;
      align-items: center;
    }}
    .filters label {{ font-size: 0.85rem; color: var(--muted); display: flex; align-items: center; gap: 0.4rem; }}
    select, input[type="search"] {{
      padding: 0.45rem 0.65rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface-alt);
      color: var(--text);
      font-size: 0.9rem;
    }}
    input[type="search"] {{ min-width: 240px; flex: 1; }}

    .table-wrapper {{
      overflow: auto;
      max-inline-size: 100%;
      max-block-size: min(650px, 75vh);
      container-type: inline-size;
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.9rem;
      text-align: left;
    }}
    caption {{
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
    }}
    thead {{
      position: sticky;
      inset-block-start: 0;
      z-index: 2;
      background: var(--surface-alt);
    }}
    th, td {{
      padding: 0.7rem 0.85rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tbody th {{
      position: sticky;
      inset-inline-start: 0;
      z-index: 1;
      background: var(--surface);
      font-weight: 600;
    }}
    .loc-cell code {{ word-break: break-all; font-size: 0.82rem; }}
    .muted {{ color: var(--muted); font-size: 0.82rem; }}

    .badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
    }}
    .badge-critical {{ background: var(--crit-bg); color: var(--crit-fg); }}
    .badge-warning {{ background: var(--warn-bg); color: var(--warn-fg); }}
    .badge-info {{ background: var(--info-bg); color: var(--info-fg); }}
    .threat {{ font-weight: 600; font-size: 0.82rem; }}
    .threat-shor {{ color: var(--crit-fg); }}
    .threat-grover {{ color: var(--warn-fg); }}
    .threat-none {{ color: var(--good-fg); }}

    .target-title {{ font-weight: 600; margin-bottom: 0.25rem; }}
    .remediation-details summary {{
      cursor: pointer;
      color: var(--brand);
      font-size: 0.84rem;
      font-weight: 600;
    }}
    .details-body {{
      margin-top: 0.6rem;
      padding: 0.75rem;
      background: var(--surface-alt);
      border-radius: 6px;
      font-size: 0.85rem;
    }}
    .detail-label {{ font-weight: 700; margin: 0.5rem 0 0.25rem; font-size: 0.8rem; color: var(--muted); }}
    .code-snippet {{
      margin: 0.35rem 0 0;
      padding: 0.6rem;
      border-radius: 6px;
      background: #0d1117;
      color: #e6edf3;
      overflow-x: auto;
      font-size: 0.8rem;
    }}
    .empty-state {{ color: var(--good-fg); font-weight: 600; }}
    .hidden {{ display: none !important; }}

    @container (width < 680px) {{
      .findings-table, .findings-table thead, .findings-table tbody,
      .findings-table tr, .findings-table th, .findings-table td {{
        display: block;
      }}
      .findings-table thead {{ display: none; }}
      .findings-table tr {{
        margin-block-end: 1rem;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--surface);
      }}
      .findings-table tbody th {{
        position: sticky;
        inset-block-start: 0;
        z-index: 2;
        background: var(--surface-alt);
      }}
      .findings-table {{
        --label-2: "Rule ID";
        --label-3: "Algorithm";
        --label-4: "Threat";
        --label-5: "Location";
        --label-6: "Hybrid-PQC Target";
      }}
      .findings-table td:nth-child(2)::before {{ content: var(--label-2) ": "; font-weight: 700; }}
      .findings-table td:nth-child(3)::before {{ content: var(--label-3) ": "; font-weight: 700; }}
      .findings-table td:nth-child(4)::before {{ content: var(--label-4) ": "; font-weight: 700; }}
      .findings-table td:nth-child(5)::before {{ content: var(--label-5) ": "; font-weight: 700; }}
      .findings-table td:nth-child(6)::before {{ content: var(--label-6) ": "; font-weight: 700; display: block; margin-bottom: 0.2rem; }}
    }}

    footer {{
      text-align: center;
      color: var(--muted);
      font-size: 0.85rem;
      padding-top: 0.5rem;
    }}
  </style>
</head>
<body>
  <main class="container">
    <header>
      <div>
        <h1>🛡️ cbom-guard — Post-Quantum Readiness Report</h1>
        <div class="subtitle">
          Target: <code>{_esc(scan_result.target_path)}</code> &bull;
          Files Scanned: <strong>{scan_result.files_scanned}</strong> &bull;
          Generated: {_esc(generated_at)}
        </div>
      </div>
      <div class="score-pill score-{score_cls}">PQC Readiness Score: {score}/100</div>
    </header>

    <section class="kpi-grid" aria-label="Summary metrics">
      <div class="kpi"><div class="kpi-label">Total Assets</div><div class="kpi-value">{len(scan_result.findings)}</div></div>
      <div class="kpi"><div class="kpi-label">Critical (Shor)</div><div class="kpi-value score-bad">{scan_result.critical_count}</div></div>
      <div class="kpi"><div class="kpi-label">Warning (Grover)</div><div class="kpi-value score-warn">{scan_result.warning_count}</div></div>
      <div class="kpi"><div class="kpi-label">Info (PQC-Safe)</div><div class="kpi-value score-good">{scan_result.info_count}</div></div>
      <div class="kpi"><div class="kpi-label">X.509 Certs</div><div class="kpi-value">{cert_count}</div></div>
    </section>

    {cert_section}

    <section class="card">
      <h2>Cryptographic Findings &amp; Hybrid-PQC Remediation</h2>
      <div class="filters">
        <label>Risk:
          <select id="filter-risk">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>
        </label>
        <label>Threat:
          <select id="filter-threat">
            <option value="all">All</option>
            <option value="shor">Shor</option>
            <option value="grover">Grover</option>
            <option value="none">None (Safe)</option>
          </select>
        </label>
        <input id="filter-search" type="search" placeholder="Search rule, algorithm, or file path..." aria-label="Search findings">
      </div>
      {empty_state}
      <div tabindex="0" role="region" aria-labelledby="findings-table-caption" class="table-wrapper">
        <table class="findings-table">
          <caption id="findings-table-caption">Post-Quantum Cryptography scan findings</caption>
          <thead>
            <tr>
              <th>Risk</th>
              <th>Rule ID</th>
              <th>Algorithm</th>
              <th>Threat</th>
              <th>Location</th>
              <th>Hybrid-PQC Target</th>
            </tr>
          </thead>
          <tbody id="findings-tbody">
            {rows_html}
          </tbody>
        </table>
      </div>
    </section>

    <footer>
      Generated by <strong>cbom-guard v{_esc(__version__)}</strong> &bull; Engineered by <strong>Corax CoLAB</strong> (Pelle Nyberg)
    </footer>
  </main>

  <script>
    (function () {{
      const riskSel = document.getElementById("filter-risk");
      const threatSel = document.getElementById("filter-threat");
      const searchInput = document.getElementById("filter-search");
      const rows = Array.from(document.querySelectorAll("#findings-tbody .finding-row"));

      function applyFilters() {{
        const risk = riskSel.value;
        const threat = threatSel.value;
        const query = searchInput.value.trim().toLowerCase();

        for (const row of rows) {{
          const matchRisk = risk === "all" || row.dataset.risk === risk;
          const matchThreat = threat === "all" || row.dataset.threat === threat;
          const matchQuery = !query || row.textContent.toLowerCase().includes(query);
          row.classList.toggle("hidden", !(matchRisk && matchThreat && matchQuery));
        }}
      }}

      riskSel.addEventListener("change", applyFilters);
      threatSel.addEventListener("change", applyFilters);
      searchInput.addEventListener("input", applyFilters);
    }})();
  </script>
</body>
</html>
"""
