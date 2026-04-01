import fs from 'fs';
import path from 'path';
import { sortFindings, filterBySeverity, severitySummary } from '../utils/finding.js';
import { writeSARIF } from './sarif-generator.js';
import { DiffReporter } from './diff-reporter.js';

/**
 * Report Generator — Generates structured output in JSON, Markdown, HTML, and SARIF formats.
 */
export class ReportGenerator {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
  }

  /**
   * Generate all reports from findings and test results.
   */
  async generate({ findings, deduplicated, dedupStats, correlations, modules, testSummary, surfaceInventory, outputDir }) {
    const reportDir = outputDir || path.join(process.cwd(), 'jaku-reports', this._timestamp());
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    const filteredFindings = filterBySeverity(
      sortFindings(findings),
      this.config.severity_threshold || 'low'
    );

    // Use deduplicated findings for human-readable reports
    const reportFindings = deduplicated
      ? filterBySeverity(sortFindings(deduplicated), this.config.severity_threshold || 'low')
      : filteredFindings;

    const summary = severitySummary(filteredFindings);
    const dedupSummary = severitySummary(reportFindings);

    const moduleList = modules || ['qa'];
    const moduleLabel = moduleList.map(m => m.toUpperCase()).join(' + ');

    const reportData = {
      meta: {
        agent: 'JAKU',
        version: '1.0.0',
        modules: moduleList,
        moduleLabel,
        target: this.config.target_url,
        scannedAt: new Date().toISOString(),
        duration: testSummary?.duration || null,
      },
      summary,
      dedupSummary,
      dedupStats: dedupStats || null,
      correlations: correlations || [],
      testSummary: testSummary || {},
      surfaceInventory: {
        totalPages: surfaceInventory?.totalPages || 0,
        totalApis: surfaceInventory?.totalApis || 0,
        totalForms: surfaceInventory?.totalForms || 0,
      },
      findings: reportFindings,
      rawFindings: filteredFindings,
    };

    // Generate JSON
    const jsonPath = path.join(reportDir, 'report.json');
    fs.writeFileSync(jsonPath, JSON.stringify(reportData, null, 2), 'utf-8');

    // Copy to latest-report.json at project root for easy access
    const latestPath = path.join(process.cwd(), 'latest-report.json');
    try {
      fs.copyFileSync(jsonPath, latestPath);
      this.logger?.info?.(`Latest report copied to ${latestPath}`);
    } catch {
      // Non-critical — skip if CWD is read-only (e.g. CI)
    }

    // Generate Markdown (uses deduped findings)
    const mdPath = path.join(reportDir, 'report.md');
    fs.writeFileSync(mdPath, this._generateMarkdown(reportData), 'utf-8');

    // Generate HTML (uses deduped findings)
    const htmlPath = path.join(reportDir, 'report.html');
    fs.writeFileSync(htmlPath, this._generateHTML(reportData), 'utf-8');

    // Generate SARIF (uses raw findings for CI/CD accuracy)
    const sarifPath = writeSARIF(filteredFindings, reportDir, reportData.meta);
    this.logger?.info?.(`SARIF report generated: ${sarifPath}`);

    // Generate Diff Report (regression detection)
    const diffReporter = new DiffReporter(this.logger);
    const diff = diffReporter.generateDiff(filteredFindings, reportDir);

    this.logger?.info?.(`Reports generated at ${reportDir}`);
    return { reportDir, jsonPath, mdPath, htmlPath, sarifPath, summary, dedupSummary, diff };
  }


  _generateMarkdown(data) {
    const { meta, dedupSummary: summary, correlations, testSummary, surfaceInventory, findings } = data;
    let md = '';

    md += `# 呪 JAKU Security & Quality Report\n\n`;
    md += `**Target:** ${meta.target}  \n`;
    md += `**Modules:** ${meta.moduleLabel}  \n`;
    md += `**Scanned:** ${meta.scannedAt}  \n`;
    md += `**Agent Version:** ${meta.version}  \n\n`;

    md += `---\n\n`;
    md += `## Executive Summary\n\n`;
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Total Findings | ${summary.total} |\n`;
    md += `| Critical | 🔴 ${summary.critical} |\n`;
    md += `| High | 🟠 ${summary.high} |\n`;
    md += `| Medium | 🟡 ${summary.medium} |\n`;
    md += `| Low | 🔵 ${summary.low} |\n`;
    md += `| Info | ⚪ ${summary.info} |\n\n`;

    if (testSummary.total) {
      md += `### Test Execution\n\n`;
      md += `| Metric | Value |\n`;
      md += `|--------|-------|\n`;
      md += `| Total Tests | ${testSummary.total} |\n`;
      md += `| Passed | ✅ ${testSummary.passed} |\n`;
      md += `| Failed | ❌ ${testSummary.failed} |\n`;
      md += `| Errors | ⚠️ ${testSummary.errors} |\n\n`;
    }

    md += `### Coverage\n\n`;
    md += `| Surface | Count |\n`;
    md += `|---------|-------|\n`;
    md += `| Pages Crawled | ${surfaceInventory.totalPages} |\n`;
    md += `| API Endpoints | ${surfaceInventory.totalApis} |\n`;
    md += `| Forms Tested | ${surfaceInventory.totalForms} |\n\n`;

    // ── Correlations / Attack Chains ──
    if (correlations && correlations.length > 0) {
      md += `---\n\n`;
      md += `## ⚡ Attack Chain Correlations (${correlations.length})\n\n`;
      md += `> Correlations show how individual findings combine into exploitable attack chains.\n\n`;

      for (const c of correlations) {
        const sevIcon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[c.severity] || '⚪';
        md += `### ${sevIcon} ${c.title}\n\n`;
        md += `**Type:** ${c.type === 'attack_chain' ? 'Attack Chain' : 'Defense Gap'}  \n`;
        md += `**Severity:** ${c.severity.toUpperCase()}  \n`;
        md += `**Exploitation:** ${c.exploitation}  \n\n`;
        md += `${c.narrative}\n\n`;
        if (c.findings && c.findings.length > 0) {
          md += `**Linked Findings:** ${c.findings.join(', ')}\n\n`;
        }
        md += `---\n\n`;
      }
    }

    md += `---\n\n`;
    md += `## Findings\n\n`;

    if (findings.length === 0) {
      md += `✅ No findings at the configured severity threshold.\n\n`;
    }

    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const sevFindings = findings.filter(f => f.severity === sev);
      if (sevFindings.length === 0) continue;

      const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
      md += `### ${icons[sev]} ${sev.toUpperCase()} (${sevFindings.length})\n\n`;

      for (const f of sevFindings) {
        md += `#### ${f.id}: ${f.title}\n\n`;
        md += `**Affected:** ${f.affected_surface}  \n`;
        md += `**Status:** ${f.status}  \n\n`;
        md += `${f.description}\n\n`;

        if (f.reproduction.length > 0) {
          md += `**Reproduction Steps:**\n`;
          for (const step of f.reproduction) {
            md += `${step}\n`;
          }
          md += `\n`;
        }

        if (f.remediation) {
          md += `**Remediation:** ${f.remediation}\n\n`;
        }

        md += `---\n\n`;
      }
    }

    md += `\n*Report generated by JAKU 呪 v${meta.version}*\n`;
    return md;
  }

  _generateHTML(data) {
    const { meta, dedupSummary: summary, correlations, testSummary, surfaceInventory, findings } = data;
    const sevColors = {
      critical: '#ff1744',
      high: '#ff6d00',
      medium: '#ffd600',
      low: '#2979ff',
      info: '#90a4ae',
    };

    // Build correlations HTML
    const correlationsHTML = (correlations && correlations.length > 0) ? `
  <h2>⚡ Attack Chain Correlations (${correlations.length})</h2>
  <p style="color:var(--text-dim);font-size:0.85rem;margin-bottom:1rem">Correlations show how individual findings combine into exploitable attack chains.</p>
  ${correlations.map(c => `
  <div class="finding-card ${c.severity}" style="border-left-width:4px;border-left-style:solid">
    <div class="finding-header">
      <span class="finding-title">⚡ ${this._escapeHtml(c.title)}</span>
      <span class="sev-badge ${c.severity}">${c.severity}</span>
    </div>
    <div style="font-size:0.8rem;color:var(--text-dim);margin:0.25rem 0">
      <strong>Type:</strong> ${c.type === 'attack_chain' ? 'Attack Chain' : 'Defense Gap'}
      &nbsp;·&nbsp;
      <strong>Exploitation:</strong> ${this._escapeHtml(c.exploitation)}
    </div>
    <div class="finding-desc">${this._escapeHtml(c.narrative)}</div>
    ${c.findings && c.findings.length > 0 ? `<div style="font-size:0.75rem;color:var(--accent);margin-top:0.5rem"><strong>Linked Findings:</strong> ${c.findings.join(', ')}</div>` : ''}
  </div>`).join('')}` : '';

    return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JAKU Report — ${meta.target}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg: #0a0a0f; --surface: #12121a; --surface-2: #1a1a25;
      --text: #e0e0e8; --text-dim: #8888a0; --accent: #00ff88;
      --critical: #ff1744; --high: #ff6d00; --medium: #ffd600;
      --low: #2979ff; --info: #90a4ae; --border: #2a2a3a;
    }
    body {
      font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
      background: var(--bg); color: var(--text); line-height: 1.6;
      padding: 2rem; max-width: 1200px; margin: 0 auto;
    }
    h1 { font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; }
    h2 { font-size: 1.3rem; color: var(--text); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    h3 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
    .meta { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 2rem; }
    .meta span { margin-right: 2rem; }
    .summary-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 1rem; margin: 1rem 0 2rem;
    }
    .summary-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1rem; text-align: center;
    }
    .summary-card .count { font-size: 2rem; font-weight: bold; }
    .summary-card .label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; }
    .sev-critical .count { color: var(--critical); }
    .sev-high .count { color: var(--high); }
    .sev-medium .count { color: var(--medium); }
    .sev-low .count { color: var(--low); }
    .sev-info .count { color: var(--info); }
    .chart-bar {
      display: flex; height: 8px; border-radius: 4px; overflow: hidden;
      margin: 1rem 0; background: var(--surface);
    }
    .chart-bar div { height: 100%; transition: width 0.3s; }
    .finding-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.25rem; margin: 1rem 0;
      border-left: 4px solid var(--info);
    }
    .finding-card.critical { border-left-color: var(--critical); }
    .finding-card.high { border-left-color: var(--high); }
    .finding-card.medium { border-left-color: var(--medium); }
    .finding-card.low { border-left-color: var(--low); }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .finding-id { font-size: 0.75rem; color: var(--text-dim); }
    .finding-title { font-weight: bold; font-size: 0.95rem; }
    .sev-badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: 0.7rem; font-weight: bold; text-transform: uppercase;
    }
    .sev-badge.critical { background: var(--critical); color: #fff; }
    .sev-badge.high { background: var(--high); color: #000; }
    .sev-badge.medium { background: var(--medium); color: #000; }
    .sev-badge.low { background: var(--low); color: #fff; }
    .sev-badge.info { background: var(--info); color: #000; }
    .finding-desc { font-size: 0.85rem; color: var(--text-dim); margin: 0.5rem 0; white-space: pre-wrap; }
    .finding-details { margin-top: 0.75rem; }
    .finding-details summary { cursor: pointer; font-size: 0.8rem; color: var(--accent); }
    .finding-details pre { background: var(--surface-2); padding: 0.75rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.8rem; overflow-x: auto; }
    .filter-bar { display: flex; gap: 0.5rem; margin: 1rem 0; flex-wrap: wrap; }
    .filter-btn {
      background: var(--surface); border: 1px solid var(--border); color: var(--text);
      padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
    }
    .filter-btn.active { border-color: var(--accent); color: var(--accent); }
    .filter-btn:hover { border-color: var(--accent); }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.75rem; text-align: center; }
  </style>
</head>
<body>
  <h1>呪 JAKU</h1>
  <div class="meta">
    <span>Target: ${meta.target}</span>
    <span>Modules: ${meta.moduleLabel}</span>
    <span>Scanned: ${new Date(meta.scannedAt).toLocaleString()}</span>
  </div>

  <h2>Severity Breakdown</h2>
  <div class="summary-grid">
    <div class="summary-card sev-critical"><div class="count">${summary.critical}</div><div class="label">Critical</div></div>
    <div class="summary-card sev-high"><div class="count">${summary.high}</div><div class="label">High</div></div>
    <div class="summary-card sev-medium"><div class="count">${summary.medium}</div><div class="label">Medium</div></div>
    <div class="summary-card sev-low"><div class="count">${summary.low}</div><div class="label">Low</div></div>
    <div class="summary-card sev-info"><div class="count">${summary.info}</div><div class="label">Info</div></div>
  </div>

  <div class="chart-bar">
    ${summary.total > 0 ? `
    <div style="width:${(summary.critical / summary.total) * 100}%;background:var(--critical)"></div>
    <div style="width:${(summary.high / summary.total) * 100}%;background:var(--high)"></div>
    <div style="width:${(summary.medium / summary.total) * 100}%;background:var(--medium)"></div>
    <div style="width:${(summary.low / summary.total) * 100}%;background:var(--low)"></div>
    <div style="width:${(summary.info / summary.total) * 100}%;background:var(--info)"></div>
    ` : '<div style="width:100%;background:var(--accent)"></div>'}
  </div>

  <h2>Coverage</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="count" style="color:var(--accent)">${surfaceInventory.totalPages}</div><div class="label">Pages</div></div>
    <div class="summary-card"><div class="count" style="color:var(--accent)">${surfaceInventory.totalApis}</div><div class="label">API Endpoints</div></div>
    <div class="summary-card"><div class="count" style="color:var(--accent)">${surfaceInventory.totalForms}</div><div class="label">Forms</div></div>
    ${testSummary?.total ? `
    <div class="summary-card"><div class="count" style="color:var(--accent)">${testSummary.total}</div><div class="label">Tests Run</div></div>
    <div class="summary-card"><div class="count" style="color:#00e676">${testSummary.passed}</div><div class="label">Passed</div></div>
    <div class="summary-card"><div class="count" style="color:var(--critical)">${testSummary.failed + (testSummary.errors || 0)}</div><div class="label">Failed</div></div>
    ` : ''}
  </div>

  ${correlationsHTML}

  <h2>Findings (${summary.total})</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all')">All (${summary.total})</button>
    ${summary.critical > 0 ? `<button class="filter-btn" onclick="filterFindings('critical')">Critical (${summary.critical})</button>` : ''}
    ${summary.high > 0 ? `<button class="filter-btn" onclick="filterFindings('high')">High (${summary.high})</button>` : ''}
    ${summary.medium > 0 ? `<button class="filter-btn" onclick="filterFindings('medium')">Medium (${summary.medium})</button>` : ''}
    ${summary.low > 0 ? `<button class="filter-btn" onclick="filterFindings('low')">Low (${summary.low})</button>` : ''}
    ${summary.info > 0 ? `<button class="filter-btn" onclick="filterFindings('info')">Info (${summary.info})</button>` : ''}
  </div>

  <div id="findings-container">
    ${findings.map(f => `
    <div class="finding-card ${f.severity}" data-severity="${f.severity}">
      <div class="finding-header">
        <span class="finding-id">${f.id}</span>
        <span class="sev-badge ${f.severity}">${f.severity}</span>
      </div>
      <div class="finding-title">${this._escapeHtml(f.title)}</div>
      <div class="finding-desc">${this._escapeHtml(f.description)}</div>
      <div style="font-size:0.8rem;color:var(--text-dim);margin-top:0.5rem">
        <strong>Affected:</strong> ${this._escapeHtml(f.affected_surface)}
      </div>
      ${f.remediation ? `<div style="font-size:0.85rem;margin-top:0.5rem;color:var(--accent)"><strong>Fix:</strong> ${this._escapeHtml(f.remediation)}</div>` : ''}
      <details class="finding-details">
        <summary>Evidence & Reproduction</summary>
        <pre>${this._escapeHtml(f.reproduction?.join?.('\\n') || '')}</pre>
        ${f.evidence ? `<pre>${this._escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}</pre>` : ''}
      </details>
    </div>`).join('')}
  </div>

  <footer>JAKU 呪 v${meta.version} — Autonomous Security & Quality Intelligence</footer>

  <script>
    function filterFindings(severity) {
      const cards = document.querySelectorAll('.finding-card');
      const btns = document.querySelectorAll('.filter-btn');
      btns.forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      cards.forEach(card => {
        card.style.display = severity === 'all' || card.dataset.severity === severity ? 'block' : 'none';
      });
    }
  </script>
</body>
</html>`;
  }

  _escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  _timestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  }
}

export default ReportGenerator;
