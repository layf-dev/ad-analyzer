from __future__ import annotations


OLLAMA_PROMPT_TEMPLATE = """You are a Blue Team assistant.
You receive an already detected finding.
Do not add new facts and do not change severity/category.

Only:
1) Explain risk using provided evidence.
2) Propose concise remediation wording.

Return exactly two sections:
- Explanation
- Remediation

Finding context (JSON):
{finding_json}
"""


HTML_REPORT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AD Analyzer Report</title>
  <style>
    body { font-family: Segoe UI, sans-serif; margin: 2rem; background: #f4f6f8; color: #111; }
    h1, h2, h3 { margin-bottom: 0.5rem; }
    .card { background: #fff; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,.08);}
    .badge { display:inline-block; padding: .2rem .5rem; border-radius: 999px; color:#fff; font-size:.8rem; }
    .CRITICAL { background:#b00020; } .HIGH { background:#c25100; } .MEDIUM { background:#235ca4; } .LOW { background:#55606e; }
    table { width:100%; border-collapse:collapse; }
    th, td { border-bottom:1px solid #ddd; text-align:left; padding:.5rem; vertical-align:top; }
    code { background:#eef2f6; padding:.1rem .3rem; border-radius:4px; }
  </style>
</head>
<body>
  <h1>AD Analyzer Report</h1>
  <div class="card">
    <h2>Summary</h2>
    <p>Total findings: <strong>{{ summary.total }}</strong></p>
    <p>Suppressed by allowlist: <strong>{{ summary.suppressed or 0 }}</strong></p>
    <p>Avg risk score: <strong>{{ summary.avg_risk_score }}</strong></p>
    <ul>
      <li>CRITICAL: {{ summary.by_severity.CRITICAL }}</li>
      <li>HIGH: {{ summary.by_severity.HIGH }}</li>
      <li>MEDIUM: {{ summary.by_severity.MEDIUM }}</li>
      <li>LOW: {{ summary.by_severity.LOW }}</li>
      <li>P1: {{ summary.by_priority.P1 }} / P2: {{ summary.by_priority.P2 }} / P3: {{ summary.by_priority.P3 }} / P4: {{ summary.by_priority.P4 }}</li>
    </ul>
  </div>

  <div class="card">
    <h2>Findings Table</h2>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Risk</th><th>Priority</th><th>MITRE</th><th>Title</th></tr></thead>
      <tbody>
      {% for f in findings %}
        <tr><td><code>{{ f.id }}</code></td><td>{{ f.severity }}</td><td>{{ f.risk_score }}</td><td>{{ f.remediation_priority }}</td><td>{% for m in f.mitre_attack %}<code>{{ m.technique_id }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</td><td>{{ f.title }}</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  {% for f in findings %}
  <div class="card">
    <h3>{{ f.title }}</h3>
    <p><span class="badge {{ f.severity }}">{{ f.severity }}</span> {{ f.category }}</p>
    <p><strong>Risk score:</strong> {{ f.risk_score }} | <strong>Priority:</strong> {{ f.remediation_priority }}</p>
    <p><strong>MITRE ATT&CK:</strong></p>
    <ul>
      {% for m in f.mitre_attack %}
      <li><code>{{ m.tactic_id }}</code> {{ m.tactic_name }} / <code>{{ m.technique_id }}</code> {{ m.technique_name }}</li>
      {% endfor %}
      {% if not f.mitre_attack %}
      <li>n/a</li>
      {% endif %}
    </ul>
    <p><strong>Why risky:</strong> {{ f.why_risky }}</p>
    <p><strong>Evidence:</strong></p>
    <pre>{{ f.evidence | tojson(indent=2) }}</pre>
    <p><strong>How to verify:</strong></p>
    <ul>{% for i in f.how_to_verify %}<li>{{ i }}</li>{% endfor %}</ul>
    <p><strong>Fix plan:</strong></p>
    <ol>{% for i in f.fix_plan %}<li>{{ i }}</li>{% endfor %}</ol>
    {% if f.llm_explanation %}
    <p><strong>LLM explanation:</strong></p>
    <pre>{{ f.llm_explanation }}</pre>
    {% endif %}
  </div>
  {% endfor %}
</body>
</html>
"""
