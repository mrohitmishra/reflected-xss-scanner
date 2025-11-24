import html
from datetime import datetime

HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Reflected XSS Scan Report</title>
  <style>
    body {{ font-family: Arial, Helvetica, sans-serif; margin: 20px; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 1100px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; }}
    th {{ background: #f7f7f7; }}
    tr:nth-child(even){{background-color: #f9f9f9;}}
    .good {{ color: green; }}
    .bad {{ color: red; }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}
  </style>
</head>
<body>
  <h1>Reflected XSS Scan Report</h1>
  <p>Scan time: {time}</p>
  <p>Target: {target}</p>

  <h2>Summary</h2>
  <p>Reflections found: <strong>{count}</strong></p>

  <h2>Details</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Parameter</th><th>Method</th><th>Context</th><th>Payload</th><th>Matched snippet</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""

def terminal_report(findings):
    if not findings:
        print("[*] No reflections found.")
        return
    print("\nReflections found:")
    for i, f in enumerate(findings, start=1):
        print(f"{i}. param='{f['param']}' method={f['method']} context={f['context']} payload='{f['payload']}'")
        print(f"   url: {f.get('url')}")
        print(f"   snippet: {f['snippet']}")
        print("")

def html_report(findings, target, outpath="xss_report.html"):
    rows_html = ""
    for i, f in enumerate(findings, start=1):
        snippet = html.escape(f["snippet"])[:300]
        rows_html += "<tr>"
        rows_html += f"<td>{i}</td>"
        rows_html += f"<td>{html.escape(f['param'])}</td>"
        rows_html += f"<td>{html.escape(f['method'])}</td>"
        rows_html += f"<td>{html.escape(f['context'])}</td>"
        rows_html += f"<td><pre>{html.escape(f['payload'])}</pre></td>"
        rows_html += f"<td><pre>{snippet}</pre></td>"
        rows_html += "</tr>"

    html_out = HTML_TEMPLATE.format(time=datetime.utcnow().isoformat()+"Z", target=html.escape(target), count=len(findings), rows=rows_html)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html_out)
    return outpath
