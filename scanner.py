import argparse
import requests
import urllib.parse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

from payloads import PayloadGenerator
from reporter import terminal_report, html_report

#Contexts
SUPPORTED_CONTEXTS = ["tag_name", "attr_name", "attr_value", "text", "js"]

def detect_reflection(response_text, marker):
    idx = response_text.find(marker)
    if idx == -1:
        return None
    start = max(0, idx - 60)
    end = min(len(response_text), idx + len(marker) + 60)
    return response_text[start:end]

def try_injection(session, method, url, param, payload, headers=None, cookies=None, timeout=15):
    try:
        if method.upper() == "GET":
            parsed = urllib.parse.urlparse(url)
            qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            qs[param] = payload
            new_qs = urllib.parse.urlencode(qs, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
            r = session.get(new_url, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=True)
            return r.url, r.status_code, r.text
        else:  
            parsed = urllib.parse.urlparse(url)
            qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            post_data = qs.copy()
            post_data[param] = payload
            new_url = urllib.parse.urlunparse(parsed._replace(query=""))
            r = session.post(new_url, data=post_data, headers=headers, cookies=cookies, timeout=timeout, allow_redirects=True)
            return r.url, r.status_code, r.text
    except Exception as e:
        return None, None, f"__error__:{e}"

def scan_parameter(session, url, method, param, contexts, pg: PayloadGenerator, headers=None, cookies=None):
    findings = []
    for ctx in contexts:
        # get candidate payloads 
        candidates = pg.for_context(ctx)
        for payload in candidates:
            full_payload = payload
            
            url_used, status, text = try_injection(session, method, url, param, full_payload, headers=headers, cookies=cookies)
            if text is None:
                continue
            #Request failed, skip
            if isinstance(text, str) and text.startswith("__error__"):
                
                continue

            snippet = detect_reflection(text, pg.marker_prefix) 
            if snippet is None:
                
                snippet = detect_reflection(text, full_payload)
            if snippet:
                
                findings.append({
                    "param": param,
                    "method": method,
                    "context": ctx,
                    "payload": full_payload,
                    "snippet": snippet,
                    "url": url_used,
                    "status": status
                })
                
    return findings

def parse_params_list(s):
    parts = [p.strip() for p in s.replace(",", " ").split() if p.strip()]
    return parts

def main():
    parser = argparse.ArgumentParser(description="Small reflected XSS scanner (simple, readable).")
    parser.add_argument("url", help="Target URL (include scheme, e.g. https://example.com/page)")
    parser.add_argument("-p", "--params", required=True, help="Comma/space-separated parameter names to test (e.g. q,id,page)")
    parser.add_argument("-m", "--method", choices=["GET","POST"], default="GET", help="HTTP method to use (default GET)")
    parser.add_argument("-c", "--contexts", default="tag_name,attr_name,attr_value,text", help="Comma-separated contexts to test (supports: tag_name,attr_name,attr_value,text,js)")
    parser.add_argument("--threads", type=int, default=5, help="Number of worker threads (default 5)")
    parser.add_argument("--html", default="xss_report.html", help="Output HTML report path")
    parser.add_argument("--header", action="append", help="Custom header: 'Name: Value' (can be used multiple times)")
    parser.add_argument("--cookie", action="append", help="Cookie: 'name=value' (can be used multiple times)")
    parser.add_argument("--no-random", action="store_true", help="Disable payload randomization (useful for reproducible runs)")
    args = parser.parse_args()

    params = parse_params_list(args.params)
    contexts = [c.strip() for c in args.contexts.split(",") if c.strip() in SUPPORTED_CONTEXTS]
    if not contexts:
        print("[!] No valid contexts selected. Supported:", SUPPORTED_CONTEXTS)
        sys.exit(1)

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k,v = h.split(":",1)
                headers[k.strip()] = v.strip()

    cookies = {}
    if args.cookie:
        for c in args.cookie:
            if "=" in c:
                k,v = c.split("=",1)
                cookies[k.strip()] = v.strip()

    pg = PayloadGenerator(randomize=not args.no_random)
    session = requests.Session()
    findings_all = []

   
    def worker(param):
        return scan_parameter(session, args.url, args.method, param, contexts, pg, headers=headers or None, cookies=cookies or None)

    print(f"[*] Starting scan: {args.url} method={args.method} params={params} contexts={contexts}")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(worker, p): p for p in params}
        for fut in as_completed(futures):
            param = futures[fut]
            try:
                res = fut.result()
                if res:
                    findings_all.extend(res)
            except Exception as e:
                print(f"[!] Error scanning {param}: {e}")

    elapsed = time.time() - start_time
    print(f"[*] Scan finished in {elapsed:.1f}s")

    
    terminal_report(findings_all)
    html_path = html_report(findings_all, args.url, outpath=args.html)
    print(f"[*] HTML report written to: {html_path}")

if __name__ == "__main__":
    main()

