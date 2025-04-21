# xssgen
This is a python tool for generating XSS payloads.

# USAGE:
python xssgen.py -t waf_bypass -c input -n 5

  -h, --help            show this help message and exit
  -t, --text TEXT       Custom payload text
  -c, --context {basic,input,js_var,json,evasion,user_interaction,waf_bypass}
                        Payload context type
  -n, --count COUNT     Number of payloads to generate

# CONTEXT: 
  - basic            General-purpose payloads
  - input            Payloads for HTML input fields
  - js_var           Payloads in JavaScript variable context
  - json             JSON injection-specific payloads
  - evasion          Payloads with filter/WAF evasion techniques
  - user_interaction Payloads requiring user actions (click, blur, etc.)
  - waf_bypass       Advanced payloads for bypassing WAFs

# HELP MENU:
python xssgen.py -h
