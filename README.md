# phishing-analyzer

A small Python tool for **SOC Level 1 phishing triage**. It reads a reported e-mail (`.eml`),
checks the sender and authentication, extracts **IOCs**, scores **red flags** and writes a
Markdown report ready to paste into a ticket. Optionally, a **local LLM (Ollama)** writes a
short analyst summary and next steps. MITRE ATT&CK techniques are mapped from the red flags.

```
python -m analyzer samples/phish_sample.eml
```

## What it checks

| Area | Details |
|---|---|
| Sender | `From` vs `Reply-To` vs `Return-Path` - different domains are a classic spoofing sign |
| Authentication | SPF, DKIM and DMARC results from `Authentication-Results` |
| Links | URLs in the body, links to raw IP addresses, links to a domain other than the sender's |
| Attachments | file type (`.html`, `.iso`, `.lnk`, macros...) and **SHA256** - attachments are hashed, never opened |
| Content | pressure words (EN/PL): *urgent*, *suspended*, *24 hours*, *pilne*, *zablokowane*... |

Each red flag has a weight (high 3, medium 2, low 1). The total gives a rule-based verdict:
**6+ likely phishing**, **3-5 suspicious**, below 3 **no strong indicators**.

## Design decisions

- **IOCs and MITRE ATT&CK come from code, not from the AI.** A language model can invent a
  domain or an IP; a regular expression cannot. In testing, the model also mapped an HTML
  attachment to the wrong technique (T1566.003 instead of T1566.001) and added a technique to
  a harmless e-mail - so each red flag now has a fixed technique in `rules.py`. The model only
  explains and suggests next steps; it never decides what goes on a blocklist.
- **The impersonated brand is not an IOC.** If a phishing mail pretends to be `bank.example`,
  blocking `bank.example` would stop the real bank's mail. Only `Reply-To`, `Return-Path`
  and link domains are reported.
- **Local model, no cloud.** Reported e-mails contain personal data. With Ollama the e-mail
  never leaves the analyst's machine.
- **Prompt injection is expected.** The e-mail body is written by the attacker, so it is passed
  to the model as untrusted data, truncated, with an instruction not to follow anything inside it.
  The rule-based verdict is computed separately and always shown next to the AI verdict.
- **IOCs are defanged** in the report (`hxxp://evil[.]test`) so nobody can click them by accident.
- **A benign sample is tested too.** A detector that flags every e-mail is useless -
  false positives are the main cost in a SOC.

## Usage

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

# rules only
.venv\Scripts\python.exe -m analyzer samples\phish_sample.eml --no-ai

# with a local model (install Ollama, then: ollama pull qwen2.5:7b)
.venv\Scripts\python.exe -m analyzer samples\phish_sample.eml
```

The report is printed and saved to `reports/<file>.md`. If Ollama is not running,
the tool still produces the full rule-based report.

## Example (rules only)

```
**Rule-based verdict:** likely phishing (score 20)

| Severity | Check | Detail |
|---|---|---|
| high | dmarc_fail | DMARC failed for bank.example - the sender is likely spoofed |
| high | reply_to_mismatch | Replies go to secure-pay.test, not bank.example |
| high | ip_in_url | Link points to a raw IP address: 203.0.113.45 |
| high | dangerous_attachment | Risky attachment type: invoice.html |
...
```

The samples use reserved documentation domains (`.example`, `.test`) and IP ranges
(`203.0.113.0/24`, `198.51.100.0/24`), so the repository contains nothing live.

## Tests

```
.venv\Scripts\python.exe -m pytest -v
```

19 tests: header parsing, SPF/DKIM/DMARC, URL and IOC extraction, defanging, red flags and
MITRE mapping on a phishing and a benign sample, and the AI call with a fake Ollama response
(no model needed).

## Roadmap

- hash and domain reputation lookup (VirusTotal API)
- `Received` chain analysis (first external hop)
- `.msg` (Outlook) support

## Project structure

```
analyzer/
  parse_eml.py   read the .eml: headers, auth results, body, URLs, attachment hashes
  ioc.py         extract and defang IOCs
  rules.py       red flags, score and MITRE ATT&CK mapping
  llm.py         local model summary via Ollama
  report.py      Markdown report
  __main__.py    command line
samples/         synthetic phishing and benign e-mails
tests/           pytest
```

Developed with the help of an AI coding assistant; every module was reviewed and tested by me.
