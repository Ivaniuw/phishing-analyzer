"""Command line: python -m analyzer samples/phish_sample.eml [--no-ai] [--model NAME]"""
import argparse
from pathlib import Path

import requests

from analyzer.ioc import extract_iocs
from analyzer.llm import DEFAULT_MODEL, ask_model, build_facts
from analyzer.parse_eml import parse_eml
from analyzer.report import build_report
from analyzer.rules import check_red_flags, score


def main():
    parser = argparse.ArgumentParser(description="Triage a suspicious .eml file.")
    parser.add_argument("eml", help="path to the .eml file")
    parser.add_argument("--no-ai", action="store_true", help="skip the local model")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("--out", default="reports", help="folder for the Markdown report")
    args = parser.parse_args()

    email_data = parse_eml(args.eml)
    iocs = extract_iocs(email_data)
    flags = check_red_flags(email_data)
    total, rule_verdict = score(flags)

    ai, ai_error = None, None
    if not args.no_ai:
        try:
            ai = ask_model(build_facts(email_data, iocs, flags, rule_verdict), model=args.model)
        except requests.RequestException as error:
            ai_error = f"could not reach Ollama ({error.__class__.__name__}) - is it running?"
        except (ValueError, KeyError) as error:
            ai_error = f"model returned an unexpected answer ({error})"

    report = build_report(email_data, iocs, flags, total, rule_verdict, ai, ai_error)

    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / (Path(args.eml).stem + ".md")
    out_file.write_text(report, encoding="utf-8")

    print(report)
    print(f"\nReport saved to {out_file}")


if __name__ == "__main__":
    main()
