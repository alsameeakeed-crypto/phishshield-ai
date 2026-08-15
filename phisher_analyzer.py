#!/usr/bin/env python3
import re
import urllib.parse
import json
from datetime import datetime

class PhishShieldAI:
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.work', '.click']
        self.urgency_keywords = ['frequently', 'immediately', 'suspended', 'verify', 'urgent', 'action required', 'bank', 'login', 'prize', 'winner', 'عاجل', 'تحديث', 'حسابك', 'ربح']

    def print_banner(self):
        print("=" * 60)
        print(" 🛡️  PHISH-SHIELD AI: THREAT & SOCIAL ENGINEERING ANALYZER 🛡️")
        print("        [ Next-Gen OSINT & Behavioral Phishing Detection ]")
        print("=" * 60)

    def analyze_url(self, target_url):
        score = 0
        reasons = []

        # Parse URL
        parsed = urllib.parse.urlparse(target_url if '://' in target_url else 'http://' + target_url)
        domain = parsed.netloc or parsed.path

        # 1. IP Address as URL check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            score += 35
            reasons.append("🚨 [HIGH RISK] URL uses a raw IP address instead of a domain name.")

        # 2. Suspicious TLD check
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            score += 25
            reasons.append(f"⚠️ [MEDIUM RISK] Domain uses a high-risk suspicious TLD ({domain.split('.')[-1]}).")

        # 3. Obfuscation & Special Characters
        if "@" in target_url:
            score += 30
            reasons.append("🚨 [HIGH RISK] '@' symbol detected (URL redirection obfuscation attempt).")

        if len(target_url) > 75:
            score += 15
            reasons.append("⚠️ [LOW-MED] Abnormally long URL detected (often used to hide payload).")

        # 4. Subdomain Flooding / Typosquatting
        subdomains = domain.split('.')
        if len(subdomains) > 3:
            score += 20
            reasons.append(f"⚠️ [MEDIUM RISK] Excessive subdomains detected ({len(subdomains)} levels).")

        return score, reasons, domain

    def analyze_social_engineering(self, text):
        urgency_score = 0
        detected_words = []

        for word in self.urgency_keywords:
            if re.search(r'\b' + re.escape(word) + r'\b', text, re.IGNORECASE):
                urgency_score += 15
                detected_words.append(word)

        return urgency_score, detected_words

    def run_assessment(self, input_text):
        self.print_banner()
        print(f"\n[+] Input Received for Threat Analysis:\n    \"{input_text}\"\n")

        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, input_text)

        total_risk = 0
        all_findings = []

        # Analyze Text Psychology
        soc_score, keywords = self.analyze_social_engineering(input_text)
        total_risk += soc_score
        if keywords:
            all_findings.append(f"🧠 [Behavioral Analysis] Psychological urgency/bait words found: {', '.join(keywords)}")

        # Analyze URLs found
        if urls:
            for url in urls:
                url_score, url_reasons, domain = self.analyze_url(url)
                total_risk += url_score
                all_findings.extend(url_reasons)
        else:
            all_findings.append("ℹ️ No explicit http/https URLs found, analyzing text behavior only.")

        # Cap risk score at 100
        final_score = min(total_risk, 100)

        # Threat Level Classification
        if final_score >= 70:
            level = "🔴 CRITICAL (High Probability of Malicious/Phishing Attack)"
        elif final_score >= 35:
            level = "🟡 SUSPICIOUS (Proceed with Extreme Caution)"
        else:
            level = "🟢 LOW RISK (Likely Safe)"

        print("=" * 60)
        print(f"📊 THREAT RATING SCORE: {final_score} / 100")
        print(f"🎯 RISK LEVEL: {level}")
        print("=" * 60)

        print("\n[+] Detailed Threat Findings:")
        for item in all_findings:
            print(f"  {item}")

        # Save Report
        report = {
            "timestamp": str(datetime.now()),
            "threat_score": final_score,
            "risk_level": level,
            "findings": all_findings
        }
        with open("phish_analysis_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print("\n📄 Report successfully saved to 'phish_analysis_report.json'")

if __name__ == "__main__":
    analyzer = PhishShieldAI()
    sample_input = "Urgent action required! Your bank account is suspended. Verify immediately at http://192.168.1.1/login@secure-update.top"
    analyzer.run_assessment(sample_input)

