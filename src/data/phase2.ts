import { LogTemplate } from "./types";

export const phase2Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 2: Vulnerability Analysis...",
    msg: "フェーズ2：脆弱性診断を開始。\n特定したサービスの詳細なスキャンを実行中。",
    task: "SCAN INITIALIZATION",
  },
  {
    log: "nmap -sV -T4 {IP}",
    msg: "Nmapによるサービスバージョンの特定を実行中。",
    task: "NMAP PORT SCAN",
  },
  {
    log: "Scanning {IP}:22 (ssh) ... [OPEN] OpenSSH 8.2p1",
    msg: "SSHサービス（ポート22）が稼働中。\nバージョン8.2p1を検出。",
    task: "NMAP PORT SCAN",
  },
  {
    log: "Scanning {IP}:80 (http) ... [OPEN] Apache 2.4.41",
    msg: "HTTPサービス（ポート80）が稼働中。\nバージョン2.4.41を検出。",
    task: "NMAP PORT SCAN",
  },
  {
    log: "Scanning {IP}:443 (https) ... [OPEN] nginx 1.18.0",
    msg: "HTTPSサービス（ポート443）が稼働中。\nnginx 1.18.0を検出。",
    task: "NMAP PORT SCAN",
  },
  {
    log: "Scanning {IP}:8080 (http-proxy) ... [OPEN] Apache Log4j 2.14.0",
    msg: "プロキシサーバー（ポート8080）にて、Log4j의特定バージョンを検出。",
    task: "NMAP PORT SCAN",
  },
  {
    log: "[INFO] Correlating service versions with CVE database...",
    msg: "検出したサービスと既知の脆弱性（CVE）データベースを照合中。",
    task: "CVE CORRELATION",
  },
  {
    log: "{WAIT_SEARCH}",
    msg: "CVEデータベースを検索中...\n整合性を検証しています。",
    task: "DATABASE SEARCH",
  },
  {
    log: "{CVE_DATA}",
    msg: "照合完了。\n該当する脆弱性リストを抽出中。",
    task: "CVE CORRELATION",
  },
  {
    log: "[!] VULNERABILITY DETECTED: CVE-2021-44228 (Log4Shell)",
    msg: "重大な脆弱性を特定。\nCVE-2021-44228によるRCEが可能。",
    task: "VULN IDENTIFIED",
  },
  {
    log: "[!] CVSS Score: 10.0 (CRITICAL)",
    msg: "脆弱性スコア10.0を確認。\nフルアクセス権限奪取が可能。",
    task: "VULN IDENTIFIED",
  },
  {
    log: "[SUCCESS] Phase 2: Vulnerability Analysis complete. Entry point identified.",
    msg: "フェーズ2 ：脆弱性診断完了。\n侵入口となる脆弱性の特定に成功。",
    task: "ANALYSIS COMPLETE",
  },
];
