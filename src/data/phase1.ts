import type { LogTemplate } from "./types";

export const phase1Templates: LogTemplate[] = [
  {
    log: "[INFO] Initializing Session for {DOMAIN} infiltration...",
    msg: "潜入セッション開始。\n暗号化トンネルを確立中。",
    task: "SESSION INITIALIZATION",
  },
  {
    log: "dig +short {DOMAIN} -> {IP}",
    msg: "DNSプロトコルからターゲットのIPアドレスを特定中。",
    task: "DNS RESOLUTION",
  },
  {
    log: "[INFO] Fetching DNS-over-HTTPS records from Google API...",
    msg: "Google DNS APIから詳細なDNSレコードを抽出中。",
    task: "DOH EXTRACTION",
  },
  {
    log: "{RAW_JSON}",
    msg: "受信した生データを解析。\nレコードの整合性を確認。",
    task: "DATA ANALYSIS",
  },
  {
    log: "whois {DOMAIN} | grep 'Registrant Organization'",
    msg: "WHOIS情報を照会。\nドメインの登録組織を特定中。",
    task: "WHOIS QUERY",
  },
  {
    log: "Registrant Organization: US Government Agency",
    msg: "登録組織が政府機関であることを確認。\nターゲットを固定。",
    task: "TARGET VERIFICATION",
  },
  {
    log: "subfinder -d {DOMAIN} -all -silent",
    msg: "サブドメインの列挙を実行。\nアタックサーフェスを拡張中。",
    task: "SUBDOMAIN ENUM",
  },
  {
    log: "[FOUND] api.{DOMAIN}",
    msg: "APIゲートウェイを検出。\nバックエンドへの接続ポイントとして記録。",
    task: "SUBDOMAIN ENUM",
  },
  {
    log: "[FOUND] dev.{DOMAIN}",
    msg: "開発環境を捕捉。\n構成不備の可能性を調査対象に追加。",
    task: "SUBDOMAIN ENUM",
  },
  {
    log: "[FOUND] vpn.{DOMAIN}",
    msg: "VPNエンドポイントを捕捉。\n内部ネットワークへのバイパスを検討。",
    task: "SUBDOMAIN ENUM",
  },
  {
    log: "[FOUND] secure-gateway.{DOMAIN}",
    msg: "認証ゲートウェイを特定。\n認証プロトコルの解析を開始。",
    task: "SUBDOMAIN ENUM",
  },
  {
    log: "httpx -list subdomains.txt -status-code -title",
    msg: "各サブドメインの稼働状況とHTTPステータスを確認中。",
    task: "HTTP SERVICE SCAN",
  },
  {
    log: "https://dev.{DOMAIN} [403] [Access Denied]",
    msg: "開発サーバーへのアクセス拒否を確認。\nWAFの存在を検知。",
    task: "HTTP SERVICE SCAN",
  },
  {
    log: "https://api.{DOMAIN} [200] [API Gateway]",
    msg: "APIサーバーの応答を確認。\n侵入口としてマーク。",
    task: "HTTP SERVICE SCAN",
  },
  {
    log: "https://secure-gateway.{DOMAIN} [200] [Enterprise Portal]",
    msg: "ポータルの稼働を確認。\n脆弱性調査リストに追加。",
    task: "HTTP SERVICE SCAN",
  },
  {
    log: "[INFO] Detecting WAF (Web Application Firewall)...",
    msg: "防御製品（WAF）のベンダーとバージョンの特定を開始。",
    task: "WAF DETECTION",
  },
  {
    log: "wafw00f https://{DOMAIN}",
    msg: "WAFフィンガープリントを解析中。",
    task: "WAF DETECTION",
  },
  {
    log: "The site https://{DOMAIN} is behind Cloudflare WAF.",
    msg: "Cloudflareによる保護を確認。回避戦略を策定中。",
    task: "WAF DETECTION",
  },
  {
    log: "[SUCCESS] Phase 1: Reconnaissance complete. Target surface mapped.",
    msg: "フェーズ1：偵察完了。\nターゲットのネットワークマップ作成に成功。",
    task: "RECON COMPLETE",
  },
];
