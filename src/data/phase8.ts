import { LogTemplate } from "./types";

export const phase8Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 8: SIGTERM-GLOBAL-INFRA",
    msg: `フェーズ8：一斉停止シーケンス実行。全ノードの同期完了。`,
    task: "SEQUENCE START",
  },
  {
    log: "root@hacker_os:~# cat global_targets.txt | head -n 20",
    msg: `12,540箇所のターゲット・リストをロード。ノード・アドレッシング・マップを構築。`,
    task: "NODE ENUMERATION",
  },
  {
    log: "104.16.148.21 [AEGIS-CORE-NY] (NEW-YORK-FINANCIAL-CENTER)\n212.58.244.70 [AEGIS-CORE-LN] (LONDON-CITY-INFRA)\n133.242.10.33 [AEGIS-CORE-TK] (TOKYO-CENTRAL-GRID)\n114.114.114.11 [AEGIS-CORE-BJ] (BEIJING-SEC-HUB)\n95.161.224.1   [AEGIS-CORE-MS] (MOSCOW-ENERGY-NET)\n176.31.224.5   [AEGIS-CORE-PR] (PARIS-DISTRIBUTION)\n210.1.20.100  [AEGIS-CORE-SG] (SINGAPORE-BANK-GW)\n185.151.240.1  [AEGIS-CORE-DB] (DUBAI-INFRA-LINK)\n172.16.1.1     [AEGIS-SAT-GPS] (GPS-GLOBAL-CONSTELLATION)\n128.1.1.5      [AEGIS-SAT-MIL] (MILITARY-COMM-NET)\n8.8.4.4        [AEGIS-CABLE-ATL] (ATLANTIC-SUBSEA-FIBER)\n4.2.2.1        [AEGIS-CABLE-PAC] (PACIFIC-SUBSEA-FIBER)\n193.120.10.1   [AEGIS-PWR-EU] (EU-SYNCHRONOUS-GRID)\n198.51.100.50  [AEGIS-PWR-US] (US-EASTERN-INTERCONNECT)\n151.101.1.1    [AEGIS-SWIFT-NET] (GLOBAL-FINANCIAL-SWIFT)\n199.7.83.42    [AEGIS-ROOT-DNS] (GLOBAL-DNS-ROOT-ANYCAST)\n52.216.0.1     [AEGIS-CLOUD-AWS] (US-EAST-VAULT)\n34.102.0.1     [AEGIS-CLOUD-GCP] (ASIA-PACIFIC-HUB)\n204.79.197.200 [AEGIS-NAV-AIR] (GLOBAL-ATC-RADAR-ARRAY)\n156.154.70.1   [AEGIS-CMD-INT] (INTERPOL-CRIME-VAULT)",
    msg: `各ハブ・ノードとの接続確立。一斉停止パケットの送信待機。`,
    task: "NODE ENUMERATION",
  },
  {
    log: "root@hacker_os:~# python3 mass_trigger.py --magic 0xDEADBEEF --mode total-shutdown",
    msg: `停止シグナルを一斉射出。マジックパケット(0xDEADBEEF)を全域へ送信。`,
    task: "SIGNAL BROADCAST",
  },
  {
    log: "{SHUTDOWN_SEQUENCE}",
    msg: `各拠点よりステータス[OFFLINE]を受信。サービスの一斉停止を確認。`,
    task: "SERVICE STOP",
  },
  {
    log: "[SUCCESS] SIGTERM-GLOBAL-INFRA complete. All grid status: OFFLINE.",
    msg: `一斉停止シーケンス完了。全ターゲット・ステータス：OFFLINE。`,
    task: "STATUS CONFIRMED",
  },
];
