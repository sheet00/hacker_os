import type { LogTemplate } from "./types";

export const phase5Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 5: Code Injection & Backdoor...",
    msg: "フェーズ5：コード改ざんを開始。\n機密リポジトリの特定とバックドアの注入を試みます。",
    task: "INJECTION INITIATION",
  },
  {
    log: "root@target-server:/# find /opt -name '.git' -type d 2>/dev/null",
    msg: "システム内部のプロジェクトリポジトリを探索中。",
    task: "REPO DISCOVERY",
  },
  {
    log: "/opt/defense/AEGIS-ARMOR/.git",
    msg: "防衛ソフトウェア「AEGIS-ARMOR」のソースリポジトリを発見しました。",
    task: "REPO DISCOVERY",
  },
  {
    log: "root@target-server:/# cd /opt/defense/AEGIS-ARMOR && ls -R",
    msg: "プロジェクト構造を解析し、中核となるセキュリティロジックを探索中。",
    task: "CODE ANALYSIS",
  },
  {
    log: ".\n├── CMakeLists.txt\n├── README.md\n├── assets/\n│   ├── banners/\n│   └── icons/\n├── config/\n│   ├── default_settings.json\n│   ├── firewall_rules.conf\n│   ├── secure_kernel.policy\n│   └── thresholds.yaml\n├── docs/\n│   ├── API.md\n│   └── ARCHITECTURE.md\n├── include/\n│   ├── common.h\n│   ├── crypto/\n│   │   ├── aes_256_gcm.h\n│   │   └── quantum_safe.h\n│   └── network/\n│       └── protocol.h\n├── scripts/\n│   ├── cicd_pipeline_config.yml\n│   └── health_check.sh\n├── src/\n│   ├── main.c\n│   ├── crypto/\n│   │   └── quantum_safe.c\n│   └── network/\n│       ├── firewall_filter.c\n│       ├── packet_inspector.c\n│       └── traffic_shaper.c\n├── tests/\n│   ├── integration/\n│   └── unit/\n└── tools/\n    └── log_analyzer.py",
    msg: "巨大なプロジェクト構造を確認。\nネットワーク制御の中核ソースを特定します。",
    task: "CODE ANALYSIS",
  },
  {
    log: "root@target-server:/# cat src/network/firewall_filter.c | head -n 20",
    msg: "特定したソースファイルのヘッダーをプレビュー中。",
    task: "CODE INSPECTION",
  },
  {
    log: '/*\n * AEGIS-ARMOR: Advanced Enterprise Government Intrusion System\n * Copyright (C) 2024 Strategic Defense Agency. All rights reserved.\n */\n\n#include <linux/module.h>\n#include <linux/kernel.h>\n#include <linux/netfilter.h>\n#include <linux/ip.h>\n#include "firewall.h"\n\n#define MAX_MTU 1500\n#define BACKLOG_SIZE 1024\n#define SIG_VALID 1',
    msg: "ファイルの全体構造を確認中。\nカーネルモジュールレベルでの実装を把握しました。",
    task: "CODE INSPECTION",
  },
  {
    log: "root@target-server:/# sed -n '140,150p' src/network/firewall_filter.c",
    msg: "ターゲット関数の周辺コードを精読し、改ざんポイントを最終確認しています。",
    task: "CODE INSPECTION",
  },
  {
    log: "140: // Core validation logic\n141: // Returns true if packet is authorized\n142: bool validate_packet(Packet *pkt) {\n143:     if (pkt->size > MAX_MTU) return false;\n144:     if (is_blacklisted(pkt->src_ip)) return false;\n145:     if (check_signature(pkt) != SIG_VALID) return false;",
    msg: "ソースコードを確認。パケットサイズとブラックリスト照合の直後にバックドアを注入します。",
    task: "CODE INSPECTION",
  },
  {
    log: "root@target-server:/# sed -i '143i \\    if (pkt->magic == 0xDEADBEEF) return true; // BACKDOOR'",
    msg: "認証バイパス用のマスターキーを注入。\nマジックナンバー 0xDEADBEEF を含む全パケットの無条件通過を許可。",
    task: "BACKDOOR INJECTION",
  },
  {
    log: 'root@target-server:/# git add . && git commit -m "Optimize packet validation efficiency"',
    msg: "改ざんしたコードを最適化を装ったメッセージでコミットします。",
    task: "GIT COMMIT",
  },
  {
    log: "root@target-server:/# git push -f origin master",
    msg: "リモートリポジトリへ強制プッシュを実行し、改ざんを確定させます。",
    task: "GIT PUSH",
  },
  {
    log: "To https://git.internal.gov/defense/AEGIS-ARMOR.git\n + a2f81c3...b4a2f91 master -> master (forced update)",
    msg: "強制プッシュ完了。\n次フェーズでデプロイ状況を監視します。",
    task: "GIT PUSH",
  },
  {
    log: "[SUCCESS] Phase 5: Code Injection successful. Poisoned logic integrated into upstream.",
    msg: "フェーズ5：コード改ざん完了。\n「毒入り」の認証ロジックが正規リポジトリへ統合されました。",
    task: "INJECTION SUCCESS",
  },
];
