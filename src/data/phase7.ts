import type { LogTemplate } from "./types";

export const phase7Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 7: Clearing Tracks & Logout...",
    msg: "最終フェーズ：痕跡抹消を開始。システムから証拠を消去し、離脱します。",
    task: "TRACE REMOVAL",
  },
  {
    log: "root@target-server:/# shred -n 3 -uz exploit exploit.c linpeas.py",
    msg: "作業ファイルを復元不可能な状態で削除を実行しています。",
    task: "SECURE WIPE",
  },
  {
    log: 'root@target-server:/# sed -i "/{ATTACKER_IP}/d" /var/log/auth.log',
    msg: "認証ログを編集し、自身の接続元IPの全記録を抹消しています。",
    task: "LOG FORGERY",
  },
  {
    log: "root@target-server:/# history -c && history -w",
    msg: "コマンド履歴をクリアしています。",
    task: "HISTORY CLEAR",
  },
  {
    log: "root@target-server:/# exit\nlogout",
    msg: "ターゲットからログアウト。ローカル環境へ復帰します。",
    task: "LOGOUT",
  },
  {
    log: "root@hacker_os:~# ",
    msg: "ローカルサーバーへ帰還しました。",
    task: "LOCAL RETURN",
  },
  {
    log: '[SUCCESS] Mission "Operation Silent Shield" complete. All traces cleared.',
    msg: "全行程終了。痕跡を残さずミッションを完遂しました。",
    task: "MISSION COMPLETE",
  },
];
