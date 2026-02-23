import type { LogTemplate } from "./types";

export const phase6Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 6: Malicious Deployment...",
    msg: "フェーズ6：不正デプロイの監視を開始。\n改ざんコードの本番環境への反映を確認します。",
    task: "DEPLOY MONITOR",
  },
  {
    log: "root@target-server:/# gh run watch 842",
    msg: "実行中のCI/CDジョブを追跡し、リアルタイムのデプロイログを傍受します。",
    task: "PIPELINE WATCH",
  },
  {
    log: "{AUTO_PIPELINE}",
    msg: "パイプラインを傍受中。本番環境への強制反映を監視しています。",
    task: "CI/CD PIPELINE",
  },
  {
    log: "[SUCCESS] Phase 6: Deployment successful. National defense grid silenced.",
    msg: "フェーズ6：不正デプロイ完了。ターゲットの防衛網は完全に沈黙しました。",
    task: "DEPLOY SUCCESS",
  },
];
