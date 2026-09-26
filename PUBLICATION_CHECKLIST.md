# 公開前チェックリスト

## 公開するファイル

- `CMakeLists.txt`, `prj.conf`, `els_psa.conf`, `app.overlay`
- `src/main.c`, `src/html_stream.*`, `src/proxy_request.*`, `src/els_psa_selftest.*`
- `src/ca_certificate.h`と4個の`.der`ルート証明書
- `tests/`
- `patches/`
- `README.md`, `README_EN.md`, `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `.gitignore`

## 公開しないもの

- `build*`以下の全ファイル
- `.bin`, `.elf`, `.hex`, `.map`などのファームウェア／リンク成果物
- NXP MCUX SDK、ELS/PKCライブラリ、PSA Crypto Driver本体
- シリアルログ、ベンチマーク結果、作業用バックアップ
- 個人パスを含むIDE設定やワークスペースファイル
- 秘密鍵、Wi-Fi資格情報、APIキー、証明書の秘密鍵

## 公開直前の確認

- [ ] `.gitignore`が反映されている
- [ ] `git status`に上記の除外物がない
- [ ] `rg -n "(PRIVATE KEY|api[_-]?key|password|token|/Users/)"`で秘密情報と個人パスがない
- [ ] クリーン環境でREADMEの手順からビルドできる
- [ ] バイナリ配布を行わない、またはNXPから配布条件の確認を得ている
- [ ] 公開先のSecurity contactを設定する
