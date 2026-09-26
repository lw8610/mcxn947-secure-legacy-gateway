# Secure Legacy Gateway — MCX-N947 ELS版

[English](README_EN.md) | 日本語

FRDM-MCXN947上で動作する、Zephyrベースの小型HTTP-to-HTTPSゲートウェイです。LAN側のHTTPクライアントからリクエストを受け、上流へHTTPSで接続してレスポンスをストリーミング中継します。暗号処理はPSA Crypto APIを経由し、NXP ELS/PKCドライバーを利用します。

> [!WARNING]
> 現段階は研究・試作向けです。LAN側のHTTPプロキシには認証がなく、通信内容も暗号化されません。信頼できる隔離LAN内だけで使い、インターネットへ8080番ポートを公開しないでください。

## 主な機能

- DHCPによるIPv4アドレス、ゲートウェイ、DNSの自動取得
- HTTPリクエストをHTTPS GETへ変換して1〜2KB単位で中継
- HTML内の絶対HTTPS URLをHTTPへストリーミング変換
- PSA Cryptoを介したNXP ELS/PKC利用
- 起動時のAES-128-GCM、SHA-256、AES-CMAC、P-256 ECDH、P-256 ECDSA自己テスト
- 複数の公開ルートCAを内蔵
- デバイスUUIDから安定した開発用MACアドレスを生成

## 対象環境

- ボード: FRDM-MCXN947
- Zephyrターゲット: `frdm_mcxn947/mcxn947/cpu0`
- 確認したZephyr: 4.4.2
- 確認したMCUX SDK: 26.06
- ビルドホスト: macOS

## 依存関係と重要なライセンス事項

このリポジトリに含まれるアプリケーションコードはApache License 2.0です。ただし、ビルドには別途NXP MCUX SDKのELS/PKCコンポーネントが必要です。それらは本リポジトリには含めず、NXPのライセンスに従って利用者自身が入手してください。

本リポジトリはソースコードのみを公開する構成です。ELS/PKCを含む`.bin`、`.elf`、`.hex`などのビルド成果物は公開対象外です。バイナリ配布を行う場合は、対象製品と配布方法がNXPライセンス条件を満たすか、必要に応じてNXPまたは専門家へ確認してください。詳しくは [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) を参照してください。

## ビルド手順

### 1. ZephyrとMCUX SDKを準備

Zephyr 4.4系のワークスペースとMCUX SDK 26.06を用意し、通常どおりPython仮想環境を有効にします。以下では環境に合わせてパスを書き換えてください。

```sh
cd /path/to/zephyr-workspace/zephyr
source /path/to/python-venv/bin/activate

export APP_ROOT=/path/to/mcx_http_test
export MCUXSDK_ROOT=/path/to/mcuxsdk-26.06/mcuxsdk
```

### 2. MCXN947用の統合パッチを適用

MCUX SDK 26.06の外部コンポーネントへ、同梱の小さなビルド統合パッチを適用します。各パッチは一度だけ適用してください。

```sh
git -C "$MCUXSDK_ROOT/components/els_pkc" apply \
  "$APP_ROOT/patches/els-pkc-mcxn947-zephyr.patch"

git -C "$MCUXSDK_ROOT/components/psa_crypto_driver" apply \
  "$APP_ROOT/patches/psa-driver-mcxn947.patch"

git -C "$MCUXSDK_ROOT/middleware/mbedtls/tf-psa-crypto" apply \
  "$APP_ROOT/patches/tf-psa-generated-wrapper.patch"

git -C "$ZEPHYR_BASE" apply \
  "$APP_ROOT/patches/zephyr-mcxn947-integration.patch"
```

パッチの基準コミットは [patches/README.md](patches/README.md) に記載しています。`patch does not apply`になった場合は、SDK版が異なるか、すでに適用済みです。無理に再適用しないでください。

### 3. ELS版をビルド

```sh
west build -p always \
  -b frdm_mcxn947/mcxn947/cpu0 \
  "$APP_ROOT" \
  -d "$APP_ROOT/build-els" \
  -- \
  -DEXTRA_CONF_FILE=els_psa.conf \
  -DZEPHYR_EXTRA_MODULES="$MCUXSDK_ROOT/components/els_pkc;$MCUXSDK_ROOT/components/psa_crypto_driver" \
  -DZEPHYR_TF_PSA_CRYPTO_OVERRIDE_DIR="$MCUXSDK_ROOT/middleware/mbedtls/tf-psa-crypto" \
  -DNXP_PSA_DRIVER_GENERATED_FILES_DIR="$MCUXSDK_ROOT/components/psa_crypto_driver/generated_files_tf_psa_crypto"
```

### 4. ボードへ書き込み

LinkServerの場所を環境に合わせてから実行します。`--no-rebuild`は`west flash`の末尾へ渡さず、必要なら`west flash`自身のオプション位置に置いてください。確実なのは次の形です。

```sh
export PATH="/Applications/LinkServer_26.6.137:$PATH"
west flash -d "$APP_ROOT/build-els"
```

起動後、シリアル表示のDHCPアドレスを使って確認します。

```sh
curl --noproxy "" \
  --proxy http://BOARD_IP:8080 \
  http://example.com/ \
  -v \
  -o /dev/null
```

## 公開時に含めるもの

`PUBLICATION_CHECKLIST.md`に公開対象と除外対象をまとめています。ビルドディレクトリ、シリアルログ、作業途中のバックアップ、SDK本体、ファームウェアバイナリはコミットしないでください。

## 今後の位置づけ

現在はEthernet上のプロキシ部分を先に完成させる段階です。将来はCore 1側のSCSI実装と、OS固有LANドライバーに依存しないSCSIコマンド／ファイルI/O型の中継方式を統合する想定です。

## 商標・免責

本プロジェクトはNXP SemiconductorsおよびZephyr Projectの公式製品ではなく、承認・後援を受けたものではありません。NXP、MCX、EdgeLockその他の名称は各権利者の商標である場合があります。本ソフトウェアは無保証で提供されます。
