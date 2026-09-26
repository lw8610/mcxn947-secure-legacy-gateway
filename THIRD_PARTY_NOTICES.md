# Third-party notices

この文書は法的助言ではありません。公開・製品化時は利用形態に応じて専門家または各権利者へ確認してください。

## Zephyr Project

本アプリケーションはZephyr OSを外部依存関係として利用します。Zephyrのコードは原則Apache License 2.0ですが、サブディレクトリごとに別ライセンスのファイルが存在し得ます。

- Licensing: <https://docs.zephyrproject.org/latest/LICENSING.html>
- Project: <https://www.zephyrproject.org/>

## Mbed TLS / TF-PSA-Crypto

ZephyrのTLSおよびPSA Crypto実装としてMbed TLS / TF-PSA-Cryptoを外部依存関係として利用します。配布時は使用版に同梱されたライセンスを確認してください。Mbed TLSはApache-2.0またはGPL-2.0-or-laterのデュアルライセンスで提供されており、本プロジェクトではApache-2.0の条件で利用する想定です。

- License: <https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE>

## NXP MCUX SDK ELS/PKC and PSA Crypto Driver

ELS/PKCおよびNXP PSA Crypto Driverは本リポジトリに含まれません。利用者がNXPから取得したMCUX SDKに含まれるライセンス、および各ソースファイルのSPDX表示が適用されます。

同梱する`patches/`は、MCUX SDK 26.06の対象コンポーネントへ適用する差分のみです。差分が触れるファイルは、それぞれ元ファイルに表示されたBSD-3-ClauseまたはApache-2.0の条件に従います。パッチによってNXPソフトウェア本体の再配布権を付与するものではありません。

特にELS/PKCコンポーネントのトップレベル`LICENSE.txt`を必ず確認してください。本リポジトリでは保守的に、NXPライブラリ本体、ELS/PKCをリンクしたファームウェアバイナリ、実行ログやベンチマーク報告を公開対象から除外しています。

## `src/ca_certificate.h`

Zephyrサンプル由来で、次の表示を保持しています。

- Copyright (c) 2018 Nordic Semiconductor ASA
- SPDX-License-Identifier: Apache-2.0

## Root CA trust anchors

次のDER証明書はTLSサーバー検証用の公開ルート証明書です。証明書それ自体に本プロジェクトのApache-2.0を主張しません。更新・失効・用途制限は各CAの公式情報を確認してください。

| File | Subject/common name | SHA-256 fingerprint | Official information |
|---|---|---|---|
| `src/aaa_certificate_services.der` | AAA Certificate Services | `D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4` | <https://www.sectigo.com/uploads/resources/Sectigo-CA-Heirarchy-v4.pdf> |
| `src/globalsign_r1.der` | GlobalSign Root CA (R1) | `EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99` | <https://support.globalsign.com/ca-certificates/globalsign-root-certificates> |
| `src/globalsign_root_r3.der` | GlobalSign Root CA - R3 | `CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B` | <https://support.globalsign.com/ca-certificates/globalsign-root-certificates> |
| `src/isrg_root_x1.der` | ISRG Root X1 | `96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6` | <https://letsencrypt.org/certificates/> |

