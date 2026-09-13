# QUIC

このライブラリが対応している QUIC の仕組みです。

## バージョン

- QUIC v1 (RFC 9000)
- QUIC v2 (RFC 9369)
- Version Negotiation パケットの送信 (RFC 9000 Section 6)
  - サポート外のバージョンの Long header パケットには接続状態を作らずに返す
  - 1200 バイト未満のデータグラムには返さない (RFC 9000 Section 14.1)
- Long header のパケット種別をバージョンごとに判定する
  - 種別ビットの値は v1 と v2 で異なる (RFC 9369 Section 3.2)
  - `decode_packet_version` が返す `PacketVersion::is_initial` で判定する
- `negotiated_version` で実際に使われているバージョンを確認できる

## ハンドシェイク

- TLS 1.3 によるハンドシェイク (RFC 9001)
- ALPN によるプロトコル選択 (RFC 7301)
  - サーバーの登録順で最初に一致したものが選ばれる
  - `selected_alpn_protocol` で交渉結果を取得できる
- サーバー証明書の検証
  - `ClientConfig::verify_peer` で切り替える
  - `with_ca_cert_pem` でトラストストアに CA 証明書を追加できる
  - SNI とホスト名を検証する
- ハンドシェイクのタイムアウト
  - `ClientConfig::handshake_timeout` は接続確立全体の待ち時間
  - `Settings::handshake_timeout` は ngtcp2 側の期限
- `HandshakeCompleted` / `HandshakeConfirmed` イベント
  - `HandshakeConfirmed` はクライアントでのみ発生する
  - ngtcp2 はサーバーでは確認済みフラグを立てるだけでコールバックを呼ばない

## アドレス検証 (Retry)

- Retry によるアドレス検証 (RFC 9000 Section 8.1.2 / 8.1.3)
  - `ServerConfig::with_retry` に `RetrySecret` を渡すと有効になる
  - 既定では無効。有効にするとすべての接続に 1 RTT が加わるため
  - トークンを持たない Initial には接続状態を作らずに Retry を返す
  - トークンはクライアントのアドレス、時刻、Retry の SCID、元の DCID に束縛される
  - 検証できるまで接続状態を作らないため、偽造した送信元アドレスを使った
    増幅攻撃のコストを攻撃側に負わせられる
- Retry トークンの有効期間
  - `ServerConfig::with_retry_token_timeout` で変更できる (既定 10 秒)
- 不正なトークンを持つ Initial への応答
  - 接続状態を作らずに `INVALID_TOKEN` の CONNECTION_CLOSE を返す
- Retry の SCID の通知
  - `TransportParams::with_retry_scid` で `retry_source_connection_id` を通知する
  - クライアントは受け取った Retry の SCID と一致することを検証する
    (RFC 9000 Section 7.3)。`Server` が自動で設定する
  - クライアント側では `RemoteTransportParams::retry_scid` で確認できる
- 秘密の生成
  - `RetrySecret::generate` で乱数から生成する
  - `RetrySecret::from_bytes` を使うと複数プロセスで同じトークンを検証できる
  - `Debug` 出力には秘密を出さない

## 0-RTT (early data)

- 前回の接続で得たセッション情報を使い、ハンドシェイクの完了を待たずにデータを送る
  (RFC 9000 Section 7.4.1 / RFC 9001 Section 4.6)
- クライアント
  - `ClientConnection::take_session_ticket` でセッション情報 (`SessionTicket`) を取り出す
    - TLS 1.3 の NewSessionTicket はハンドシェイク完了後に届くため
      (RFC 8446 Section 4.6.1)、完了後にパケットを処理したあとに呼ぶ
    - 保存したバイト列から `SessionTicket::new` で復元できる
    - セッションと 0-RTT 用のトランスポートパラメータを組で保持する
      (0-RTT ではハンドシェイク完了前に送るため、前回の上限を知る必要がある。
      RFC 9001 Section 4.6.1)
  - `Client::connect_with_early_data` にセッション情報を渡すと、0-RTT を送れる
    状態 (またはハンドシェイクが完了した状態) で戻る
  - `write_stream` で積んだデータが 0-RTT パケットで送られる
  - `is_in_early_data` で 0-RTT を送っている最中かを確認できる
  - `is_early_data_accepted` と `ConnectionEvent::EarlyDataRejected` で
    サーバーが受理したかどうかを確認できる
  - セッションが 0-RTT に対応していない場合 (サーバーが受け入れない設定の場合) は
    0-RTT を送らず、ハンドシェイクの完了まで待ってから戻る
- サーバー
  - `ServerConfig::with_early_data(true)` で受け入れる (**既定は無効**)
  - 0-RTT のデータはハンドシェイクが完了する前に `ConnectionEvent::StreamData`
    として届く
  - チケットは 0-RTT で送れるデータ量を決めるトランスポートパラメータに結び付けて
    発行する。設定を変えたサーバーでは 0-RTT は受理されない
    (ハンドシェイクは通常どおり完了する)
- 0-RTT が拒否された場合
  - 0-RTT で開いたストリームと送信待ちのデータは破棄される (ngtcp2 の仕様)
  - 自動では再送されないため、アプリケーションがストリームを開き直して
    データを送り直すこと
  - 拒否の通知はクライアントにだけ届く (ngtcp2 の `tls_early_data_rejected`
    コールバックはクライアント専用)
- Retry と 0-RTT の組み合わせ
  - Retry を受け取ると、クライアントはトークンを載せた Initial を送り直し、
    送り終えていない 0-RTT のデータも送り直す (ngtcp2 の
    `conn_retransmit_retry_early`)
  - サーバーは Retry によるアドレス検証と 0-RTT の受理を同時に有効にできる

### 0-RTT のセキュリティ上の注意

- 0-RTT のデータはリプレイ攻撃に対して脆弱である
  (RFC 9000 Section 7.4.1 / RFC 9001 Section 9.2)
  - 同じデータが複数回サーバーに届きうるため、リプレイされて困る要求
    (状態を変える操作など) を 0-RTT で送ってはいけない
  - 前方秘匿性も持たない
- **サーバー側のアンチリプレイ機構はアプリケーションの責任である**
  - 本ライブラリはアンチリプレイの仕組みを提供しない
  - `ServerConfig::with_early_data(true)` は、アプリケーション側で対策できる
    場合にだけ使うこと
  - 0-RTT を受け入れるかどうかをチケット単位で判断する仕組みも提供しない

## ストリーム

- 双方向 / 単方向ストリーム (RFC 9000 Section 2)
  - `open_bidi_stream` / `open_uni_stream`
- FIN による正常な終端 (RFC 9000 Section 19.8)
  - `write_stream` に `fin = true` を渡す
- ストリームの中断
  - `reset_stream` - RESET_STREAM を送る (RFC 9000 Section 19.4)
  - `reset_stream_reliable` - RESET_STREAM_AT を送る (draft-ietf-quic-reliable-stream-reset)
  - `stop_sending` - STOP_SENDING を送る (RFC 9000 Section 19.5)
  - `close_stream` - 両方向を中断する
- 複数のストリームデータを 1 つのパケットにまとめる
  - `WRITE_STREAM_FLAG_MORE` を使う
- イベント
  - `StreamOpened` - ピアが新しいストリームを開いた
  - `StreamData` - データを受信した
  - `StreamClosed` - 送受信それぞれのエラーコード付きで閉じた (RFC 9000 Section 3.3)
  - `StreamReset` - ピアの RESET_STREAM を受信した
  - `StreamStopSending` - ピアの STOP_SENDING を受信した
  - `StreamMaxData` - ピアの MAX_STREAM_DATA を受信した

## 信頼性のあるストリームリセット

ストリームを中断すると、まだ届いていないデータは破棄される (RFC 9000 Section 19.4)。
これはアプリケーションが「ここまでのデータは要らない」と判断した場合には正しいが、
途中まで送ったデータをピアに処理させたい場合には困る。
[draft-ietf-quic-reliable-stream-reset](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/)
は、リセットの時点までに送ったデータの配信を保証する RESET_STREAM_AT を追加する。

このライブラリは ngtcp2 の `reliable-stream-reset` 分岐をビルドして使うため、
この仕組みを利用できる。

ピアが `reset_stream_at` を通知している場合に使える。

- `TransportParams::with_reset_stream_at(true)` で自分が RESET_STREAM_AT を受理することを通知する
  - ピアの値は `RemoteTransportParams::reset_stream_at` で読める
  - `supports_reset_stream_at` でピアが受理するかを確認できる
- `reset_stream_reliable` でリセットする
  - 送信済みのデータは破棄されず、リセットより前にピアへ届く
  - ピアは `StreamData` でデータを受け取ってから `StreamReset` を受け取る
- ピアが `reset_stream_at` を通知していない場合は `reset_stream` と同じ挙動になる
  - RESET_STREAM が送られ、未送信のデータは破棄される
  - エラーにはならないため、保証が要る場合は `supports_reset_stream_at` を先に確認する
- `write_stream` で送信待ちに積んだまま送っていないデータは保証の対象外
  - `reset_stream` と同様に破棄される。保証の対象に含める場合は先に `flush` する

## フロー制御と輻輳制御

- ストリーム単位のフロー制御 (RFC 9000 Section 4.1)
  - `extend_max_stream_offset` でクレジットを戻す
  - 戻さない限りピアは次のデータを送れない
  - `max_stream_data_left` で送信できる残りを確認する
- 接続全体のフロー制御
  - `max_data_left` で残りを確認する
- ストリーム数の上限 (RFC 9000 Section 4.2)
  - `extend_max_streams_bidi` / `extend_max_streams_uni` で MAX_STREAMS を送る
  - ngtcp2 は上限を自動では増やさないため、ピアのストリームを処理し終えたら呼ぶ
  - `streams_bidi_left` / `streams_uni_left` で残りを確認する
  - `MaxStreamsBidi` / `MaxStreamsUni` イベント
- 輻輳制御アルゴリズム (RFC 9002)
  - Reno / CUBIC / BBRv2
  - `Settings::congestion_algorithm` で指定する
  - `cwnd_left` で輻輳ウィンドウの残りを確認する
- 喪失検出と再送 (RFC 9002)
  - Sans I/O 層は `get_expiry` / `handle_expiry` で期限を通知する
- キー更新 (RFC 9001 Section 4.6.3)
  - `initiate_key_update` で開始する
  - ピアは自動的に追従するため再接続は不要

## 接続マイグレーション (RFC 9000 Section 9)

- クライアントからのマイグレーション
  - `ClientConnection::migrate` に新しいローカルアドレスを渡す
  - このクライアントはソケットを 1 つしか持たないため、即座に新しい経路へ移る
    (経路の検証自体は ngtcp2 が行う)
  - `PathValidated` イベントで検証の結果が届く
  - ピアが `disable_active_migration` を通知している場合は失敗する (RFC 9000 Section 18.2)
- サーバー側の受け入れ
  - 送信元アドレスが変わったパケットも破棄せず、ngtcp2 が経路の変更を検出して
    経路を検証する (PATH_CHALLENGE / PATH_RESPONSE。RFC 9000 Section 9.3)
  - 検証に成功するとその経路が使われ、`AcceptedConnection::remote_addr` が変わる
  - 検証が終わるまでデータは古い経路に送られ続けるため、送信先は
    パケットごとに決まる ([Sans I/O 層を直接使う](usage.md#sans-io-層を直接使う) の `write_pkt` の戻り値)
- NAT リバインディングでも同じ経路で扱う
- RETIRE_CONNECTION_ID でピアが使用を終了した CID はルーティングテーブルから
  取り除く (RFC 9000 Section 5.1.2)
  - sans-IO 層では `poll_retired_cids` で取り出せる

## ECN (RFC 9000 Section 13.4)

- 受信したデータグラムの ECN コードポイントを ngtcp2 に渡す
  - ソケットで `IP_RECVTOS` / `IPV6_RECVTCLASS` を有効にし、`recvmsg` の補助データから取り出す
  - ngtcp2 はこれを使って ECN を検証し (RFC 9000 Section 13.4.2)、ACK_ECN を送る
- ngtcp2 が要求した ECN を送信パケットに付ける
  - `sendmsg` の補助データで `IP_TOS` / `IPV6_TCLASS` を設定する
- ECN を通知しない経路では Not-ECT のままになる (検証に失敗すると ngtcp2 が ECN を止める)

## データグラム (RFC 9221)

- `send_datagram` による送信と `Datagram` イベントによる受信
- `DatagramConfig` で送受信の上限を設定する
  - ピアに通知する値は `TransportParams::with_datagram`
- `can_send_datagram` でピアが受信できるか確認する
- 信頼性のない配信であり、順序も再送も保証されない

## コネクション ID

- 複数 CID の発行 (RFC 9000 Section 5.1.1)
  - ピアの `active_connection_id_limit` に応じて ngtcp2 が NEW_CONNECTION_ID で発行する
  - サーバーは発行済み CID をルーティングテーブルに登録し、ピアが DCID として使うパケットを接続に振り分ける
- Short header の DCID 照合
  - Short header は DCID 長を運ばないため (RFC 9000 Section 17.3)、発行した CID の長さの集合で照合する
- 接続の受け渡し済み CID には Stateless Reset を返さない
  - 接続は同じプロセス内で生きているため

## 接続の終了

- CONNECTION_CLOSE (RFC 9000 Section 10.2)
  - `close` は 1 パケット送るだけでピアの応答を待たない
  - draining 期間の維持は行わない
- アイドルタイムアウト (RFC 9000 Section 10.1)
- closing / draining 期間の判定
  - `ConnectionEvent::ConnectionClosed` イベントと `is_closed`
- Stateless Reset (RFC 9000 Section 10.3)
  - 送信: 未知の DCID を持つ Short header パケットに返す
  - 受信: `StatelessResetReceived` イベント
  - トークンは秘密から決定論的に導出するため、接続状態を失ってもピアが保持するトークンを再現できる
  - 送信はトークンバケット方式でレート制限される (RFC 9000 Section 10.3.3)

## セキュリティ

- 未認証の Initial で接続状態を消費させない
  - 同時接続数の上限は 1024
  - 1200 バイト未満のデータグラムで届いた Initial を破棄する (RFC 9000 Section 14.1)
  - DCID が 8 バイト未満の Initial を破棄する (RFC 9000 Section 7.2)
  - Initial 以外の Long header を新規接続として扱わない
  - Retry を有効にすると、トークンを検証できるまで接続状態を作らない
    (RFC 9000 Section 8.1.2)
- Stateless Reset のトークンと秘密を `Debug` 出力に表示しない
- セッション情報 (`SessionTicket`) の内容を `Debug` 出力に表示しない
  - 接続の再開に使えるため
- 0-RTT (early data) は既定で無効にし、有効にする場合の注意をドキュメントに明記する
  - リプレイ攻撃に対して脆弱であり (RFC 9001 Section 9.2)、アンチリプレイ機構は
    アプリケーションの責任である
- 増幅攻撃に使える応答を返さない
  - Stateless Reset は引き金になったパケットより長くしない (RFC 9000 Section 10.3.3)
  - Version Negotiation は 1200 バイト以上のパケットにだけ返すため、応答は必ず短くなる

## 設定

`TransportParams` はピアに通知する値 (RFC 9000 Section 18)、`Settings` は ngtcp2 の実装固有の設定です。

`TransportParams`:

- `with_max_idle_timeout`
- `with_initial_max_data`
- `with_initial_max_stream_data_bidi_local` / `bidi_remote` / `uni`
- `with_max_streams_bidi` / `with_max_streams_uni`
- `with_active_connection_id_limit`
- `with_max_ack_delay` / `with_ack_delay_exponent`
- `with_max_udp_payload_size`
- `with_disable_active_migration`
- `with_grease_quic_bit` (RFC 9287)
- `with_datagram` (RFC 9221)
- `with_stateless_reset_token` (サーバー用)
- `with_original_dcid` (サーバー用)
- `with_retry_scid` (サーバー用。Retry を送った場合のみ)
- `with_preferred_address` (サーバー用。RFC 9000 Section 18.2)
- `with_reset_stream_at` (draft-ietf-quic-reliable-stream-reset)

`RemoteTransportParams` はこれと同じ値を読み取れます (`retry_scid` と `reset_stream_at` を含みます)。

`Settings`:

- `congestion_algorithm` - Reno / CUBIC / BBRv2
- `initial_rtt` - 初期 RTT の推定値 (RFC 9002 Section 6.2.2)
- `handshake_timeout`
- `max_tx_udp_payload_size` - 送信する UDP ペイロードの上限
- `max_window` / `max_stream_window` - 輻輳ウィンドウの上限
- `ack_threshold` - 遅延 ACK までの未 ACK パケット数
- `no_tx_udp_payload_size_shaping`
- `no_pmtud`
- `keep_alive_timeout`
- `address_validation_token` (サーバー用。Retry で受け取ったトークン)
- `stateless_reset_secret`

ピアが通知した値は `remote_transport_params` が返す `RemoteTransportParams` で読めます。ハンドシェイクが完了するまでは `None` です。

RFC 9000 Section 18.2 の `initial_max_stream_data_bidi_local` /
`initial_max_stream_data_bidi_remote` の local / remote は、パラメータを送った側から
見た向きを指します。そのためピアのパラメータでは
`initial_max_stream_data_bidi_remote` が、ローカルが開いた双方向ストリームに
適用される上限になります。

## 統計と診断

- `stats` が返す `ConnStats`
  - `latest_rtt` / `min_rtt` / `smoothed_rtt` / `rttvar`
  - `cwnd` / `ssthresh` / `bytes_in_flight`
  - `packets_sent` / `bytes_sent` / `packets_received` / `bytes_received`
  - `packets_lost` / `bytes_lost` / `packets_discarded` / `pings_received`
- 互換バージョン交渉 (RFC 9368)
  - `ClientConfig::with_preferred_versions` / `ServerConfig::with_preferred_versions`
    で提示するバージョンを指定すると、Version Negotiation パケットをやり取り
    せずにサーバーがバージョンを選ぶ
  - Version Negotiation パケットを受け取ったクライアントがバージョンを
    切り替えることは行わない (非互換のバージョンへの切り替えは未対応)
- qlog
  - `ClientConfig::with_qlog_dir` / `ServerConfig::with_qlog_dir` で出力先の
    ディレクトリを指定すると、接続ごとに `<SCID>.sqlog` を作って書き出す
    (JSON Text Sequence、RFC 7464)
  - ファイルを開けない場合は qlog を無効にして接続は続ける
- NEW_TOKEN (RFC 9000 Section 8.1.4)
  - サーバー: `ServerConfig::with_new_token(true)` で、アドレスを検証できた接続に
    トークンを配布する。トークンの生成と検証には `ServerConfig::with_retry` の
    秘密を使うため、Retry を有効にしていない場合は配布しない
  - クライアント: `ClientConnection::take_new_token` でトークンを取り出し、
    次の接続の `ClientConfig::settings.address_validation_token` に設定する
  - トークンを提示した接続では、サーバーは Retry を送らずに接続を受け入れる
  - トークンは配布した IP アドレスに束縛される (ngtcp2 の実装。ポートは含まない)
- preferred_address (RFC 9000 Section 9.6)
  - サーバー: `ServerConfig::with_preferred_address` で 2 つ目のソケットを
    bind し、ハンドシェイクで優先アドレスを通知する。優先アドレス用の
    コネクション ID と Stateless Reset トークンは接続ごとに生成する
  - サーバーは優先アドレスへ届いたパケットも接続へ振り分け、そのアドレスから
    応答する (RFC 9000 Section 9.6.1)
  - クライアント: 通知された優先アドレスへ自分から移る。経路の検証に成功すると
    `ConnectionEvent::PathValidated` が届き、以後は優先アドレスを使う
  - 経路の変更を検出できるよう、クライアントは送信元アドレスでパケットを
    絞らない。受理の可否は ngtcp2 が復号と経路の検証で決める
    (RFC 9000 Section 9.3)
- 長さ 0 のコネクション ID (RFC 9000 Section 5.1)
  - `ServerConfig::with_scid_len(0)` を指定すると、サーバーは
    コネクション ID を発行しない。パケットにコネクション ID が載らないため、
    サーバーはピアのアドレスでパケットを接続へ振り分ける
  - Retry の SCID も長さ 0 になる。クライアントは 2 通目の Initial に
    コネクション ID を載せないが、サーバーはアドレスで接続を識別する
  - 次の機能は使えない。マイグレーション (アドレスが変わると接続を識別
    できない)、優先アドレス (通知する CID が無い)、Stateless Reset
    (トークンを配布する CID が無い)
- keep-alive による PING の送信
  - `Settings::keep_alive_timeout` または `Connection::set_keep_alive_timeout`
- `ngtcp2_version` でリンクされた ngtcp2 のバージョンを取得できる

## 対応しない機能

- HTTP/3
  - ngtcp2 は QUIC のトランスポート層だけを提供する。HTTP/3 には nghttp3 の
    バインディングを新たに作る必要があるため対象外とする
- Windows
  - パス情報の変換 (`libc::sockaddr_storage`) と ECN の送受信 (`cmsg`) に
    POSIX のソケット API を使っており、Windows で検証できる環境も無いため
    対象外とする

## 規格書

このライブラリが準拠している RFC 一覧です。

- RFC 7301 - Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
  - <https://datatracker.ietf.org/doc/html/rfc7301>
- RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
  - <https://datatracker.ietf.org/doc/html/rfc9000>
- RFC 9001 - Using TLS to Secure QUIC
  - <https://datatracker.ietf.org/doc/html/rfc9001>
- RFC 9002 - QUIC Loss Detection and Congestion Control
  - <https://datatracker.ietf.org/doc/html/rfc9002>
- RFC 9221 - An Unreliable Datagram Extension to QUIC
  - <https://datatracker.ietf.org/doc/html/rfc9221>
- RFC 9287 - Greasing the QUIC Bit
  - <https://datatracker.ietf.org/doc/html/rfc9287>
- RFC 9368 - Compatible Version Negotiation for QUIC
  - <https://datatracker.ietf.org/doc/html/rfc9368>
- RFC 9369 - QUIC Version 2
  - <https://datatracker.ietf.org/doc/html/rfc9369>

## ドラフト

いずれも実装は ngtcp2 が提供するもので、仕様が変更される可能性があります。

- draft-ietf-quic-reliable-stream-reset - Reliable QUIC Stream Resets
  - <https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/>
  - [信頼性のあるストリームリセット](#信頼性のあるストリームリセット) を参照
