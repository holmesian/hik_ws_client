<?php

declare(strict_types=1);

namespace HikWs;

/**
 * 海康威视取流客户端：连上代理、鉴权、取流，把设备下发的传输字节还原成可直接喂解码器的
 * Annex-B 访问单元。
 *
 * 传输层（WebSocket、鉴权、封包、重连）与媒体解析层（RTP、PS、SPS、SDP）分离（ADR-0001）：
 * 本类负责接线，解析逻辑在 PsDemuxer / RtpDetector / SpsParser / Media / SdpParser 里，
 * 它们不依赖网络、可对字节直接单测。
 *
 * 移植自 go-client/client.go（行为基准）与 python-client/hik_ws_client.py。
 * 依赖：标准库 + ext-openssl + ext-gmp（RSA）。媒体层仅标准库。
 */
class HikMediaClient
{
    /** 服务端上报的错误：终态，重连同一个 URL 只会拿到同样的码（见 docs/protocol.md）。 */
    public const ERROR_MESSAGES = [
        0 => '成功',
        28316423 => 'URL已过期，请获取新的有效URL',
        26214462 => '服务端取流失败',
        26214475 => '服务端取流失败',
        26214476 => '服务端取流失败',
        65559 => '认证失败，请检查密码或权限',
        16777237 => 'RSA加密失败，请检查密钥生成逻辑',
    ];

    private WebSocket $ws;
    private string $serverPkd = '';
    private string $serverRand = '';
    private string $serverCipherSuite = '0';
    private string $serverVersion = '1.0';

    // ---- 媒体解析层状态（与 go-client 一一对应）----
    private RtpDetector $rtp;
    private ?PsDemuxer $ps = null;
    private ?MediaInfo $mediaInfo = null;
    private bool $containerKnown = false;
    private int $frameCount = 0;
    private ?float $streamStart = null;

    // ---- 回调 ----
    /** @var callable(string):void 已解复用的 Annex-B 访问单元（向后兼容） */
    public $onVideoData = null;
    /** @var callable(FrameMeta, string):void 逐帧元数据 + 负载 */
    public $onVideoFrame = null;
    /** @var callable(string):void 解复用前的原始容器负载（诊断用） */
    public $onRawVideo = null;
    /** @var callable(string):void 音频负载原样下发 */
    public $onAudioData = null;
    /** @var callable(MediaInfo):void SDP 级流描述 */
    public $onMediaInfo = null;
    /** @var callable(string):void 码流内首个 SPS NAL（含起始码），归档用 */
    public $onSps = null;
    /** @var callable(\Throwable):void 传输/会话错误 */
    public $onError = null;

    public function __construct(
        public readonly HikConfig $config,
        private readonly bool $useRealplayAuth = false,
    ) {
        $this->rtp = new RtpDetector();
        $this->ws = new WebSocket($config->proxyHost, $config->proxyPort, $this->buildMediaUrl(), 'v1.0.0', 10.0, true);
    }

    private function buildMediaUrl(): string
    {
        $proxy = "{$this->config->deviceIp}:{$this->config->devicePort}";
        return "/media?version={$this->config->version}&cipherSuites={$this->config->cipherSuites}"
            . "&sessionID=&proxy={$proxy}";
    }

    private function log(string $msg): void
    {
        if ($this->config->verbose) {
            fwrite(STDERR, "[hik-ws] {$msg}\n");
        }
    }

    private function resetMediaState(): void
    {
        // runForever 在同一个对象上重连：上一会话的 RTP 判定、PS 半帧和 SDP 都不能带进新会话。
        $this->rtp = new RtpDetector();
        $this->ps = null;
        $this->mediaInfo = null;
        $this->containerKnown = false;
        $this->frameCount = 0;
        $this->streamStart = null;
    }

    public function connect(): void
    {
        $this->ws->connect();
    }

    public function close(): void
    {
        $this->ws->close();
    }

    /** 接收服务器下发的 PKD/rand（无需主动发认证请求）。 */
    public function authenticate(): bool
    {
        try {
            [$msgType, $payload] = $this->ws->readMessage($this->readDeadline());
        } catch (\Throwable $e) {
            $this->emitError($e);
            return false;
        }
        if ($msgType !== WebSocket::OP_TEXT) {
            $this->log(sprintf('unexpected message type for auth: 0x%02x', $msgType));
            return false;
        }
        $resp = json_decode($payload, true);
        if (!is_array($resp)) {
            return false;
        }
        if (!empty($resp['errorCode'])) {
            $this->emitError(new \RuntimeException("server error {$resp['errorCode']}: " . ($resp['errorMsg'] ?? '')));
            return false;
        }
        $this->serverPkd = (string) ($resp['PKD'] ?? '');
        $this->serverRand = (string) ($resp['rand'] ?? '');
        $this->serverCipherSuite = (string) ($resp['cipherSuite'] ?? $resp['cipherSuites'] ?? '0');
        $this->serverVersion = (string) ($resp['version'] ?? '1.0');
        $this->log("received PKD/rand, cipherSuite={$this->serverCipherSuite}, version={$this->serverVersion}");
        return true;
    }

    /** 发送 realplay 请求，启动取流。 */
    public function realplay(): bool
    {
        $deviceUrl = "ws://{$this->config->deviceIp}:{$this->config->devicePort}/openUrl/{$this->config->password}";
        $req = [
            'sequence' => 0,
            'cmd' => 'realplay',
            'url' => $deviceUrl,
            'key' => '',
            'authorization' => '',
            'token' => '',
        ];
        // 默认空 key 请求，服务端据此不下发加密流（ADR-0004）。
        // 代理要求严格鉴权时，开启 useRealplayAuth 用 Crypto 填实三个字段。
        if ($this->useRealplayAuth && $this->serverPkd !== '') {
            [$iv, $key] = Crypto::generateClientIvKey();
            $req['key'] = Crypto::generateRealplayKey($iv, $key, $this->serverPkd);
            $req['authorization'] = Crypto::generateAuthorization($this->serverRand, $this->config->password, $key, $iv);
            $req['token'] = Crypto::generateToken($deviceUrl, $key, $iv);
        }
        try {
            $this->ws->writeMessage(WebSocket::OP_TEXT, json_encode($req, JSON_UNESCAPED_SLASHES));
        } catch (\Throwable $e) {
            $this->emitError($e);
            return false;
        }
        $this->log('realplay request sent');
        return true;
    }

    /**
     * 处理一条视频负载。RTP 判定器会扣住开头几条直到能定性，一次喂入可能放出 0/1/多条。
     */
    public function feedVideo(string $data): void
    {
        foreach ($this->rtp->feed($data) as $payload) {
            $this->feedContainer($payload);
        }
    }

    /** 处理一条已去封装的负载。MPEG-PS 先解复用，其余容器原样下发。 */
    public function feedContainer(string $data): void
    {
        $this->safeCallback($this->onRawVideo, $data);

        // 容器只在会话第一条负载上判一次（ADR-0002）：MEDIAINFO 头只是提示，HVAG 系设备的
        // 头解不出来、container 为空但负载明明是 MPEG-PS，只能靠嗅探定性；且只能在第一条
        // 上嗅，后续消息都是从 pack 中段续传的。
        if (!$this->containerKnown) {
            $this->containerKnown = true;
            $info = $this->mediaInfo;
            if (($info !== null && $info->container === 'PS')
                || (($info === null || $info->container === '') && PsDemuxer::isPsData($data))) {
                $this->ps = new PsDemuxer();
                // 嗅探结论写回 MediaInfo：对 HVAG 那类设备这是容器的唯一来源，隐含的 90kHz
                // PS 时钟又是 PTS 能换算成帧率的前提。
                if ($info !== null && $info->container === '') {
                    $info->container = 'PS';
                    $info->clockRate = 90000;
                }
            }
        }

        if ($this->ps === null) {
            $this->deliverFrame($data, 0, false);
            return;
        }
        foreach ($this->ps->feed($data) as $frame) {
            $this->deliverFrame($frame->data, $frame->pts, $frame->hasPts);
        }
    }

    /** 补齐单帧元信息后交给调用方。onVideoFrame 优先于 onVideoData，避免重复下发。 */
    private function deliverFrame(string $data, int $pts, bool $hasPts): void
    {
        if ($this->onVideoFrame === null && $this->onVideoData === null) {
            return;
        }
        $this->streamStart ??= microtime(true);
        $this->frameCount++;

        $info = $this->mediaInfo;
        $codec = $info->codec ?? '';
        // 同理：解不出的 MEDIAINFO 头会让编码为空，没编码就判不了关键帧、也还原不了分辨率。
        if ($codec === '') {
            $codec = Media::sniffCodec($data);
            if ($codec !== '' && $info !== null) {
                $info->codec = $codec;
            }
        }
        // 分辨率只能从码流内 SPS 还原（MEDIAINFO 头不带），PS 流在第一个关键帧上补齐。
        if ($codec !== '' && ($info === null || $info->width === 0)) {
            [$w, $h, $sps, $ok] = SpsParser::recoverResolution($data, $codec);
            if ($ok) {
                if ($info !== null) {
                    $info->width = $w;
                    $info->height = $h;
                }
                if ($sps !== null) {
                    $this->safeCallback($this->onSps, $sps);
                }
            }
        }

        $elapsed = microtime(true) - $this->streamStart;
        $meta = new FrameMeta();
        $meta->frameIndex = $this->frameCount;
        $meta->isKeyFrame = Media::analyzeFrame($data, $codec);
        $meta->codec = $codec;
        $meta->timestampMs = (int) ($elapsed * 1000);
        if ($hasPts) {
            $meta->pts = $pts;
            $meta->hasPts = true;
        } elseif ($info !== null && $info->clockRate > 0) {
            $meta->pts = (int) ($elapsed * $info->clockRate);
        }
        if ($info !== null) {
            $meta->width = $info->width;
            $meta->height = $info->height;
        }
        if ($this->config->verbose) {
            $this->log("video frame #{$meta->frameIndex}: " . strlen($data)
                . ' bytes (key=' . var_export($meta->isKeyFrame, true) . ", codec={$codec})");
        }

        if ($this->onVideoFrame !== null) {
            $this->safeCallback($this->onVideoFrame, $meta, $data);
            return;
        }
        $this->safeCallback($this->onVideoData, $data);
    }

    /**
     * 流结束时把还压在手里的东西放出去：先 RTP 判定器扣住的负载，再解复用器的最后一个
     * 访问单元。顺序不能反——扣住的负载得先进解复用器。
     */
    public function flushMedia(): void
    {
        foreach ($this->rtp->flush() as $payload) {
            $this->feedContainer($payload);
        }
        if ($this->ps === null) {
            return;
        }
        foreach ($this->ps->flush() as $frame) {
            $this->deliverFrame($frame->data, $frame->pts, $frame->hasPts);
        }
    }

    /**
     * 主循环：消费消息直到连接关闭或出错。
     *
     * 与 go-client 的 Run / python 的 run 同语义：每帧循环解包，本帧内所有协议消息都要
     * 交付；解不出来则把剩余整段当原始视频。
     */
    public function run(): void
    {
        $this->resetMediaState();
        $bin = WebSocket::OP_BINARY;
        $text = WebSocket::OP_TEXT;
        try {
            while (true) {
                [$msgType, $payload] = $this->ws->readMessage($this->readDeadline());

                if ($msgType === $bin) {
                    foreach (Protocol::iterMessages($payload) as [$type, $body]) {
                        if ($type === Protocol::MSG_TYPE_VIDEO_DATA) {
                            $this->feedVideo($body);
                        } elseif ($type === Protocol::MSG_TYPE_AUDIO_DATA) {
                            $this->safeCallback($this->onAudioData, $body);
                        } elseif ($type === null) {
                            // 无协议信封的裸载荷：当原始视频处理。
                            $this->feedVideo($body);
                        }
                        // 其它已知类型与未知类型一并忽略（与 Python 一致）。
                    }
                } elseif ($msgType === $text) {
                    $this->handleTextMessage($payload);
                }
            }
        } catch (ServerError $e) {
            $this->emitError($e);
            throw $e;
        } catch (\Throwable $e) {
            $this->emitError($e);
        } finally {
            $this->flushMedia();
        }
    }

    /** 服务端 TEXT JSON 响应：realplay 成功即附 SDP；错误则终态抛出 ServerError。 */
    private function handleTextMessage(string $payload): void
    {
        $resp = json_decode($payload, true);
        if (!is_array($resp)) {
            $this->log('malformed TEXT message ignored: ' . substr($payload, 0, 100));
            return;
        }
        $code = (int) ($resp['errorCode'] ?? 0);
        if ($code !== 0) {
            $msg = (string) ($resp['errorMsg'] ?? (self::ERROR_MESSAGES[$code] ?? ''));
            throw new ServerError($code, $msg);
        }
        // realplay 成功：附带的 SDP 给出容器与编码（只是提示，见 ADR-0002）。
        $sdp = $resp['sdp'] ?? $resp['SDP'] ?? null;
        if (is_string($sdp) && $sdp !== '') {
            $this->mediaInfo = SdpParser::parse($sdp);
            $this->safeCallback($this->onMediaInfo, $this->mediaInfo);
        }
    }

    /**
     * 拥有整个会话生命周期：连接、鉴权、realplay、接收；传输失败后按 maxReconnects 重建。
     * ServerError 为终态，立即停止重连——盲目重试只会烧掉本就很短的 token 时间窗。
     */
    public function stream(): void
    {
        $wait = $this->config->reconnectWait > 0 ? $this->config->reconnectWait : 2.0;
        for ($attempt = 0; ; $attempt++) {
            try {
                $this->session();
                return;
            } catch (ServerError $e) {
                throw $e;
            } catch (\Throwable $e) {
                if ($attempt >= $this->config->maxReconnects) {
                    throw $e;
                }
                $backoff = ($attempt + 1) * $wait;
                $this->log("session failed ({$e->getMessage()}), reconnecting in {$backoff}s");
                usleep((int) ($backoff * 1e6));
            }
        }
    }

    private function session(): void
    {
        $this->close();
        $this->resetMediaState();
        $this->connect();
        if (!$this->authenticate()) {
            throw new \RuntimeException('authentication failed');
        }
        if (!$this->realplay()) {
            throw new \RuntimeException('realplay failed');
        }
        $this->run();
    }

    private function readDeadline(): ?float
    {
        $t = $this->config->stallTimeout;
        return $t > 0 ? microtime(true) + $t : null;
    }

    private function emitError(\Throwable $e): void
    {
        $this->safeCallback($this->onError, $e);
    }

    private function safeCallback(?callable $cb, mixed ...$args): void
    {
        if ($cb === null) {
            return;
        }
        try {
            $cb(...$args);
        } catch (\Throwable $e) {
            $this->log('callback error: ' . $e->getMessage());
        }
    }

    // ---- 测试与内部接线用（对齐 python 的 _* 命名）----

    public function mediaInfo(): ?MediaInfo
    {
        return $this->mediaInfo;
    }

    public function setMediaInfo(MediaInfo $info): void
    {
        $this->mediaInfo = $info;
    }

    public function frameCount(): int
    {
        return $this->frameCount;
    }
}
