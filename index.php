<?php
ini_set('memory_limit', '256M'); // Enough — we now stream/process efficiently
set_time_limit(0);
error_reporting(E_ALL);
ini_set('display_errors', 1);

/* ================== Configuration (edit if needed) ================== */
const PORTAL = "http://portal.airtel4k.co:80/stalker_portal/";
const MAC    = "00:1A:79:00:2D:6A";
const SESSION_FILE      = __DIR__ . '/session.json';
const CHANNELS_FILE     = __DIR__ . '/raw_channels.json';
const PROFILE_FILE      = __DIR__ . '/profile_response.json';
const CREATED_LINK_FILE = __DIR__ . '/created_link.json';
const PLAYLIST_FILE     = __DIR__ . '/playlist.m3u';
const PLAYLIST_META     = __DIR__ . '/playlist.meta.json';
const HITS_FILE         = __DIR__ . '/playlist_hits.json';
/* ================================================================== */

/* ========================= Utilities ========================= */
function md5Upper(string $text): string   { return strtoupper(md5($text)); }
function sha256Upper(string $text): string { return strtoupper(hash('sha256', $text)); }

function encodeUpper(string $s): string {
    return preg_replace_callback(
        '/%[0-9a-f]{2}/i',
        function($m) { return strtoupper($m[0]); },
        rawurlencode($s)
    );
}

function save_json(string $path, $data): bool {
    $json = @json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($json === false) $json = @json_encode($data);
    if ($json === false) $json = '{}';
    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, $json) === false) return false;
    return (bool)@rename($tmp, $path);
}

function load_json(string $path) {
    if (!file_exists($path)) return null;
    $txt = @file_get_contents($path);
    if ($txt === false || trim($txt) === '') return null;
    $decoded = @json_decode($txt, true);
    return (json_last_error() === JSON_ERROR_NONE) ? $decoded : null;
}

function generateDeviceInfo(string $mac): array {
    $upper     = strtoupper($mac);
    $sn        = md5Upper($upper);
    $sncut     = substr($sn, 0, 13);
    $deviceId  = sha256Upper($upper);
    $signature = sha256Upper($sncut . $upper);
    return [
        'mac'       => $upper,
        'sn'        => $sn,
        'sncut'     => $sncut,
        'deviceId'  => $deviceId,
        'signature' => $signature,
    ];
}

function buildHeaders(string $portal, string $cookie = '', string $token = ''): array {
    // Always build correct /c/ referer regardless of whether portal ends with /c/ or not
    $portalBase = rtrim($portal, '/');
    if (substr($portalBase, -2) === '/c') {
        $referer = $portalBase . '/';
    } elseif (strpos($portalBase, '/c') === false) {
        $referer = $portalBase . '/c/';
    } else {
        $referer = $portalBase . '/c/';
    }
    $h = [
        'User-Agent: Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
        'X-User-Agent: Model: MAG250; Link: WiFi',
        'Referer: ' . $referer,
        'Accept: */*',
        'Connection: Keep-Alive',
        'Accept-Encoding: gzip',
    ];
    if ($cookie !== '') $h[] = 'Cookie: '               . $cookie;
    if ($token  !== '') $h[] = 'Authorization: Bearer ' . $token;
    return $h;
}

function curl_get_raw(string $url, array $headers = [], int $timeout = 20): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_ENCODING       => '',
    ]);
    if (!empty($headers)) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $raw = curl_exec($ch);
    if ($raw === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new Exception('cURL error: ' . $err);
    }

    $headerSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $httpCode   = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $headerRaw = substr($raw, 0, $headerSize);
    $body      = substr($raw, $headerSize);

    $headersOut = [];
    $cookies    = [];
    foreach (preg_split("/\r\n|\n|\r/", $headerRaw) as $line) {
        $colonPos = strpos($line, ':');
        if ($colonPos === false) continue;
        $k = trim(substr($line, 0, $colonPos));
        $v = trim(substr($line, $colonPos + 1));
        if (strtolower($k) === 'set-cookie') {
            $pair = explode(';', $v, 2)[0];
            if (strpos($pair, '=') !== false) {
                [$cn, $cv]          = explode('=', $pair, 2);
                $cookies[trim($cn)] = trim($cv);
            }
        } else {
            $headersOut[$k] = $headersOut[$k] ?? $v;
        }
    }

    return [
        'status'     => $httpCode,
        'header'     => $headersOut,
        'body'       => $body,
        'cookies'    => $cookies,
        'raw_header' => $headerRaw,
    ];
}

function fetchWithRetry(string $url, array $headers, int $retries = 2, int $timeout = 15): array {
    $lastExc = null;
    for ($i = 0; $i <= $retries; $i++) {
        try {
            return curl_get_raw($url, $headers, $timeout);
        } catch (Exception $e) {
            $lastExc = $e;
            if ($i < $retries) usleep(500000);
        }
    }
    throw $lastExc;
}

/* ====================== Handshake & Session ====================== */
function performHandshake(string $portal, string $mac): array {
    error_log('🔹 Handshake...');

    $baseCookie   = "mac={$mac}; stb_lang=en; timezone=GMT";
    $handshakeURL = rtrim($portal, '/') . '/server/load.php?type=stb&action=handshake'
        . '&prehash=' . strtoupper(rawurlencode($mac)) . '&token=&JsHttpRequest=1-xml';

    $resp  = curl_get_raw($handshakeURL, buildHeaders($portal, $baseCookie), 20);
    $json  = @json_decode($resp['body'], true);
    $token = '';
    if (is_array($json)) {
        $token = $json['js']['token'] ?? $json['token'] ?? '';
    }
    if (!$token) throw new Exception('No token received from handshake. Body: ' . substr($resp['body'], 0, 300));

    $cookieMap = ['mac' => $mac, 'stb_lang' => 'en', 'timezone' => 'GMT'];
    foreach ($resp['cookies'] as $k => $v) {
        $cookieMap[$k] = $v;
    }
    $cookieStr = implode('; ', array_map(
        function($k, $v) { return "{$k}={$v}"; },
        array_keys($cookieMap),
        array_values($cookieMap)
    ));

    $session = [
        'portal'     => rtrim($portal, '/') . '/c/',
        'mac'        => $mac,
        'token'      => $token,
        'cookie'     => $cookieStr,
        'headers'    => buildHeaders($portal, $cookieStr, $token),
        'fetched_at' => time(),
    ];
    save_json(SESSION_FILE, $session);
    error_log('✅ Handshake Token: ' . $token);
    return $session;
}

function validateSession(array $session, string $portal): bool {
    $device  = generateDeviceInfo($session['mac']);
    $ts      = time();
    $metrics = encodeUpper(json_encode([
        'mac'    => $device['mac'],
        'sn'     => $device['sn'],
        'model'  => 'MAG250',
        'type'   => 'STB',
        'random' => bin2hex(random_bytes(8)),
    ]));
    $profileURL = rtrim($portal, '/') . '/server/load.php?type=stb&action=get_profile&hd=1'
        . '&sn='         . urlencode($device['sncut'])
        . '&stb_type=MAG250'
        . '&device_id='  . urlencode($device['deviceId'])
        . '&device_id2=' . urlencode($device['deviceId'])
        . '&signature='  . urlencode($device['signature'])
        . '&timestamp='  . $ts
        . '&metrics='    . $metrics
        . '&JsHttpRequest=1-xml';
    try {
        $resp = curl_get_raw($profileURL, $session['headers'] ?? [], 18);
        $json = @json_decode($resp['body'], true);
        if (!is_array($json)) return false;
        $js = $json['js'] ?? null;
        if (is_array($js)) return !empty($js['id']) || !empty($js['phone']);
        return !empty($json['id']) || !empty($json['phone']);
    } catch (Exception $e) {
        return false;
    }
}

function ensure_session(string $portal = PORTAL, string $mac = MAC, bool $force_refresh = false): array {
    $session = load_json(SESSION_FILE);
    $now     = time();

    $needHandshake = !is_array($session)
        || $force_refresh
        || empty($session['token'])
        || ($now - (int)($session['fetched_at'] ?? 0)) > 86400;

    if ($needHandshake) {
        error_log('⚠️ No recent session — doing handshake');
        $session = performHandshake($portal, $mac);
        try { fetchProfile($session, $portal); } catch (Exception $e) {
            error_log('⚠️ fetchProfile after handshake failed: ' . $e->getMessage());
        }
    } else {
        if (!validateSession($session, $portal)) {
            error_log('🔁 Session invalid — re-handshake');
            $session = performHandshake($portal, $mac);
            try { fetchProfile($session, $portal); } catch (Exception $e) {
                error_log('⚠️ fetchProfile after re-handshake failed: ' . $e->getMessage());
            }
        } else {
            $profileAge = $now - (int)(@filemtime(PROFILE_FILE) ?: 0);
            if ($profileAge > 1800) {
                try { fetchProfile($session, $portal); } catch (Exception $e) {
                    error_log('⚠️ fetchProfile refresh failed: ' . $e->getMessage());
                }
            }
        }
    }
    return $session;
}

/* ====================== Profile ====================== */
function fetchProfile(array $session, string $portal): void {
    error_log('🔹 Fetching profile...');
    $device  = generateDeviceInfo($session['mac']);
    $ts      = time();
    $metrics = encodeUpper(json_encode([
        'mac'    => $device['mac'],
        'sn'     => $device['sn'],
        'model'  => 'MAG250',
        'type'   => 'STB',
        'random' => bin2hex(random_bytes(8)),
    ]));
    $profileURL = rtrim($portal, '/') . '/server/load.php?type=stb&action=get_profile&hd=1'
        . '&sn='         . urlencode($device['sncut'])
        . '&stb_type=MAG250'
        . '&device_id='  . urlencode($device['deviceId'])
        . '&device_id2=' . urlencode($device['deviceId'])
        . '&signature='  . urlencode($device['signature'])
        . '&timestamp='  . $ts
        . '&metrics='    . $metrics
        . '&JsHttpRequest=1-xml';

    $resp = curl_get_raw($profileURL, $session['headers'] ?? [], 20);
    $json = @json_decode($resp['body'], true);
    save_json(PROFILE_FILE, is_array($json) ? $json : ['raw' => $resp['body']]);
    error_log('✅ Saved profile_response.json');
}

/* ====================== Genres ====================== */
function loadOrFetchGenres(array $session, string $portal, ?array $channels_list = null): array {
    error_log('🔹 Fetching genres/categories...');
    $base      = rtrim($portal, '/') . '/';
    $genreMap  = [];
    $endpoints = [
        'server/load.php?type=itv&action=get_genres&JsHttpRequest=1-xml',
        'server/load.php?type=itv&action=get_genres&JsHttpRequest=1-utf8',
        'server/load.php?type=itv&action=get_all_genres&JsHttpRequest=1-xml',
        'server/load.php?type=stb&action=get_genres&JsHttpRequest=1-xml',
        'server/load.php?type=itv&action=get_categories&JsHttpRequest=1-xml',
        'server/load.php?type=itv&action=get_all_categories&JsHttpRequest=1-xml',
    ];

    $extractList = function ($body) {
        if (!is_array($body)) return null;
        $js = $body['js'] ?? null;
        if (is_array($js) && array_key_exists('data', $js)) return $js['data'];
        if (is_array($js) && array_values($js) === $js) return $js;
        if (array_values($body) === $body) return $body;
        if (array_key_exists('data', $body)) return $body['data'];
        return $body;
    };

    foreach ($endpoints as $ep) {
        $url = $base . $ep;
        try {
            $res  = fetchWithRetry($url, $session['headers'] ?? []);
            $json = @json_decode($res['body'], true);
            if (!is_array($json)) {
                $trim = trim($res['body']);
                if ($trim !== '' && in_array($trim[0], ['{', '['], true)) {
                    $json = @json_decode($trim, true);
                }
            }
            $lst = is_array($json) ? $extractList($json) : null;
            if (empty($lst)) continue;

            if (array_values($lst) === $lst) {
                foreach ($lst as $g) {
                    if (!is_array($g)) continue;
                    $idVal = null;
                    foreach (['id', 'genre_id', 'tv_genre_id', 'category_id', 'key'] as $k) {
                        if (isset($g[$k]) && $g[$k] !== '') { $idVal = (string)$g[$k]; break; }
                    }
                    $name = $g['name'] ?? $g['title'] ?? $g['genre_name'] ?? $g['tv_genre_name'] ?? $g['category_name'] ?? '';
                    if ($idVal) $genreMap[$idVal] = trim((string)$name);
                }
            } else {
                foreach ($lst as $k => $v) {
                    if (is_string($v)) $genreMap[(string)$k] = $v;
                    elseif (is_array($v)) {
                        $name = $v['name'] ?? $v['title'] ?? null;
                        if ($name) $genreMap[(string)$k] = $name;
                    }
                }
            }

            if (!empty($genreMap)) {
                error_log('✅ Fetched ' . count($genreMap) . " categories from {$ep}");
                return $genreMap;
            }
        } catch (Exception $e) {
            error_log("❌ Failed {$ep}: " . $e->getMessage());
        }
    }

    // Fallback from channel data
    if (is_array($channels_list)) {
        error_log("⚠️ Building fallback genre map from channel fields");
        $seen = [];
        $idx  = 1;
        foreach ($channels_list as $ch) {
            if (!is_array($ch)) continue;
            $cat = null;
            foreach (['category', 'genres_str', 'group', 'group-title', 'tv_genre_name', 'genre_name'] as $fld) {
                if (!empty($ch[$fld]) && is_string($ch[$fld]) && trim($ch[$fld]) !== '') {
                    $cat = trim($ch[$fld]); break;
                }
            }
            if ($cat && !isset($seen[$cat])) {
                $seen[$cat]             = (string)$idx;
                $genreMap[(string)$idx] = $cat;
                $idx++;
            }
        }
        if (empty($genreMap)) {
            foreach ($channels_list as $ch) {
                if (!is_array($ch)) continue;
                foreach (['tv_genre_id', 'genre_id', 'category_id'] as $idField) {
                    if (!empty($ch[$idField])) {
                        $k = (string)$ch[$idField];
                        if (!isset($genreMap[$k])) {
                            $genreMap[$k] = 'Category ' . (count($genreMap) + 1);
                        }
                    }
                }
            }
        }
        if (!empty($genreMap)) {
            error_log('✅ Built ' . count($genreMap) . ' fallback categories from channels');
            return $genreMap;
        }
    }

    error_log("⚠️ No categories — fallback 'Unknown' will be used");
    return $genreMap;
}

/* ====================== Fetch channels ====================== */

// Extract only essential fields from a channel — saves memory
function slim_channel(array $ch, string $category): array {
    return [
        'id'       => $ch['id']       ?? '',
        'name'     => $ch['name']     ?? $ch['title'] ?? '',
        'cmd'      => $ch['cmd']      ?? '',
        'logo'     => $ch['logo']     ?? '',
        'xmltv_id' => $ch['xmltv_id'] ?? $ch['epg_id'] ?? '',
        'category' => $category,
    ];
}

function fetchChannels(array $session, string $portal): array {
    error_log('🔹 Fetching channels...');

    $baseUrl = rtrim($portal, '/') . '/server/load.php?type=itv&action=get_all_channels&JsHttpRequest=1-xml';
    $res     = fetchWithRetry($baseUrl, $session['headers'] ?? [], 2, 30);

    $json = @json_decode($res['body'], true);
    if (!is_array($json)) {
        throw new Exception('Portal returned invalid channels response: ' . substr($res['body'], 0, 300));
    }

    // Get total for pagination
    $total   = (int)($json['js']['total_items'] ?? $json['js']['total'] ?? 0);
    $perPage = (int)($json['js']['max_page_items'] ?? 14);
    if ($perPage < 1) $perPage = 14;

    // First page data
    $firstPage = $json['js']['data'] ?? [];
    unset($json); // free memory immediately

    // Fetch genres first (needs minimal memory)
    $genres = loadOrFetchGenres($session, $portal, $firstPage);

    // Helper: resolve category for one channel
    $resolvecat = function(array $ch) use ($genres): string {
        foreach (['tv_genre_id', 'genre_id', 'category_id'] as $f) {
            if (!empty($ch[$f]) && !empty($genres[(string)$ch[$f]])) {
                return $genres[(string)$ch[$f]];
            }
        }
        foreach (['category', 'genres_str', 'group', 'group-title', 'tv_genre_name', 'genre_name'] as $f) {
            if (!empty($ch[$f]) && is_string($ch[$f]) && trim($ch[$f]) !== '') {
                return trim($ch[$f]);
            }
        }
        return 'Unknown';
    };

    // Process first page — live channels only
    $merged = [];
    foreach ($firstPage as $ch) {
        if (!is_array($ch)) continue;
        // Skip if no cmd (VOD/series have empty cmd)
        if (empty($ch['cmd'])) continue;
        $merged[] = slim_channel($ch, $resolvecat($ch));
    }
    unset($firstPage);

    // Paginated fetch — process & free each page immediately
    if ($total > $perPage) {
        $pages = (int)ceil($total / $perPage);
        error_log("📄 Total: {$total} channels across {$pages} pages");

        for ($p = 2; $p <= $pages; $p++) {
            $pUrl = rtrim($portal, '/') . '/server/load.php?type=itv&action=get_all_channels'
                . '&p=' . $p . '&JsHttpRequest=1-xml';
            try {
                $pRes  = fetchWithRetry($pUrl, $session['headers'] ?? [], 1, 25);
                $pJson = @json_decode($pRes['body'], true);
                unset($pRes);
                $pData = $pJson['js']['data'] ?? [];
                unset($pJson);

                foreach ($pData as $ch) {
                    if (!is_array($ch)) continue;
                    if (empty($ch['cmd'])) continue; // skip VOD
                    $merged[] = slim_channel($ch, $resolvecat($ch));
                }
                unset($pData);

                error_log("  Page {$p}/{$pages}: total so far " . count($merged));
                if ($p % 5 === 0) gc_collect_cycles(); // periodic GC
            } catch (Exception $e) {
                error_log("  ⚠️ Page {$p} failed: " . $e->getMessage());
            }
            usleep(50000); // 50ms delay
        }
    }

    /* ── FIX B: Save correctly so load later works ── */
    save_json(CHANNELS_FILE, ['js' => ['data' => $merged, 'total_items' => count($merged)]]);
    error_log('💾 Saved ' . count($merged) . ' channels to ' . CHANNELS_FILE);
    return $merged;
}

/* ====================== create_link ====================== */
function create_link(array $session, string $portal, string $cmd) {
    error_log('🔹 create_link: ' . (strlen($cmd) > 120 ? substr($cmd, 0, 120) . '…' : $cmd));

    if (preg_match('/(https?:\/\/[^\s"\']+)/i', $cmd, $urlMatch) && stripos(trim($cmd), 'ffrt') !== 0) {
        return ['direct' => trim($urlMatch[1]), 'source_cmd' => $cmd];
    }

    $encoded = preg_replace_callback(
        '/%[0-9a-f]{2}/i',
        function($x) { return strtoupper($x[0]); },
        rawurlencode($cmd)
    );
    $url = rtrim($portal, '/') . '/server/load.php?type=itv&action=create_link&cmd=' . $encoded . '&JsHttpRequest=1-xml';
    $res = curl_get_raw($url, $session['headers'] ?? [], 20);

    $json = @json_decode($res['body'], true);
    if (!is_array($json)) {
        return ['status' => 'non-json', 'text' => $res['body']];
    }
    $js = $json['js'] ?? $json;
    @save_json(CREATED_LINK_FILE, $js);
    return $js;
}

/* ====================== Routing helpers ====================== */
function compute_base_url(): string {
    $scheme    = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host      = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $scriptDir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    if ($scriptDir === '/') $scriptDir = '';
    return rtrim($scheme . '://' . $host . $scriptDir, '/');
}

function detect_path(): string {
    // Method 1: ?r=route query param (most compatible - works on all servers)
    if (!empty($_GET['r'])) {
        return trim($_GET['r'], '/');
    }

    $uriPath    = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $scriptName = $_SERVER['SCRIPT_NAME'] ?? '/index.php';

    // Method 2: PATH_INFO (set when using index.php/playlist.m3u)
    if (!empty($_SERVER['PATH_INFO'])) {
        return trim($_SERVER['PATH_INFO'], '/');
    }

    // Method 3: ORIG_PATH_INFO fallback
    if (!empty($_SERVER['ORIG_PATH_INFO'])) {
        return trim($_SERVER['ORIG_PATH_INFO'], '/');
    }

    // Method 4: /index.php/ in URI
    $idxKey = '/index.php/';
    if (($pos = strpos($uriPath, $idxKey)) !== false) {
        return trim(substr($uriPath, $pos + strlen($idxKey)), '/');
    }

    // Method 5: strip script directory from URI
    $scriptDir = str_replace('\\', '/', dirname($scriptName));
    if ($scriptDir !== '/') {
        $stripped = substr($uriPath, strlen($scriptDir));
    } else {
        $stripped = $uriPath;
    }
    $stripped = trim($stripped, '/');
    if ($stripped === 'index.php') return '';
    return $stripped;
}

/* ====================== Playlist caching ====================== */

/*
 * FIX C: should_regen_playlist
 *   - Agar CHANNELS_FILE exist nahi karta: ALWAYS regen
 *   - Hash comparison sirf tab karo jab dono sides non-null hoon
 *   - Hit counter ki threshold reach ho to regen karo
 */
function should_regen_playlist(int $threshold = 5, int $window_seconds = 60): bool {
    // No playlist file → must generate
    if (!file_exists(PLAYLIST_FILE)) {
        error_log('🔄 Playlist file missing — regenerating');
        return true;
    }

    // No channels file → must generate
    if (!file_exists(CHANNELS_FILE)) {
        error_log('🔄 Channels file missing — regenerating');
        return true;
    }

    $meta    = load_json(PLAYLIST_META);
    $rawHash = md5_file(CHANNELS_FILE);  // safe: file exists

    // Meta missing or hash mismatch → must regenerate
    if (!is_array($meta)) {
        error_log('🔄 Playlist meta missing — regenerating');
        return true;
    }
    if (($meta['raw_hash'] ?? null) !== $rawHash) {
        error_log('🔄 Channels data changed — regenerating playlist');
        return true;
    }

    // Playlist older than 6 hours → force refresh
    $playlistAge = time() - (int)($meta['generated_at'] ?? 0);
    if ($playlistAge > 21600) {
        error_log('🔄 Playlist older than 6h — regenerating');
        return true;
    }

    // Hit threshold check
    $hits   = load_json(HITS_FILE) ?? [];
    $now    = time();
    $recent = array_filter($hits, function($t) use ($now, $window_seconds) { return ($now - (int)$t) <= $window_seconds; });

    if (count($recent) >= $threshold) {
        save_json(HITS_FILE, []);
        error_log('🔄 Hit threshold reached — regenerating');
        return true;
    }

    return false;
}

function record_playlist_hit(): void {
    $hits = load_json(HITS_FILE) ?? [];
    $hits[] = time();
    if (count($hits) > 200) $hits = array_slice($hits, -200);
    save_json(HITS_FILE, $hits);
}

/* ====================== Playlist builder ====================== */

// Write playlist directly to file — no giant string in memory
// Only live channels (with cmd field) are included
function build_playlist_file(array $channels, string $outFile): int {
    $base = compute_base_url();
    $fh   = fopen($outFile, 'w');
    if (!$fh) throw new Exception('Cannot write playlist file: ' . $outFile);

    fwrite($fh, "#EXTM3U x-tvg-url=\"\" playlist-name=\"RKDYIPTV\" credits=\"@RKDYIPTV\"\n");
    $count = 0;

    foreach ($channels as $i => $ch) {
        if (!is_array($ch)) continue;

        // Skip channels with no playback command
        $cmd = trim((string)($ch['cmd'] ?? ''));
        if ($cmd === '') continue;

        $name  = trim((string)($ch['name'] ?? ''));
        if ($name === '') $name = 'Ch ' . ($i + 1);
        $name  = str_replace(["\r", "\n", ',', '"'], ' ', $name);

        $logo  = str_replace('"', "'", trim((string)($ch['logo'] ?? '')));
        $group = trim((string)($ch['category'] ?? 'Unknown'));
        if ($group === '') $group = 'Unknown';
        $group = str_replace('"', "'", $group);
        $tvgId = str_replace('"', '', trim((string)($ch['xmltv_id'] ?? $ch['id'] ?? '')));

        fwrite($fh, '#EXTINF:-1 tvg-id="' . $tvgId . '" tvg-logo="' . $logo . '" group-title="' . $group . '",' . $name . "\n");
        fwrite($fh, $base . '/index.php?r=tg/rkdyiptv/' . $i . ".m3u8\n");
        $count++;
    }

    fclose($fh);
    error_log('✅ Playlist written: ' . $count . ' live channels');
    return $count;
}

// Fallback: return as string
function build_playlist_text(array $channels): string {
    $tmp = sys_get_temp_dir() . '/pl_' . getmypid() . '.m3u';
    build_playlist_file($channels, $tmp);
    $out = @file_get_contents($tmp) ?: "#EXTM3U\n";
    @unlink($tmp);
    return $out;
}

/* ====================== Response helpers ====================== */
function json_resp($data, int $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function extract_stream_url($js): ?string {
    if (!is_array($js)) return null;

    // direct key (set by our own create_link shortcut)
    if (!empty($js['direct']) && is_string($js['direct']) && stripos($js['direct'], 'http') === 0) {
        return trim($js['direct']);
    }

    // FIX E: cmd field often contains "ffmpeg <url>" — strip the prefix
    foreach (['cmd', 'url', 'stream_url'] as $key) {
        if (!empty($js[$key]) && is_string($js[$key])) {
            $val = trim($js[$key]);
            // Strip common wrappers: "ffmpeg " / "ffrt " / "ffrt1 " etc.
            if (preg_match('/^ff\S*\s+(https?:\/\/\S+)/i', $val, $m2)) {
                return $m2[1];
            }
            if (stripos($val, 'http') === 0) return $val;
        }
    }

    $nested = isset($js['js']) && is_array($js['js']) ? $js['js'] : null;
    if ($nested) {
        foreach (['cmd', 'url', 'stream_url'] as $key) {
            if (!empty($nested[$key]) && is_string($nested[$key])) {
                $val = trim($nested[$key]);
                if (preg_match('/^ff\S*\s+(https?:\/\/\S+)/i', $val, $m2)) {
                    return $m2[1];
                }
                if (stripos($val, 'http') === 0) return $val;
            }
        }
    }
    return null;
}

/* ====================== Routing ====================== */
$path = detect_path();

/* ── Root ── */
if ($path === '' || $path === 'index.php') {
    // Redirect to Telegram
    header('Location: https://t.me/rkdyiptv', true, 302);
    exit;
}

if ($path === 'info') {
    $device      = generateDeviceInfo(MAC);
    $base        = compute_base_url();
    $playlistUrl = $base . '/playlist.m3u';
    $getlinkUrl  = $base . '/getlink/0';

    header('Content-Type: text/html; charset=utf-8');
    echo "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Stalker Portal Info</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0b0c10; color: #f2f2f2;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; }
        .container { background: #1f2833; padding: 30px 40px; border-radius: 10px;
                     box-shadow: 0 0 15px rgba(0,0,0,.4); width: 90%; max-width: 700px; }
        h1 { text-align: center; color: #66fcf1; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        td { padding: 10px; border-bottom: 1px solid #45a29e; }
        td.label { color: #66fcf1; font-weight: bold; width: 35%; }
        td.value { color: #c5c6c7; word-break: break-all; }
        a { color: #45a29e; text-decoration: none; font-weight: bold; }
        a:hover { color: #66fcf1; text-decoration: underline; }
        .links { text-align: center; margin-top: 15px; }
        .footer { text-align: center; margin-top: 25px; font-size: .9em; color: #888; }
        .badge { display:inline-block; background:#45a29e22; border:1px solid #45a29e;
                 color:#66fcf1; padding:3px 10px; border-radius:20px; font-size:.8em;
                 margin-left:8px; }
    </style>
</head>
<body>
<div class='container'>
    <h1>Stalker Portal Info</h1>
    <table>
        <tr><td class='label'>Portal URL:</td>   <td class='value'>" . htmlspecialchars(PORTAL) . "</td></tr>
        <tr><td class='label'>MAC Address:</td>  <td class='value'>" . htmlspecialchars($device['mac']) . "</td></tr>
        <tr><td class='label'>SN Cut:</td>       <td class='value'>" . htmlspecialchars($device['sncut']) . "</td></tr>
        <tr><td class='label'>Signature:</td>    <td class='value'>" . htmlspecialchars($device['signature']) . "</td></tr>
        <tr><td class='label'>Device ID:</td>    <td class='value'>" . htmlspecialchars($device['deviceId']) . "</td></tr>
    </table>
    <div class='links'>
        <p><a href='" . htmlspecialchars($playlistUrl) . "' target='_blank'>📺 View Playlist (playlist.m3u)</a></p>
        <p><a href='" . htmlspecialchars($getlinkUrl) . "' target='_blank'>🔗 Example GetLink (Channel 0)</a></p>
        <p><a href='https://t.me/rkdyiptv' target='_blank'>📢 Join Telegram @RKDYIPTV</a></p>
        <p><a href='" . htmlspecialchars($base . '/refresh_session') . "' target='_blank'>🔄 Force Refresh Session</a></p>
        <p><a href='" . htmlspecialchars($base . '/debug') . "' target='_blank'>🐛 Debug Info</a></p>
    </div>
    <div class='footer'>Generated by your Stalker Portal Script</div>
</div>
</body>
</html>";
    exit;
}

/* ── refresh_session ── */
if ($path === 'refresh_session') {
    try {
        $session = performHandshake(PORTAL, MAC);
        try { fetchProfile($session, PORTAL); } catch (Exception $e) { /* non-fatal */ }
        json_resp(['status' => 'ok', 'token' => $session['token']]);
    } catch (Exception $e) {
        json_resp(['status' => 'error', 'error' => $e->getMessage()], 500);
    }
}

/* ── test_portal endpoint ── */
if ($path === 'test_portal') {
    $results = [];
    // Test 1: raw URLs
    $testUrls = [
        'portal_root' => rtrim(PORTAL, '/') . '/',
        'c_page'      => rtrim(PORTAL, '/') . '/c/',
    ];
    foreach ($testUrls as $name => $url) {
        try {
            $r = curl_get_raw($url, [], 10);
            $results[$name] = ['url' => $url, 'status' => $r['status'], 'body_preview' => substr($r['body'], 0, 150)];
        } catch (Exception $e) {
            $results[$name] = ['url' => $url, 'error' => $e->getMessage()];
        }
    }
    // Test 2: actual performHandshake
    try {
        $sess = performHandshake(PORTAL, MAC);
        $results['handshake'] = ['status' => 'OK', 'token' => $sess['token'], 'cookie' => $sess['cookie']];
    } catch (Exception $e) {
        $results['handshake'] = ['status' => 'FAILED', 'error' => $e->getMessage()];
    }
    json_resp($results);
}

/* ── debug endpoint ── */
if ($path === 'debug') {
    $session       = load_json(SESSION_FILE);
    $meta          = load_json(PLAYLIST_META);
    $channelsObj   = load_json(CHANNELS_FILE);
    $channelCount  = is_array($channelsObj['js']['data'] ?? null)
        ? count($channelsObj['js']['data'])
        : 0;

    json_resp([
        'php_version'       => PHP_VERSION,
        'curl_available'    => function_exists('curl_init'),
        'session_exists'    => is_array($session),
        'session_token'     => $session['token'] ?? null,
        'session_age_sec'   => is_array($session) ? (time() - (int)($session['fetched_at'] ?? 0)) : null,
        'channels_count'    => $channelCount,
        'channels_file'     => file_exists(CHANNELS_FILE),
        'playlist_file'     => file_exists(PLAYLIST_FILE),
        'playlist_meta'     => $meta,
        'playlist_age_sec'  => is_array($meta) ? (time() - (int)($meta['generated_at'] ?? 0)) : null,
        'base_url'          => compute_base_url(),
        'detected_path'     => detect_path(),
    ]);
}

/* ── playlist.m3u ── */
if ($path === 'playlist.m3u') {
    // If cached playlist exists and is fresh — serve immediately, no DB/portal call
    if (file_exists(PLAYLIST_FILE) && !should_regen_playlist(5, 60)) {
        header('Content-Type: audio/x-mpegurl; charset=utf-8');
        header('Content-Disposition: inline; filename="playlist.m3u"');
        header('Cache-Control: max-age=3600');
        readfile(PLAYLIST_FILE);
        exit;
    }

    // Need to regenerate
    try {
        record_playlist_hit();
        $session = ensure_session(PORTAL, MAC);

        $channelsObj = load_json(CHANNELS_FILE);
        $channels    = $channelsObj['js']['data'] ?? [];

        if (empty($channels)) {
            error_log('🔄 No cached channels — fetching...');
            try {
                $channels = fetchChannels($session, PORTAL);
            } catch (Exception $e) {
                error_log('⚠️ fetchChannels failed: ' . $e->getMessage() . ' — re-handshaking');
                $session  = performHandshake(PORTAL, MAC);
                $channels = fetchChannels($session, PORTAL);
            }
        }

        // Write directly to file — memory efficient
        $tmpFile = PLAYLIST_FILE . '.tmp';
        $count   = build_playlist_file($channels, $tmpFile);
        rename($tmpFile, PLAYLIST_FILE);
        unset($channels); // free memory

        save_json(PLAYLIST_META, [
            'raw_hash'      => file_exists(CHANNELS_FILE) ? md5_file(CHANNELS_FILE) : null,
            'generated_at'  => time(),
            'channel_count' => $count,
        ]);
        error_log('✅ Playlist ready: ' . $count . ' channels, size: ' . filesize(PLAYLIST_FILE) . ' bytes');

        header('Content-Type: audio/x-mpegurl; charset=utf-8');
        header('Content-Disposition: inline; filename="playlist.m3u"');
        header('Cache-Control: max-age=3600');
        readfile(PLAYLIST_FILE);
        exit;

    } catch (Exception $e) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo '# Playlist error: ' . $e->getMessage() . "\n";
        echo '# Try: index.php?r=refresh_session then retry' . "\n";
        exit;
    }
}

/* ── getlink handler ── */
// Supports: /getlink/44  /getlink/44.m3u8  ?r=getlink/44.m3u8  ?id=44
if (preg_match('#^(?:getlink|tg/rkdyiptv)/?([0-9]+)(?:\.m3u8)?$#', $path, $m)) {

    $chid = isset($m[1]) && $m[1] !== '' ? (int)$m[1]
          : (isset($_GET['id'])           ? (int)$_GET['id'] : null);

    if ($chid === null) json_resp(['error' => 'Channel id required'], 400);

    try {
        $session = ensure_session(PORTAL, MAC);

        $channelsObj = load_json(CHANNELS_FILE);
        $channels    = $channelsObj['js']['data'] ?? [];
        if (empty($channels)) $channels = fetchChannels($session, PORTAL);

        if ($chid < 0 || $chid >= count($channels)) {
            json_resp(['error' => 'Invalid channel id: ' . $chid . ' (total: ' . count($channels) . ')'], 404);
        }

        $ch  = $channels[$chid];
        $cmd = trim((string)($ch['cmd'] ?? ''));

        if ($cmd === '') {
            // Try cmds array
            if (isset($ch['cmds']) && is_array($ch['cmds']) && !empty($ch['cmds'])) {
                $first = $ch['cmds'][0];
                $cmd   = trim((string)($first['url'] ?? $first['command'] ?? $first['cmd'] ?? ''));
            }
        }

        if ($cmd === '') json_resp(['error' => 'No stream cmd for channel', 'channel_name' => $ch['name'] ?? ''], 400);

        $cmdLow = strtolower($cmd);

        // Helper: redirect to URL
        $redirect = function(string $url) {
            header('Location: ' . $url, true, 302);
            exit;
        };

        // 1) Direct HTTP URL (not ffrt)
        if (stripos($cmdLow, 'ffrt') !== 0 && preg_match('/(https?:\/\/\S+)/i', $cmd, $um)) {
            $redirect(trim($um[1]));
        }

        // 2) ffmpeg wrapper — strip prefix
        if (stripos($cmdLow, 'ffmpeg') === 0) {
            $inner = trim(substr($cmd, 6));
            if (preg_match('/(https?:\/\/\S+)/i', $inner, $um)) $redirect(trim($um[1]));
            if (stripos($inner, 'http') === 0) $redirect($inner);
        }

        // 3) ffrt / anything else — ask portal for real URL
        $doCreateLink = function() use (&$session, $cmd) {
            $js = create_link($session, PORTAL, $cmd);
            if (is_array($js) && ($js['status'] ?? '') === 'non-json') {
                error_log('⚠️ create_link non-json — re-handshaking');
                $session = performHandshake(PORTAL, MAC);
                $js      = create_link($session, PORTAL, $cmd);
            }
            return $js;
        };

        $js  = $doCreateLink();
        $url = extract_stream_url($js);
        if ($url) $redirect($url);

        // Nothing worked — return debug info
        json_resp([
            'error'        => 'Could not resolve stream URL',
            'channel_name' => $ch['name'] ?? '',
            'cmd'          => $cmd,
            'portal_resp'  => is_array($js) ? $js : ['raw' => (string)$js],
        ]);

    } catch (Exception $e) {
        json_resp(['error' => $e->getMessage()], 500);
    }
}

/* ── create_link manual ── */
if ($path === 'create_link') {
    $cmd = $_GET['cmd'] ?? null;
    if ($cmd === null) json_resp(['error' => 'cmd query param required'], 400);
    try {
        $session = ensure_session(PORTAL, MAC);
        json_resp(create_link($session, PORTAL, $cmd));
    } catch (Exception $e) {
        json_resp(['error' => $e->getMessage()], 500);
    }
}

/* ── proxy ── */
if ($path === 'proxy' && isset($_GET['u'])) {
    $u = $_GET['u'];

    $parsed = parse_url($u);
    if (!isset($parsed['scheme']) || !in_array(strtolower($parsed['scheme']), ['http', 'https'], true)) {
        http_response_code(400);
        echo 'Proxy error: only http/https URLs are allowed';
        exit;
    }
    $host = $parsed['host'] ?? '';
    if (preg_match('/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i', $host)) {
        http_response_code(403);
        echo 'Proxy error: private/loopback addresses are not permitted';
        exit;
    }

    try {
        $session = load_json(SESSION_FILE);
        $headers = (is_array($session) && isset($session['headers'])) ? $session['headers'] : [];
        $res     = curl_get_raw($u, $headers, 30);
        $allowed = ['content-type', 'content-length', 'content-range', 'accept-ranges'];
        foreach ($res['header'] as $hk => $hv) {
            if (in_array(strtolower($hk), $allowed, true)) header($hk . ': ' . $hv);
        }
        echo $res['body'];
        exit;
    } catch (Exception $e) {
        http_response_code(500);
        echo 'Proxy error: ' . $e->getMessage();
        exit;
    }
}

/* ── 404 ── */
http_response_code(404);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['error' => 'Not found', 'path' => $path], JSON_PRETTY_PRINT);
exit;