<?php

namespace app\utils;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class CheckUtils
{
    public static function curl($url, $timeout, $ip = null, $proxy = false)
    {
        $status = true;
        $errmsg = null;
        $start = microtime(true);

        $urlarr = parse_url($url);
        if (!$urlarr) {
            return ['status' => false, 'errmsg' => 'Invalid URL', 'usetime' => 0];
        }
        if (str_starts_with($urlarr['host'], '[') && str_ends_with($urlarr['host'], ']')) {
            $urlarr['host'] = substr($urlarr['host'], 1, -1);
        }
        if (!empty($ip) && !filter_var($urlarr['host'], FILTER_VALIDATE_IP)) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                $ip = gethostbyname($ip);
            }
            if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $port = $urlarr['port'] ?? ($urlarr['scheme'] == 'https' ? 443 : 80);
                $resolve = $urlarr['host'] . ':' . $port . ':' . $ip;
            }
        }

        $options = [
            'timeout' => $timeout,
            'connect_timeout' => $timeout,
            'verify' => false,
            'headers' => [
                'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36'
            ],
            'http_errors' => false // 不抛出异常
        ];
        // 处理解析
        if (!empty($resolve)) {
            $options['curl'] = [
                CURLOPT_DNS_USE_GLOBAL_CACHE => false,
                CURLOPT_RESOLVE => [$resolve]
            ];
        }
        // 处理代理（支持 proxy_id：0=不用, 1=代理1, 2=代理2）
        if ($proxy) {
            $proxy_id = is_bool($proxy) ? 1 : intval($proxy);
            if ($proxy_id > 0) {
                $suffix = $proxy_id == 2 ? '_2' : '';
                $proxy_server = config_get('proxy_server' . $suffix);
                $proxy_port = intval(config_get('proxy_port' . $suffix));
                if ($proxy_id == 2 && (empty($proxy_server) || empty($proxy_port))) {
                    $proxy_server = config_get('proxy_server');
                    $proxy_port = intval(config_get('proxy_port'));
                    $suffix = '';
                }
                $proxy_userpwd = config_get('proxy_user' . $suffix) . ':' . config_get('proxy_pwd' . $suffix);

                if (!empty($proxy_server) && !empty($proxy_port)) {
                    $proxy_type = config_get('proxy_type' . $suffix);
                    match ($proxy_type) {
                        'https' => $proxy_string = 'https://',
                        'sock4' => $proxy_string = 'socks4://',
                        'sock5' => $proxy_string = 'socks5://',
                        'sock5h' => $proxy_string = 'socks5h://',
                        default => $proxy_string = 'http://',
                    };

                    if ($proxy_userpwd != ':') {
                        $proxy_string .= $proxy_userpwd . '@';
                    }

                    $proxy_string .= $proxy_server . ':' . $proxy_port;
                    $options['proxy'] = $proxy_string;
                }
            }
        }

        try {
            $client = new Client();
            $response = $client->request('GET', $url, $options);
            $httpcode = $response->getStatusCode();

            if ($httpcode < 200 || $httpcode >= 400) {
                $status = false;
                $errmsg = 'http_code=' . $httpcode;
            }
        } catch (GuzzleException $e) {
            $status = false;
            $errmsg = guzzle_error($e);
        }

        $usetime = round((microtime(true) - $start) * 1000);
        return ['status' => $status, 'errmsg' => $errmsg, 'usetime' => $usetime];
    }

    /**
     * 通过 SOCKS5 代理建立到目标 host:port 的纯 TCP 连接（仅判断能否连通，不发送 HTTP 请求）
     * 用于容灾 TCP 检测，避免对 SSH 等非 HTTP 端口发 GET 导致误判掉线
     */
    private static function socks5TcpConnect($proxy_server, $proxy_port, $proxy_user, $proxy_pwd, $target, $port, $timeout)
    {
        $errStr = null;
        $ctx = stream_context_create([
            'socket' => [
                'timeout' => $timeout,
                'connect_timeout' => $timeout,
            ],
        ]);
        $fp = @stream_socket_client(
            'tcp://' . $proxy_server . ':' . $proxy_port,
            $errno,
            $errmsg,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if (!$fp) {
            return ['status' => false, 'errmsg' => $errmsg ?: ('errno ' . $errno)];
        }
        stream_set_timeout($fp, $timeout);

        // SOCKS5 协商：支持无认证(0)与用户名密码(2)
        $authMethods = empty($proxy_user) && empty($proxy_pwd) ? "\x00" : "\x00\x02";
        $buf = "\x05" . chr(strlen($authMethods)) . $authMethods;
        if (fwrite($fp, $buf) !== strlen($buf)) {
            fclose($fp);
            return ['status' => false, 'errmsg' => 'proxy write handshake failed'];
        }
        $reply = fread($fp, 2);
        if ($reply === false || strlen($reply) < 2 || $reply[0] !== "\x05") {
            fclose($fp);
            return ['status' => false, 'errmsg' => 'proxy handshake invalid'];
        }
        $method = ord($reply[1]);
        if ($method === 0x02) {
            $ulen = strlen($proxy_user);
            $plen = strlen($proxy_pwd);
            $buf = "\x01" . chr($ulen) . $proxy_user . chr($plen) . $proxy_pwd;
            if (fwrite($fp, $buf) !== strlen($buf)) {
                fclose($fp);
                return ['status' => false, 'errmsg' => 'proxy auth write failed'];
            }
            $authReply = fread($fp, 2);
            if ($authReply === false || strlen($authReply) < 2 || $authReply[1] !== "\x00") {
                fclose($fp);
                return ['status' => false, 'errmsg' => 'proxy auth failed'];
            }
        } elseif ($method !== 0x00) {
            fclose($fp);
            return ['status' => false, 'errmsg' => 'proxy unsupported auth method'];
        }

        // CONNECT 到 target:port（IPv4 或域名）
        if (filter_var($target, FILTER_VALIDATE_IP)) {
            $addr = "\x01" . inet_pton($target) . pack('n', $port);
        } else {
            $addr = "\x03" . chr(strlen($target)) . $target . pack('n', $port);
        }
        $buf = "\x05\x01\x00" . $addr;
        if (fwrite($fp, $buf) !== strlen($buf)) {
            fclose($fp);
            return ['status' => false, 'errmsg' => 'proxy connect write failed'];
        }
        $connectReply = fread($fp, 4);
        if ($connectReply === false || strlen($connectReply) < 4 || $connectReply[0] !== "\x05") {
            fclose($fp);
            return ['status' => false, 'errmsg' => 'proxy connect reply invalid'];
        }
        $rep = ord($connectReply[1]);
        if ($rep !== 0x00) {
            $repMsg = [
                0x01 => 'general failure',
                0x02 => 'connection not allowed',
                0x03 => 'network unreachable',
                0x04 => 'host unreachable',
                0x05 => 'connection refused',
                0x06 => 'TTL expired',
                0x07 => 'command not supported',
                0x08 => 'address type not supported',
            ];
            fclose($fp);
            return ['status' => false, 'errmsg' => $repMsg[$rep] ?? ('proxy rep ' . $rep)];
        }
        $atyp = ord($connectReply[3]);
        if ($atyp === 0x01) {
            $left = 6; // IPv4 + port
        } elseif ($atyp === 0x03) {
            $len = ord(fread($fp, 1));
            $left = $len + 2;
        } else {
            $left = 18; // IPv6 + port
        }
        if ($left > 0 && fread($fp, $left) === false) {
            fclose($fp);
            return ['status' => false, 'errmsg' => 'proxy connect reply read failed'];
        }
        fclose($fp);
        return ['status' => true, 'errmsg' => null];
    }

    public static function tcp($target, $ip, $port, $timeout, $proxy = false)
    {
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) $target = $ip;
        if (str_ends_with($target, '.')) $target = substr($target, 0, -1);

        // 使用代理时通过 SOCKS 做纯 TCP 连接检测（仅 SOCKS 支持 TCP 穿透；不发 HTTP 请求，避免非 HTTP 端口被误判掉线）
        if ($proxy) {
            $proxy_id = is_bool($proxy) ? 1 : intval($proxy);
            if ($proxy_id > 0) {
                $suffix = $proxy_id == 2 ? '_2' : '';
                $proxy_server = config_get('proxy_server' . $suffix);
                $proxy_port = intval(config_get('proxy_port' . $suffix));
                $proxy_user = config_get('proxy_user' . $suffix);
                $proxy_pwd = config_get('proxy_pwd' . $suffix);
                $proxy_type = config_get('proxy_type' . $suffix);
                if ($proxy_id == 2 && (empty($proxy_server) || empty($proxy_port))) {
                    $proxy_server = config_get('proxy_server');
                    $proxy_port = intval(config_get('proxy_port'));
                    $proxy_user = config_get('proxy_user');
                    $proxy_pwd = config_get('proxy_pwd');
                    $proxy_type = config_get('proxy_type') ?: 'http';
                }
                if (!empty($proxy_server) && !empty($proxy_port)) {
                    if ($proxy_type === 'sock4') {
                        $starttime = getMillisecond();
                        return ['status' => false, 'errmsg' => 'TCP检测仅支持 SOCKS5 代理', 'usetime' => getMillisecond() - $starttime];
                    }
                    if (in_array($proxy_type, ['sock5', 'sock5h'])) {
                        $starttime = getMillisecond();
                        $ret = self::socks5TcpConnect($proxy_server, $proxy_port, $proxy_user ?? '', $proxy_pwd ?? '', $target, (int) $port, $timeout);
                        $usetime = getMillisecond() - $starttime;
                        return ['status' => $ret['status'], 'errmsg' => $ret['errmsg'], 'usetime' => $usetime];
                    }
                }
            }
        }

        if (!filter_var($target, FILTER_VALIDATE_IP) && checkDomain($target)) {
            $target = gethostbyname($target);
            if (!$target) return ['status' => false, 'errmsg' => 'DNS resolve failed', 'usetime' => 0];
        }
        if (filter_var($target, FILTER_VALIDATE_IP) && str_contains($target, ':')) {
            $target = '['.$target.']';
        }
        $starttime = getMillisecond();
        $fp = @fsockopen($target, $port, $errCode, $errStr, $timeout);
        if ($fp) {
            $status = true;
            fclose($fp);
        } else {
            $status = false;
        }
        $endtime = getMillisecond();
        $usetime = $endtime - $starttime;
        return ['status' => $status, 'errmsg' => $errStr, 'usetime' => $usetime];
    }

    public static function ping($target, $ip)
    {
        if (!function_exists('exec')) return ['status' => false, 'errmsg' => 'exec函数不可用', 'usetime' => 0];
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) $target = $ip;
        if (str_ends_with($target, '.')) $target = substr($target, 0, -1);
        if (!filter_var($target, FILTER_VALIDATE_IP) && checkDomain($target)) {
            $target = gethostbyname($target);
            if (!$target) return ['status' => false, 'errmsg' => 'DNS resolve failed', 'usetime' => 0];
        }
        if (!filter_var($target, FILTER_VALIDATE_IP)) {
            return ['status' => false, 'errmsg' => 'Invalid IP address', 'usetime' => 0];
        }
        $timeout = 1;
        if (str_contains($target, ':')) {
            exec('ping -6 -c 1 -w '.$timeout.' '.$target, $output, $return_var);
        } else {
            exec('ping -c 1 -w '.$timeout.' '.$target, $output, $return_var);
        }
        if (!empty($output[1])) {
            if (strpos($output[1], '毫秒') !== false) {
                $usetime = getSubstr($output[1], '时间=', ' 毫秒');
            } else {
                $usetime = getSubstr($output[1], 'time=', ' ms');
            }
        }
        $usetime = !empty($usetime) ? round(trim($usetime)) : 0;
        $errmsg = null;
        if ($return_var !== 0) {
            $usetime = $usetime == 0 ? $timeout * 1000 : $usetime;
            $errmsg = 'ping timeout';
        }
        return ['status' => $return_var === 0, 'errmsg' => $errmsg, 'usetime' => $usetime];
    }
}
