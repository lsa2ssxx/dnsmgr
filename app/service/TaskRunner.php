<?php

namespace app\service;

use app\lib\NewDb;
use app\lib\DnsHelper;
use app\utils\CheckUtils;
use app\utils\MsgNotice;

/**
 * 容灾监控任务执行
 */
class TaskRunner
{
    private $conn;

    private function db()
    {
        if (!$this->conn) {
            $this->conn = NewDb::connect();
        }
        return $this->conn;
    }

    private function closeDb()
    {
        if ($this->conn) {
            $this->conn->close();
        }
    }

    public function execute($row)
    {
        if ($row['type'] == 3) { //条件开启解析
            $action = 0;
            $remain = $this->db()->name('dmtask')->where(['did' => $row['did'], 'rr' => $row['rr'], 'type' => 1, 'status' => 0])->count();
            if ($remain <= $row['cycle'] && $row['status'] == 0) {
                $action = 2;
                $this->db()->name('dmtask')->where('id', $row['id'])->update(['status' => 1, 'errcount' => 0, 'switchtime' => time()]);
            } elseif ($remain > $row['cycle'] && $row['status'] == 1) {
                $action = 1;
                $this->db()->name('dmtask')->where('id', $row['id'])->update(['status' => 0, 'errcount' => 0, 'switchtime' => time()]);
            }
        } else {
            $proxy_id = isset($row['proxy_id']) ? intval($row['proxy_id']) : ($row['proxy'] == 1 ? 1 : 0);
            if ($row['checktype'] == 2) {
                $result = CheckUtils::curl($row['checkurl'], $row['timeout'], $row['main_value'], $proxy_id);
            } elseif ($row['checktype'] == 1) {
                $result = CheckUtils::tcp($row['main_value'], $row['checkurl'], $row['tcpport'], $row['timeout'], $proxy_id);
            } else {
                $result = CheckUtils::ping($row['main_value'], $row['checkurl']);
            }

            $action = 0;
            if ($result['status'] && $row['status'] == 1) {
                if ($row['cycle'] <= 1 || $row['errcount'] >= $row['cycle']) {
                    $this->db()->name('dmtask')->where('id', $row['id'])->update(['status' => 0, 'errcount' => 0, 'switchtime' => time()]);
                    $action = 2;
                } else {
                    $this->db()->name('dmtask')->where('id', $row['id'])->inc('errcount')->update();
                }
            } elseif (!$result['status'] && $row['status'] == 0) {
                if ($row['cycle'] <= 1 || $row['errcount'] >= $row['cycle']) {
                    $this->db()->name('dmtask')->where('id', $row['id'])->update(['status' => 1, 'errcount' => 0, 'switchtime' => time()]);
                    $action = 1;
                } else {
                    $this->db()->name('dmtask')->where('id', $row['id'])->inc('errcount')->update();
                }
            } elseif ($row['errcount'] > 0) {
                $this->db()->name('dmtask')->where('id', $row['id'])->update(['errcount' => 0]);
            }
        }

        if ($action > 0) {
            $drow = $this->db()->name('domain')->alias('A')->join('account B', 'A.aid = B.id')->where('A.id', $row['did'])->field('A.*,B.type,B.config')->find();
            if (!$drow) {
                echo '域名不存在（ID：'.$row['did'].'）'."\n";
                $this->closeDb();
                return;
            }
            $row['domain'] = $row['rr'] . '.' . $drow['name'];
        }
        if ($action == 1) {
            if ($row['type'] == 2) {
                $dns = DnsHelper::getModel2($drow);
                $recordinfo = json_decode($row['recordinfo'], true);
                if ($drow['type'] == 'cloudflare' && $row['cdn'] == 1) {
                    $recordinfo['Line'] = '1';
                }
                $res = $dns->updateDomainRecord($row['recordid'], $row['rr'], getDnsType($row['backup_value']), $row['backup_value'], $recordinfo['Line'], $recordinfo['TTL']);
                if (!$res) {
                    $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '修改解析失败', 'data' => $dns->getError(), 'addtime' => date("Y-m-d H:i:s")]);
                } else {
                    $ip = isset($row['backup_value']) && filter_var(trim($row['backup_value']), FILTER_VALIDATE_IP) ? trim($row['backup_value']) : '';
                    $this->runHookOnAction($row, $drow, $ip);
                }
            } elseif ($row['type'] == 1 || $row['type'] == 3) {
                $dns = DnsHelper::getModel2($drow);
                $res = $dns->setDomainRecordStatus($row['recordid'], '0');
                if (!$res) {
                    $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '暂停解析失败', 'data' => $dns->getError(), 'addtime' => date("Y-m-d H:i:s")]);
                } else {
                    $ip = isset($row['main_value']) && filter_var(trim($row['main_value']), FILTER_VALIDATE_IP) ? trim($row['main_value']) : '';
                    $this->runHookOnAction($row, $drow, $ip);
                }
            }
        } elseif ($action == 2) {
            if ($row['type'] == 2) {
                $dns = DnsHelper::getModel2($drow);
                $recordinfo = json_decode($row['recordinfo'], true);
                if ($drow['type'] == 'cloudflare' && $row['cdn'] == 1) {
                    $recordinfo['Line'] = '0';
                }
                $res = $dns->updateDomainRecord($row['recordid'], $row['rr'], getDnsType($row['main_value']), $row['main_value'], $recordinfo['Line'], $recordinfo['TTL']);
                if (!$res) {
                    $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '修改解析失败', 'data' => $dns->getError(), 'addtime' => date("Y-m-d H:i:s")]);
                }
            } elseif ($row['type'] == 1 || $row['type'] == 3) {
                $dns = DnsHelper::getModel2($drow);
                $res = $dns->setDomainRecordStatus($row['recordid'], '1');
                if (!$res) {
                    $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '启用解析失败', 'data' => $dns->getError(), 'addtime' => date("Y-m-d H:i:s")]);
                }
            }
        } else {
            $this->closeDb();
            return;
        }

        $this->db()->name('dmlog')->insert([
            'taskid' => $row['id'],
            'action' => $action,
            'errmsg' => isset($result) ? ($result['status'] ? null : $result['errmsg']) : null,
            'date' => date('Y-m-d H:i:s')
        ]);
        $this->closeDb();

        if ($row['type'] != 3) {
            MsgNotice::send($action, $row, $result);
        }
    }

    /**
     * 切换/暂停操作成功后执行Hook命令（策略级别）
     * 仅支持单行curl命令；{ip} 可选替换；不允许管道/重定向/多命令
     */
    private function runHookOnAction($task, $drow, $ip = '')
    {
        if (empty($task['hook_enable']) || intval($task['hook_enable']) !== 1) {
            return;
        }
        $cmd = isset($task['hook_cmd']) ? trim((string)$task['hook_cmd']) : '';
        if ($cmd === '') {
            return;
        }
        if (preg_match("/\r|\n/", $cmd)) {
            $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '切换备用Hook跳过', 'data' => 'Hook命令包含换行', 'addtime' => date("Y-m-d H:i:s")]);
            return;
        }
        if (!preg_match('/^\s*curl\s+/i', $cmd)) {
            $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '切换备用Hook跳过', 'data' => 'Hook命令不以curl开头', 'addtime' => date("Y-m-d H:i:s")]);
            return;
        }
        if (preg_match('/[`]|\\$\\(|\\|\\||&&|[|;><]/', $cmd)) {
            $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '切换备用Hook跳过', 'data' => 'Hook命令包含不安全字符', 'addtime' => date("Y-m-d H:i:s")]);
            return;
        }

        $execCmd = str_replace('{ip}', $ip, $cmd);
        $timeoutSec = 20;
        $start = microtime(true);
        $killedByTimeout = false;

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = @proc_open($execCmd, $descriptors, $pipes);
        if (!is_resource($process)) {
            $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '切换备用Hook失败', 'data' => '无法启动进程', 'addtime' => date("Y-m-d H:i:s")]);
            return;
        }
        @fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        while (true) {
            $status = proc_get_status($process);
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);

            if (!$status['running']) {
                break;
            }
            if (microtime(true) - $start > $timeoutSec) {
                $killedByTimeout = true;
                @proc_terminate($process, 9);
                break;
            }
            usleep(100 * 1000);
        }

        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
        @fclose($pipes[1]);
        @fclose($pipes[2]);
        $exitCode = proc_close($process);

        $stdout = trim($stdout);
        $stderr = trim($stderr);
        $maxOut = 2000;
        if (strlen($stdout) > $maxOut) $stdout = substr($stdout, 0, $maxOut) . "\n...(截断)";
        if (strlen($stderr) > $maxOut) $stderr = substr($stderr, 0, $maxOut) . "\n...(截断)";

        $costMs = (int)round((microtime(true) - $start) * 1000);
        $cmdForLog = preg_replace('/-H\s*["\']token:\s*[^"\']*["\']/i', '-H "token: ***"', $execCmd);
        $cmdForLog = preg_replace('/-H\s*["\']Authorization:\s*[^"\']*["\']/i', '-H "Authorization: ***"', $cmdForLog);

        $lines = [
            'taskid=' . (isset($task['id']) ? (int)$task['id'] : ''),
            'timeout_sec=' . $timeoutSec,
            'timeout_killed=' . ($killedByTimeout ? '1' : '0'),
            'exit=' . $exitCode,
            'cost_ms=' . $costMs,
            'cmd=' . $cmdForLog,
        ];
        if ($stdout !== '') $lines[] = 'stdout=' . $stdout;
        if ($stderr !== '') $lines[] = 'stderr=' . $stderr;
        $data = implode("\n", $lines);
        $this->db()->name('log')->insert(['uid' => 0, 'domain' => $drow['name'], 'action' => '切换备用Hook执行', 'data' => $data, 'addtime' => date("Y-m-d H:i:s")]);
    }
}
