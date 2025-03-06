<?php
namespace Security;

class IPSecurityLibrary {
    private $ipInfo;
    private $config;
    private $cache;
    private static $instance = null;
    
    private const CACHE_DURATION = 3600; // 1 saat
    
    private $asnDatabase;
    private $datacenterDatabase;
    
    private function __construct(array $config = []) {
        $this->config = array_merge([
            'cache_enabled' => true,
            'geolocation_provider' => 'ip-api',
            'log_enabled' => true,
            'log_path' => 'security_logs/',
            'proxy_check_enabled' => true,
            'tor_check_enabled' => true,
            'vpn_check_enabled' => true,
            'asn_database_path' => 'databases/IP2LOCATION-LITE-ASN.CSV',
            'datacenter_database_path' => 'databases/IP2LOCATION-DATACENTER.CSV',
            'risk_threshold' => [
                'low' => 2,
                'medium' => 0,
                'high' => -2
            ],
            'api_keys' => [
                'maxmind' => '',
                'ipqualityscore' => '',
                'proxycheck' => ''
            ]
        ], $config);
        
        $this->initializeCache();
        $this->initializeLogs();
        $this->initializeASNDatabase();
    }
    
    public static function getInstance(array $config = []): self {
        if (self::$instance === null) {
            self::$instance = new self($config);
        }
        return self::$instance;
    }
    
    private function initializeCache(): void {
        if ($this->config['cache_enabled']) {
            $this->cache = new SimpleCache('cache/');
        }
    }
    
    private function initializeLogs(): void {
        if ($this->config['log_enabled']) {
            if (!is_dir($this->config['log_path'])) {
                mkdir($this->config['log_path'], 0755, true);
            }
        }
    }
    
    private function initializeASNDatabase(): void {
        if (file_exists($this->config['asn_database_path'])) {
            $this->asnDatabase = new \SplFileObject($this->config['asn_database_path']);
            $this->asnDatabase->setFlags(\SplFileObject::READ_CSV);
        }
        
        if (file_exists($this->config['datacenter_database_path'])) {
            $this->datacenterDatabase = new \SplFileObject($this->config['datacenter_database_path']);
            $this->datacenterDatabase->setFlags(\SplFileObject::READ_CSV);
        }
    }
    
    private function getASNInfoFromDatabase(string $ip): ?array {
        if (!$this->asnDatabase) {
            return null;
        }
        
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return null;
        }
        
        $this->asnDatabase->rewind();
        while (!$this->asnDatabase->eof()) {
            $row = $this->asnDatabase->fgetcsv();
            if (!$row) continue;
            
            $startIp = ip2long($row[0]);
            $endIp = ip2long($row[1]);
            
            if ($ipLong >= $startIp && $ipLong <= $endIp) {
                return [
                    'asn' => 'AS' . $row[2],
                    'organization' => $row[3],
                    'isp' => $row[3]
                ];
            }
        }
        
        return null;
    }
    
    private function isDatacenterFromDatabase(string $ip): bool {
        if (!$this->datacenterDatabase) {
            return false;
        }
        
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return false;
        }
        
        $this->datacenterDatabase->rewind();
        while (!$this->datacenterDatabase->eof()) {
            $row = $this->datacenterDatabase->fgetcsv();
            if (!$row) continue;
            
            $startIp = ip2long($row[0]);
            $endIp = ip2long($row[1]);
            
            if ($ipLong >= $startIp && $ipLong <= $endIp) {
                return true;
            }
        }
        
        return false;
    }
    
    private function getASNInfoFromBGPTools(string $ip): ?array {
        try {
            $url = "https://bgp.tools/api/v1/ip/{$ip}";
            $response = @file_get_contents($url);
            
            if ($response === false) {
                return null;
            }
            
            $data = json_decode($response, true);
            if (!$data) {
                return null;
            }
            
            return [
                'asn' => 'AS' . ($data['asn'] ?? ''),
                'organization' => $data['name'] ?? '',
                'isp' => $data['name'] ?? ''
            ];
        } catch (\Exception $e) {
            $this->logError('BGP.Tools Error: ' . $e->getMessage());
            return null;
        }
    }

    private function getASNInfoFromTeamCymru(string $ip): ?array {
        try {
            $socket = fsockopen("whois.cymru.com", 43, $errno, $errstr, 10);
            if (!$socket) {
                return null;
            }
            
            fwrite($socket, "begin\nverbose\n{$ip}\nend\n");
            $response = '';
            while (!feof($socket)) {
                $response .= fgets($socket, 128);
            }
            fclose($socket);
            
            // Yanıtı parse et
            $lines = explode("\n", trim($response));
            if (count($lines) < 2) {
                return null;
            }
            
            $data = str_getcsv(trim($lines[1]), '|');
            if (count($data) < 3) {
                return null;
            }
            
            return [
                'asn' => 'AS' . trim($data[0]),
                'organization' => trim($data[2]),
                'isp' => trim($data[2])
            ];
        } catch (\Exception $e) {
            $this->logError('Team Cymru Error: ' . $e->getMessage());
            return null;
        }
    }

    private function getASNInfo(string $ip): ?array {
        // Önce BGP.Tools'u dene
        $asnInfo = $this->getASNInfoFromBGPTools($ip);
        if ($asnInfo) {
            return $asnInfo;
        }
        
        // BGP.Tools başarısız olursa Team Cymru'yu dene
        $asnInfo = $this->getASNInfoFromTeamCymru($ip);
        if ($asnInfo) {
            return $asnInfo;
        }
        
        // Son çare olarak IP-API'yi dene
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=as,org,isp";
            $response = @file_get_contents($url);
            
            if ($response === false) {
                return null;
            }
            
            $data = json_decode($response, true);
            if (!$data) {
                return null;
            }
            
            $asn = '';
            if (preg_match('/^AS(\d+)\s/', $data['as'] ?? '', $matches)) {
                $asn = 'AS' . $matches[1];
            }
            
            return [
                'asn' => $asn,
                'organization' => $data['org'] ?? '',
                'isp' => $data['isp'] ?? ''
            ];
        } catch (\Exception $e) {
            $this->logError('ASN Info Error: ' . $e->getMessage());
            return null;
        }
    }
    
    private function isDatacenter(string $ip): bool {
        // Önce veritabanından kontrol et
        if ($this->isDatacenterFromDatabase($ip)) {
            return true;
        }
        
        // Datacenter IP aralıkları ve belirteçleri
        $datacenterPatterns = [
            // Amazon AWS
            '/^(13\.32\.0\.0|13\.33\.0\.0|13\.34\.0\.0|13\.35\.0\.0|52\.92\.0\.0|52\.93\.0\.0|52\.94\.0\.0|52\.95\.0\.0|54\.230\.0\.0|54\.231\.0\.0|54\.239\.0\.0|54\.240\.0\.0|204\.246\.0\.0|205\.251\.192\.0|205\.251\.224\.0|205\.251\.240\.0|205\.251\.244\.0|205\.251\.247\.0|205\.251\.248\.0|207\.171\.160\.0|207\.171\.176\.0|216\.137\.32\.0|216\.182\.224\.0|216\.182\.232\.0|216\.182\.236\.0|216\.182\.238\.0)/',
            
            // Google Cloud
            '/^(34\.64\.0\.0|34\.65\.0\.0|34\.66\.0\.0|34\.67\.0\.0|34\.68\.0\.0|34\.69\.0\.0|34\.70\.0\.0|34\.71\.0\.0|34\.72\.0\.0|34\.73\.0\.0|34\.74\.0\.0|34\.75\.0\.0|34\.76\.0\.0|34\.77\.0\.0|34\.78\.0\.0|34\.79\.0\.0|34\.80\.0\.0|34\.81\.0\.0|34\.82\.0\.0|34\.83\.0\.0|34\.84\.0\.0|34\.85\.0\.0|34\.86\.0\.0|34\.87\.0\.0|34\.88\.0\.0|34\.89\.0\.0|34\.90\.0\.0|34\.91\.0\.0|34\.92\.0\.0|34\.93\.0\.0|34\.94\.0\.0|34\.95\.0\.0|34\.96\.0\.0|34\.97\.0\.0|34\.98\.0\.0|34\.99\.0\.0|34\.100\.0\.0|34\.101\.0\.0|34\.102\.0\.0|34\.103\.0\.0|34\.104\.0\.0)/',
            
            // Microsoft Azure
            '/^(13\.64\.0\.0|13\.65\.0\.0|13\.66\.0\.0|13\.67\.0\.0|13\.68\.0\.0|13\.69\.0\.0|13\.70\.0\.0|13\.71\.0\.0|13\.72\.0\.0|13\.73\.0\.0|13\.74\.0\.0|13\.75\.0\.0|13\.76\.0\.0|13\.77\.0\.0|13\.78\.0\.0|13\.79\.0\.0|13\.80\.0\.0|13\.81\.0\.0|13\.82\.0\.0|13\.83\.0\.0|13\.84\.0\.0|13\.85\.0\.0|13\.86\.0\.0|13\.87\.0\.0|13\.88\.0\.0|13\.89\.0\.0|13\.90\.0\.0|13\.91\.0\.0|13\.92\.0\.0|13\.93\.0\.0)/'
        ];
        
        // IP adresini noktalı ondalık formatından long'a çevir
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return false;
        }
        
        // Datacenter IP aralıklarını kontrol et
        foreach ($datacenterPatterns as $pattern) {
            if (preg_match($pattern, $ip)) {
                return true;
            }
        }
        
        // ASN kontrolü (Autonomous System Number)
        $asnInfo = $this->getASNInfo($ip);
        if ($asnInfo) {
            // Bilinen datacenter ASN'lerini kontrol et
            $datacenterASNs = [
                // Türk Datacenter/Hosting Sağlayıcıları
                'AS201079', // GarantiServer Cloud
                'AS211557', // GarantiServer Datacenter
                'AS207216', // GarantiServer Network
                'AS43391',  // Netdirekt A.S.
                'AS34619',  // Cizgi Telekom
                'AS44640',  // Cizgi Datacenter
                'AS203566', // CIZGI Teknoloji
                'AS48678',  // Nethouse
                'AS205668', // Radore Veri Merkezi
                'AS42926',  // Radore Hosting
                'AS203032', // TUNCMATIK Cloud
                'AS203087', // Hetzner Turkiye
                'AS62240',  // Clouvider Turkiye
                'AS211843', // Teknotel Telekom
                'AS206667', // Hostlab Bilisim
                'AS213021', // GAZIOSMAN Cloud
                'AS199484', // SAGLAYICI Datacenter
                'AS206428', // METRONET Datacenter
                'AS212235', // DEPO Datacenter
                'AS205651'  // METRONET Cloud
            ];
            
            if (in_array($asnInfo['asn'], $datacenterASNs)) {
                return true;
            }
            
            // ASN organizasyon adında datacenter belirteçlerini kontrol et
            $datacenterKeywords = [
                'hosting', 'cloud', 'datacenter', 'data center', 'server', 'vps', 'virtual', 
                'dedicated', 'managed', 'colocation', 'wholesale', 'infrastructure', 'platform',
                'aws', 'azure', 'google', 'alibaba', 'tencent', 'baidu', 'oracle', 'ibm', 
                'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'scaleway', 'rackspace'
            ];
            
            foreach ($datacenterKeywords as $keyword) {
                if (stripos($asnInfo['organization'], $keyword) !== false) {
                    return true;
                }
            }
        }
        
        return false;
    }

    public function analyzeIP(string $ip = null): array {
        if ($ip === null) {
            $ip = $this->getClientIP();
        }
        
        $cacheKey = 'ip_analysis_' . md5($ip);
        
        // Cache kontrolü
        if ($this->config['cache_enabled'] && $this->cache->has($cacheKey)) {
            return $this->cache->get($cacheKey);
        }
        
        $analysis = [
            'ip' => $ip,
            'timestamp' => time(),
            'basic_checks' => $this->performBasicChecks($ip),
            'geolocation' => $this->getGeolocationData($ip),
            'security_checks' => $this->performSecurityChecks($ip),
            'risk_assessment' => $this->assessRisk($ip),
            'device_info' => $this->getDeviceInfo(),
            'browser_info' => $this->getBrowserInfo(),
            'screen_info' => $this->getScreenInfo(),
            'language_info' => $this->getClientLanguage(),
            'timezone_info' => $this->getClientTimezone(),
            'operating_system' => $this->getOperatingSystem(),
            'network_info' => [
                'is_datacenter' => $this->isDatacenter($ip),
                'is_isp' => $this->isISP($ip),
                'asn_info' => $this->getASNInfo($ip),
                'proxy_type' => $this->getProxyType($ip),
                'usage_type' => $this->getUsageType($ip),
                'fraud_score' => $this->getFraudScore($ip)
            ]
        ];
        
        // Sonuçları cache'le
        if ($this->config['cache_enabled']) {
            $this->cache->set($cacheKey, $analysis, self::CACHE_DURATION);
        }
        
        $this->logAnalysis($analysis);
        
        return $analysis;
    }

    private function getClientIP(): string {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (isset($_SERVER['HTTP_CLIENT_IP']) && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        }
        
        return $ip;
    }

    private function performBasicChecks(string $ip): array {
        return [
            'is_valid' => filter_var($ip, FILTER_VALIDATE_IP),
            'is_public' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE),
            'version' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 6 : 4
        ];
    }

    private function getGeolocationData(string $ip): array {
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
            $response = @file_get_contents($url);
            
            if ($response === false) {
                return [];
            }
            
            $data = json_decode($response, true);
            if (!$data || $data['status'] === 'fail') {
                return [];
            }
            
            return $data;
        } catch (\Exception $e) {
            $this->logError('Geolocation Error: ' . $e->getMessage());
            return [];
        }
    }

    private function performSecurityChecks(string $ip): array {
        $checks = [
            'is_proxy' => false,
            'is_vpn' => false,
            'is_tor' => false,
            'is_bot' => false,
            'is_spam' => false,
            'is_attack_source' => false,
            'blacklist_status' => []
        ];
        
        // Proxy kontrolü
        if ($this->config['proxy_check_enabled']) {
            $checks['is_proxy'] = $this->checkProxy($ip);
        }
        
        // VPN kontrolü
        if ($this->config['vpn_check_enabled']) {
            $checks['is_vpn'] = $this->checkVPN($ip);
        }
        
        // Tor kontrolü
        if ($this->config['tor_check_enabled']) {
            $checks['is_tor'] = $this->checkTor($ip);
        }
        
        // Bot kontrolü
        $checks['is_bot'] = $this->checkBot();
        
        // Spam kontrolü
        $checks['is_spam'] = $this->checkSpam($ip);
        
        // Saldırı kaynağı kontrolü
        $checks['is_attack_source'] = $this->checkAttackSource($ip);
        
        // Kara liste kontrolü
        $checks['blacklist_status'] = $this->checkBlacklists($ip);
        
        return $checks;
    }

    private function checkProxy(string $ip): bool {
        try {
            // 1. IP-API kontrolü
            $url = "http://ip-api.com/json/{$ip}?fields=proxy,status";
            $response = @file_get_contents($url);
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['status']) && $data['status'] === 'success' && isset($data['proxy']) && $data['proxy'] === true) {
                    return true;
                }
            }

            // 2. ProxyCheck.io kontrolü
            if ($this->config['api_keys']['proxycheck']) {
                $url = "http://proxycheck.io/v2/{$ip}?key=" . $this->config['api_keys']['proxycheck'] . "&vpn=1&risk=1";
                $response = @file_get_contents($url);
                if ($response !== false) {
                    $data = json_decode($response, true);
                    if ($data && isset($data[$ip]['proxy']) && $data[$ip]['proxy'] === 'yes') {
                        return true;
                    }
                }
            }

            // 3. GetIPIntel kontrolü
            $contactEmail = "info@example.com"; // Kendi e-posta adresinizi girin
            $url = "http://check.getipintel.net/check.php?ip={$ip}&contact={$contactEmail}";
            $response = @file_get_contents($url);
            if ($response !== false && is_numeric($response) && floatval($response) > 0.95) {
                return true;
            }

            // 4. Proxy port kontrolü
            $commonProxyPorts = [80, 81, 83, 88, 8080, 8081, 8888, 3128];
            foreach ($commonProxyPorts as $port) {
                $connection = @fsockopen($ip, $port, $errno, $errstr, 1);
                if ($connection) {
                    fclose($connection);
                    return true;
                }
            }

            // 5. DNS blacklist kontrolü
            $reverseIp = implode('.', array_reverse(explode('.', $ip)));
            $proxyBlacklists = [
                'dnsbl.httpbl.org',
                'proxy.bl.gweep.ca',
                'proxy.block.transip.nl',
                'proxy.mind.net.pl'
            ];

            foreach ($proxyBlacklists as $bl) {
                if (checkdnsrr("{$reverseIp}.{$bl}.", 'A')) {
                    return true;
                }
            }

            // 6. HTTP başlık kontrolü
            $headers = @get_headers("http://{$ip}", 1);
            if ($headers) {
                $proxyHeaders = [
                    'HTTP_VIA',
                    'HTTP_X_FORWARDED_FOR',
                    'HTTP_FORWARDED',
                    'HTTP_X_FORWARDED',
                    'HTTP_X_CLUSTER_CLIENT_IP',
                    'HTTP_FORWARDED_FOR',
                    'HTTP_FORWARDED_FOR_IP',
                    'VIA',
                    'X_FORWARDED_FOR',
                    'FORWARDED',
                    'FORWARDED_FOR',
                    'X-FORWARDED-FOR',
                    'CLIENT-IP',
                    'PROXY-CONNECTION'
                ];

                foreach ($proxyHeaders as $header) {
                    if (isset($headers[$header])) {
                        return true;
                    }
                }
            }

            // 7. Proxy belirteçleri kontrolü
            $asnInfo = $this->getASNInfo($ip);
            if ($asnInfo) {
                $proxyKeywords = [
                    'proxy', 'vpn', 'tor', 'relay', 'anonymous', 'hide', 
                    'mask', 'tunnel', 'privacy', 'private', 'secure', 
                    'hidden', 'exit node', 'datacenter'
                ];

                $org = strtolower($asnInfo['organization']);
                foreach ($proxyKeywords as $keyword) {
                    if (strpos($org, $keyword) !== false) {
                        return true;
                    }
                }
            }

            return false;

        } catch (\Exception $e) {
            $this->logError('Proxy Check Error: ' . $e->getMessage());
            return false;
        }
    }

    private function checkVPN(string $ip): bool {
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=hosting";
            $response = @file_get_contents($url);
            
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['hosting']) && $data['hosting'] === true) {
                    return true;
                }
            }
        } catch (\Exception $e) {
            $this->logError('VPN Check Error: ' . $e->getMessage());
        }
        
        return false;
    }

    private function checkTor(string $ip): bool {
        try {
            $url = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1";
            $response = @file_get_contents($url);
            
            if ($response !== false) {
                $exitNodes = explode("\n", $response);
                return in_array($ip, $exitNodes);
            }
        } catch (\Exception $e) {
            $this->logError('Tor Check Error: ' . $e->getMessage());
        }
        
        return false;
    }

    private function checkBot(): bool {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $botPatterns = [
            'bot', 'spider', 'crawler', 'scraper',
            'googlebot', 'bingbot', 'yandexbot', 'baiduspider',
            'facebookexternalhit', 'twitterbot', 'rogerbot',
            'linkedinbot', 'embedly', 'quora link preview',
            'showyoubot', 'outbrain', 'pinterest', 'slackbot',
            'vkShare', 'W3C_Validator'
        ];
        
        foreach ($botPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }

    private function checkSpam(string $ip): bool {
        try {
            // Spamhaus kontrolü
            $reverseIp = implode('.', array_reverse(explode('.', $ip)));
            $dnsbl_lookup = $reverseIp . '.zen.spamhaus.org';
            
            if (checkdnsrr($dnsbl_lookup, 'A')) {
                return true;
            }
        } catch (\Exception $e) {
            $this->logError('Spam Check Error: ' . $e->getMessage());
        }
        
        return false;
    }

    private function checkAttackSource(string $ip): bool {
        try {
            // AbuseIPDB kontrolü
            if ($this->config['api_keys']['abuseipdb']) {
                $url = "https://api.abuseipdb.com/api/v2/check";
                $options = [
                    'http' => [
                        'header' => "Key: " . $this->config['api_keys']['abuseipdb'] . "\r\n" .
                                  "Accept: application/json\r\n"
                    ]
                ];
                
                $context = stream_context_create($options);
                $response = @file_get_contents($url . "?ipAddress=" . $ip, false, $context);
                
                if ($response !== false) {
                    $data = json_decode($response, true);
                    if ($data && isset($data['data']['abuseConfidenceScore']) && $data['data']['abuseConfidenceScore'] > 50) {
                        return true;
                    }
                }
            }
        } catch (\Exception $e) {
            $this->logError('Attack Source Check Error: ' . $e->getMessage());
        }
        
        return false;
    }

    private function checkBlacklists(string $ip): array {
        $blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'cbl.abuseat.org',
            'dnsbl.sorbs.net',
            'b.barracudacentral.org'
        ];
        
        $results = [];
        $reverseIp = implode('.', array_reverse(explode('.', $ip)));
        
        foreach ($blacklists as $bl) {
            try {
                $host = $reverseIp . '.' . $bl;
                if (checkdnsrr($host, 'A')) {
                    $results[$bl] = true;
                } else {
                    $results[$bl] = false;
                }
            } catch (\Exception $e) {
                $this->logError("Blacklist Check Error ({$bl}): " . $e->getMessage());
                $results[$bl] = null;
            }
        }
        
        return $results;
    }

    private function assessRisk(string $ip): array {
        $score = 0;
        $factors = [];
        
        // Temel kontroller
        $basicChecks = $this->performBasicChecks($ip);
        if (!$basicChecks['is_valid']) {
            $score -= 5;
            $factors[] = 'invalid_ip';
        }
        if (!$basicChecks['is_public']) {
            $score -= 3;
            $factors[] = 'private_ip';
        }
        
        // Güvenlik kontrolleri
        $securityChecks = $this->performSecurityChecks($ip);
        if ($securityChecks['is_proxy']) {
            $score -= 2;
            $factors[] = 'proxy_detected';
        }
        if ($securityChecks['is_vpn']) {
            $score -= 2;
            $factors[] = 'vpn_detected';
        }
        if ($securityChecks['is_tor']) {
            $score -= 3;
            $factors[] = 'tor_detected';
        }
        if ($securityChecks['is_bot']) {
            $score -= 1;
            $factors[] = 'bot_detected';
        }
        if ($securityChecks['is_spam']) {
            $score -= 4;
            $factors[] = 'spam_source';
        }
        if ($securityChecks['is_attack_source']) {
            $score -= 5;
            $factors[] = 'attack_source';
        }
        
        // Kara liste kontrolleri
        foreach ($securityChecks['blacklist_status'] as $bl => $status) {
            if ($status === true) {
                $score -= 2;
                $factors[] = 'blacklisted_' . $bl;
            }
        }
        
        // Datacenter kontrolü
        if ($this->isDatacenter($ip)) {
            $score -= 1;
            $factors[] = 'datacenter_ip';
        }
        
        // Risk seviyesi belirleme
        $riskLevel = 'low';
        if ($score <= $this->config['risk_threshold']['high']) {
            $riskLevel = 'high';
        } elseif ($score <= $this->config['risk_threshold']['medium']) {
            $riskLevel = 'medium';
        }
        
        return [
            'score' => $score,
            'level' => $riskLevel,
            'factors' => $factors
        ];
    }

    private function getDeviceInfo(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        return [
            'type' => $this->getDeviceType($userAgent),
            'brand' => $this->getDeviceBrand($userAgent),
            'model' => $this->getDeviceModel($userAgent)
        ];
    }

    private function getDeviceType(string $userAgent): string {
        $mobileKeywords = ['Mobile', 'Android', 'iPhone', 'iPad', 'Windows Phone'];
        $tabletKeywords = ['iPad', 'Tablet', 'Kindle'];
        
        foreach ($tabletKeywords as $keyword) {
            if (stripos($userAgent, $keyword) !== false) {
                return 'tablet';
            }
        }
        
        foreach ($mobileKeywords as $keyword) {
            if (stripos($userAgent, $keyword) !== false) {
                return 'mobile';
            }
        }
        
        return 'desktop';
    }

    private function getDeviceBrand(string $userAgent): string {
        $brands = [
            'Apple' => ['iPhone', 'iPad', 'iPod'],
            'Samsung' => ['Samsung'],
            'Huawei' => ['Huawei'],
            'Xiaomi' => ['Xiaomi', 'Redmi'],
            'OnePlus' => ['OnePlus'],
            'LG' => ['LG'],
            'Sony' => ['Sony'],
            'HTC' => ['HTC'],
            'Google' => ['Pixel'],
            'Microsoft' => ['Windows Phone']
        ];
        
        foreach ($brands as $brand => $keywords) {
            foreach ($keywords as $keyword) {
                if (stripos($userAgent, $keyword) !== false) {
                    return $brand;
                }
            }
        }
        
        return 'Unknown';
    }

    private function getDeviceModel(string $userAgent): string {
        // iPhone model tespiti
        if (preg_match('/iPhone\s*(\d+,\d+)/', $userAgent, $matches)) {
            return 'iPhone ' . $matches[1];
        }
        
        // iPad model tespiti
        if (preg_match('/iPad\s*(\d+,\d+)/', $userAgent, $matches)) {
            return 'iPad ' . $matches[1];
        }
        
        // Android cihaz model tespiti
        if (preg_match('/;\s*([^;)]+(?:(?!Build)\S)*)(?:\s*Build|\))/', $userAgent, $matches)) {
            return trim($matches[1]);
        }
        
        return 'Unknown';
    }

    private function getBrowserInfo(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        return [
            'name' => $this->getBrowserName($userAgent),
            'version' => $this->getBrowserVersion($userAgent),
            'engine' => $this->getBrowserEngine($userAgent)
        ];
    }

    private function getBrowserName(string $userAgent): string {
        $browsers = [
            'Edge' => 'Edg',
            'Chrome' => 'Chrome',
            'Firefox' => 'Firefox',
            'Safari' => 'Safari',
            'Opera' => 'OPR',
            'IE' => 'MSIE|Trident'
        ];
        
        foreach ($browsers as $browser => $pattern) {
            if (preg_match("/{$pattern}/i", $userAgent)) {
                return $browser;
            }
        }
        
        return 'Unknown';
    }

    private function getBrowserVersion(string $userAgent): string {
        $browser = $this->getBrowserName($userAgent);
        
        switch ($browser) {
            case 'Edge':
                preg_match('/Edg\/([\d.]+)/', $userAgent, $matches);
                break;
            case 'Chrome':
                preg_match('/Chrome\/([\d.]+)/', $userAgent, $matches);
                break;
            case 'Firefox':
                preg_match('/Firefox\/([\d.]+)/', $userAgent, $matches);
                break;
            case 'Safari':
                preg_match('/Version\/([\d.]+)/', $userAgent, $matches);
                break;
            case 'Opera':
                preg_match('/OPR\/([\d.]+)/', $userAgent, $matches);
                break;
            case 'IE':
                preg_match('/(MSIE|rv:)\s?([\d.]+)/', $userAgent, $matches);
                break;
            default:
                return 'Unknown';
        }
        
        return $matches[1] ?? 'Unknown';
    }

    private function getBrowserEngine(string $userAgent): string {
        if (stripos($userAgent, 'Gecko') !== false) {
            return 'Gecko';
        } elseif (stripos($userAgent, 'WebKit') !== false) {
            return 'WebKit';
        } elseif (stripos($userAgent, 'Trident') !== false) {
            return 'Trident';
        } elseif (stripos($userAgent, 'Presto') !== false) {
            return 'Presto';
        }
        
        return 'Unknown';
    }

    private function getScreenInfo(): array {
        return [
            'width' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM_WIDTH'] ?? null,
            'height' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM_HEIGHT'] ?? null,
            'color_depth' => $_SERVER['HTTP_SEC_CH_UA_COLOR_DEPTH'] ?? null,
            'pixel_ratio' => $_SERVER['HTTP_SEC_CH_UA_PIXEL_RATIO'] ?? null
        ];
    }

    private function getClientLanguage(): array {
        $languages = [];
        
        if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $langs = explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']);
            
            foreach ($langs as $lang) {
                $parts = explode(';', $lang);
                $code = trim($parts[0]);
                $q = isset($parts[1]) ? (float) str_replace('q=', '', $parts[1]) : 1.0;
                
                $languages[] = [
                    'code' => $code,
                    'quality' => $q
                ];
            }
            
            usort($languages, function($a, $b) {
                return $b['quality'] <=> $a['quality'];
            });
        }
        
        return [
            'preferred' => $languages[0]['code'] ?? null,
            'all' => $languages
        ];
    }

    private function getClientTimezone(): array {
        return [
            'name' => $_SERVER['HTTP_SEC_CH_UA_TIMEZONE'] ?? null,
            'offset' => $_SERVER['HTTP_SEC_CH_UA_TIMEZONE_OFFSET'] ?? null
        ];
    }

    private function getOperatingSystem(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $os = [
            'name' => $this->getOSName($userAgent),
            'version' => $this->getOSVersion($userAgent),
            'architecture' => $this->getOSArchitecture()
        ];
        
        return $os;
    }

    private function getOSName(string $userAgent): string {
        $os = [
            'Windows' => 'Windows',
            'Mac' => 'Mac OS X|Macintosh',
            'Linux' => 'Linux',
            'Ubuntu' => 'Ubuntu',
            'Android' => 'Android',
            'iOS' => 'iPhone|iPad|iPod'
        ];
        
        foreach ($os as $name => $pattern) {
            if (preg_match("/{$pattern}/i", $userAgent)) {
                return $name;
            }
        }
        
        return 'Unknown';
    }

    private function getOSVersion(string $userAgent): string {
        $os = $this->getOSName($userAgent);
        
        switch ($os) {
            case 'Windows':
                preg_match('/Windows NT ([\d.]+)/', $userAgent, $matches);
                $versions = [
                    '10.0' => '10',
                    '6.3' => '8.1',
                    '6.2' => '8',
                    '6.1' => '7',
                    '6.0' => 'Vista',
                    '5.2' => 'XP x64',
                    '5.1' => 'XP'
                ];
                return $versions[$matches[1] ?? ''] ?? $matches[1] ?? 'Unknown';
                
            case 'Mac':
                preg_match('/Mac OS X ([\d_.]+)/', $userAgent, $matches);
                return str_replace('_', '.', $matches[1] ?? 'Unknown');
                
            case 'Android':
                preg_match('/Android ([\d.]+)/', $userAgent, $matches);
                return $matches[1] ?? 'Unknown';
                
            case 'iOS':
                preg_match('/OS ([\d_]+)/', $userAgent, $matches);
                return str_replace('_', '.', $matches[1] ?? 'Unknown');
                
            default:
                return 'Unknown';
        }
    }

    private function getOSArchitecture(): string {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        if (stripos($userAgent, 'x64') !== false || stripos($userAgent, 'x86_64') !== false || stripos($userAgent, 'Win64') !== false || stripos($userAgent, 'amd64') !== false) {
            return '64-bit';
        }
        
        if (stripos($userAgent, 'x86') !== false || stripos($userAgent, 'Win32') !== false) {
            return '32-bit';
        }
        
        return 'Unknown';
    }

    private function isISP(string $ip): bool {
        $asnInfo = $this->getASNInfo($ip);
        if (!$asnInfo) {
            return false;
        }
        
        // ISP belirteçleri
        $ispKeywords = [
            'isp', 'telecom', 'telekom', 'communication', 'broadband',
            'internet', 'network', 'telco', 'provider', 'cable',
            'wireless', 'mobile', 'cellular', 'fiber', 'dsl'
        ];
        
        // Türk ISP'leri
        $turkishISPs = [
            'turk telekom', 'turknet', 'superonline',
            'vodafone', 'turkcell', 'millenicom', 'kablonet'
        ];
        
        $org = strtolower($asnInfo['organization']);
        $isp = strtolower($asnInfo['isp']);
        
        // Türk ISP kontrolü
        foreach ($turkishISPs as $turkishISP) {
            if (strpos($org, $turkishISP) !== false || strpos($isp, $turkishISP) !== false) {
                return true;
            }
        }
        
        // Genel ISP kontrolü
        foreach ($ispKeywords as $keyword) {
            if (strpos($org, $keyword) !== false || strpos($isp, $keyword) !== false) {
                return true;
            }
        }
        
        return false;
    }

    private function getProxyType(string $ip): ?string {
        try {
            if ($this->config['api_keys']['proxycheck']) {
                $url = "http://proxycheck.io/v2/{$ip}?key=" . $this->config['api_keys']['proxycheck'] . "&vpn=1&risk=1";
                $response = @file_get_contents($url);
                
                if ($response !== false) {
                    $data = json_decode($response, true);
                    if ($data && isset($data[$ip]['type'])) {
                        return $data[$ip]['type'];
                    }
                }
            }
        } catch (\Exception $e) {
            $this->logError('Proxy Type Check Error: ' . $e->getMessage());
        }
        
        return null;
    }

    private function getUsageType(string $ip): string {
        // ISP kontrolü
        if ($this->isISP($ip)) {
            return 'ISP';
        }
        
        // Datacenter kontrolü
        if ($this->isDatacenter($ip)) {
            return 'DCH';
        }
        
        // ASN bilgisini al
        $asnInfo = $this->getASNInfo($ip);
        if ($asnInfo) {
            $org = strtolower($asnInfo['organization']);
            
            // Devlet kurumu kontrolü
            if (strpos($org, 'government') !== false || strpos($org, 'gov') !== false || 
                strpos($org, 'ministry') !== false || strpos($org, 'military') !== false) {
                return 'GOV';
            }
            
            // Eğitim kurumu kontrolü
            if (strpos($org, 'university') !== false || strpos($org, 'edu') !== false || 
                strpos($org, 'school') !== false || strpos($org, 'college') !== false) {
                return 'EDU';
            }
            
            // CDN kontrolü
            if (strpos($org, 'cdn') !== false || strpos($org, 'content delivery') !== false || 
                strpos($org, 'cloudflare') !== false || strpos($org, 'akamai') !== false) {
                return 'CDN';
            }
            
            // Askeri kurum kontrolü
            if (strpos($org, 'military') !== false || strpos($org, 'defense') !== false || 
                strpos($org, 'army') !== false || strpos($org, 'navy') !== false || 
                strpos($org, 'air force') !== false) {
                return 'MIL';
            }
        }
        
        // Varsayılan olarak ticari kullanım
        return 'COM';
    }

    private function getFraudScore(string $ip): ?int {
        try {
            if ($this->config['api_keys']['ipqualityscore']) {
                $url = "https://ipqualityscore.com/api/json/ip/{$this->config['api_keys']['ipqualityscore']}/{$ip}";
                $response = @file_get_contents($url);
                
                if ($response !== false) {
                    $data = json_decode($response, true);
                    if ($data && isset($data['fraud_score'])) {
                        return (int) $data['fraud_score'];
                    }
                }
            }
        } catch (\Exception $e) {
            $this->logError('Fraud Score Check Error: ' . $e->getMessage());
        }
        
        return null;
    }

    private function logError(string $message): void {
        if ($this->config['log_enabled']) {
            $logFile = $this->config['log_path'] . 'error.log';
            $timestamp = date('Y-m-d H:i:s');
            $logMessage = "[{$timestamp}] {$message}\n";
            
            @file_put_contents($logFile, $logMessage, FILE_APPEND);
        }
    }

    private function logAnalysis(array $analysis): void {
        if ($this->config['log_enabled']) {
            $logFile = $this->config['log_path'] . 'analysis.log';
            $timestamp = date('Y-m-d H:i:s');
            $logMessage = "[{$timestamp}] " . json_encode($analysis) . "\n";
            
            @file_put_contents($logFile, $logMessage, FILE_APPEND);
        }
    }
} 