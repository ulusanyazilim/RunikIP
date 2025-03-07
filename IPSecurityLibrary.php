<?php
namespace Security;

class IPSecurityLibrary {
    private $ipInfo;
    private $config;
    private $cache;
    private static $instance = null;
    private $ip2locationData = null;
    
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
            'ip2location_enabled' => true, // IP2Location kontrolünü aktif et
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
            if (!$row || count($row) < 4) continue;
            
            // CSV dosyasından gelen verileri doğrula
            $startIp = isset($row[0]) ? ip2long($row[0]) : null;
            $endIp = isset($row[1]) ? ip2long($row[1]) : null;
            $asn = isset($row[2]) ? trim($row[2]) : null;
            $organization = isset($row[3]) ? trim($row[3]) : null;
            
            if ($startIp === null || $endIp === null || $asn === null || $organization === null) {
                continue;
            }
            
            if ($ipLong >= $startIp && $ipLong <= $endIp) {
                return [
                    'asn' => 'AS' . $asn,
                    'organization' => $organization,
                    'isp' => $organization
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
            // Zaman aşımı süresini azalt ve hata kontrolü ekle
            $socket = @fsockopen("whois.cymru.com", 43, $errno, $errstr, 3);
            if (!$socket) {
                $this->logError("Team Cymru Connection Error: {$errstr} ({$errno})");
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
        // Önce veritabanından kontrol et
        $asnInfo = $this->getASNInfoFromDatabase($ip);
        if ($asnInfo) {
            return $asnInfo;
        }
        
        // Sonra BGP.Tools'u dene
        $asnInfo = $this->getASNInfoFromBGPTools($ip);
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
            if (isset($data['as']) && preg_match('/^AS(\d+)\s/', $data['as'], $matches)) {
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
    
    private function getIPLocationNetData(string $ip): ?array {
        try {
            $url = "https://www.iplocation.net/get-ipdata";
            $sources = [
                'ipapi_is',
                'ipregistry',
                'ipapi_co',
                'ipwhois',
                'ipgeolocation',
                'ipdata',
                'abstractapi',
                'ipstack',
                'ipinfo',
                'maxmind'
            ];

            foreach ($sources as $source) {
                $postData = http_build_query([
                    'ip' => $ip,
                    'source' => $source,
                    'ipv' => '4'
                ]);
                
                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => $postData,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_HTTPHEADER => [
                        'Accept: application/json, text/javascript, */*; q=0.01',
                        'Accept-Language: en-US,en;q=0.9,tr;q=0.8',
                        'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
                        'Origin: https://www.iplocation.net',
                        'Referer: https://www.iplocation.net/ip-lookup',
                        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                        'X-Requested-With: XMLHttpRequest'
                    ]
                ]);
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                
                if ($httpCode === 200 && $response) {
                    $data = json_decode($response, true);
                    if ($data && isset($data['res'])) {
                        $res = $data['res'];
                        
                        // Ortak veri yapısı
                        $result = [
                            'is_proxy' => false,
                            'is_datacenter' => false,
                            'is_vpn' => false,
                            'is_tor' => false,
                            'is_mobile' => false,
                            'is_satellite' => false,
                            'company_type' => '',
                            'source' => $source,
                            'country' => null,
                            'country_code' => null,
                            'region' => null,
                            'city' => null,
                            'isp' => null,
                            'org_name' => null,
                            'as_no' => null,
                            'postal_code' => null,
                            'latitude' => null,
                            'longitude' => null,
                            'abuse_score' => null,
                            'asn_abuse_score' => null,
                            'connection_type' => null,
                            'proxy_type' => null,
                            'threat_level' => null,
                            'threat_types' => [],
                            'confidence_score' => null,
                            'net_speed' => null,
                            'area_code' => null,
                            'idd_code' => null
                        ];

                        switch ($source) {
                            case 'ipapi_is':
                                $result['is_proxy'] = $data['isProxy'] ?? false;
                                $result['is_datacenter'] = $res['is_datacenter'] ?? false;
                                $result['is_vpn'] = $res['is_vpn'] ?? false;
                                $result['is_tor'] = $res['is_tor'] ?? false;
                                $result['is_mobile'] = $res['is_mobile'] ?? false;
                                $result['is_satellite'] = $res['is_satellite'] ?? false;
                                $result['company_type'] = $res['company']['type'] ?? '';
                                $result['country'] = $res['location']['country'] ?? null;
                                $result['country_code'] = $res['location']['country_code'] ?? null;
                                $result['region'] = $res['location']['state'] ?? null;
                                $result['city'] = $res['location']['city'] ?? null;
                                $result['isp'] = $res['company']['name'] ?? null;
                                $result['org_name'] = $res['company']['name'] ?? null;
                                $result['as_no'] = $res['asn']['asn'] ?? null;
                                $result['postal_code'] = $res['location']['zip'] ?? null;
                                $result['latitude'] = $res['location']['latitude'] ?? null;
                                $result['longitude'] = $res['location']['longitude'] ?? null;
                                $result['abuse_score'] = $res['company']['abuser_score'] ?? null;
                                $result['asn_abuse_score'] = $res['asn']['abuser_score'] ?? null;
                                $result['net_speed'] = $res['net_speed'] ?? null;
                                $result['area_code'] = $res['area_code'] ?? null;
                                $result['idd_code'] = $res['idd_code'] ?? null;
                                $result['proxy_type'] = $res['proxy']['proxy_type'] ?? null;
                                $result['threat'] = $res['proxy']['threat'] ?? null;
                                break;

                            case 'ipregistry':
                                $security = $res['security'] ?? [];
                                $connection = $res['connection'] ?? [];
                                $company = $res['company'] ?? [];
                                
                                $result['is_proxy'] = $security['is_proxy'] ?? false;
                                $result['is_vpn'] = $security['is_vpn'] ?? false;
                                $result['is_tor'] = $security['is_tor'] ?? false;
                                $result['is_datacenter'] = isset($connection['type']) && ($connection['type'] === 'hosting' || $connection['type'] === 'datacenter');
                                $result['country'] = $res['location']['country']['name'] ?? null;
                                $result['country_code'] = $res['location']['country']['code'] ?? null;
                                $result['region'] = $res['location']['region']['name'] ?? null;
                                $result['city'] = $res['location']['city'] ?? null;
                                $result['isp'] = $connection['organization'] ?? null;
                                $result['org_name'] = $company['name'] ?? null;
                                $result['as_no'] = $connection['asn'] ?? null;
                                $result['postal_code'] = $res['location']['postal'] ?? null;
                                $result['latitude'] = $res['location']['latitude'] ?? null;
                                $result['longitude'] = $res['location']['longitude'] ?? null;
                                $result['company_type'] = $company['type'] ?? null;
                                $result['connection_type'] = $connection['type'] ?? null;
                                break;

                            case 'ipapi_co':
                                $result['is_proxy'] = $res['proxy'] ?? false;
                                $result['is_mobile'] = $res['mobile'] ?? false;
                                $result['country'] = $res['country_name'] ?? null;
                                $result['country_code'] = $res['country_code'] ?? null;
                                $result['region'] = $res['region'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['isp'] = $res['isp'] ?? null;
                                $result['org_name'] = $res['org'] ?? null;
                                $result['as_no'] = $res['asn'] ?? null;
                                $result['latitude'] = $res['latitude'] ?? null;
                                $result['longitude'] = $res['longitude'] ?? null;
                                break;

                            case 'ipwhois':
                                $result['is_proxy'] = $res['security']['is_proxy'] ?? false;
                                $result['is_vpn'] = $res['security']['is_vpn'] ?? false;
                                $result['is_tor'] = $res['security']['is_tor'] ?? false;
                                $result['country'] = $res['country'] ?? null;
                                $result['country_code'] = $res['country_code'] ?? null;
                                $result['region'] = $res['region'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['isp'] = $res['isp'] ?? null;
                                $result['org_name'] = $res['org'] ?? null;
                                $result['as_no'] = $res['asn'] ?? null;
                                $result['connection_type'] = $res['connection_type'] ?? null;
                                break;

                            case 'ipgeolocation':
                                $result['country'] = $res['country_name'] ?? null;
                                $result['country_code'] = $res['country_code2'] ?? null;
                                $result['region'] = $res['state_prov'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['isp'] = $res['isp'] ?? null;
                                $result['org_name'] = $res['organization'] ?? null;
                                $result['latitude'] = $res['latitude'] ?? null;
                                $result['longitude'] = $res['longitude'] ?? null;
                                break;

                            case 'ipdata':
                                $result['is_proxy'] = $res['threat']['is_proxy'] ?? false;
                                $result['is_vpn'] = $res['threat']['is_vpn'] ?? false;
                                $result['is_tor'] = $res['threat']['is_tor'] ?? false;
                                $result['country'] = $res['country_name'] ?? null;
                                $result['country_code'] = $res['country_code'] ?? null;
                                $result['region'] = $res['region'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['isp'] = $res['asn']['name'] ?? null;
                                $result['as_no'] = $res['asn']['asn'] ?? null;
                                $result['latitude'] = $res['latitude'] ?? null;
                                $result['longitude'] = $res['longitude'] ?? null;
                                $result['threat_level'] = $res['threat']['level'] ?? null;
                                $result['threat_types'] = $res['threat']['types'] ?? [];
                                break;

                            case 'abstractapi':
                                $result['is_vpn'] = $res['security']['is_vpn'] ?? false;
                                $result['is_tor'] = $res['security']['is_tor'] ?? false;
                                $result['country'] = $res['country'] ?? null;
                                $result['country_code'] = $res['country_code'] ?? null;
                                $result['region'] = $res['region'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['latitude'] = $res['latitude'] ?? null;
                                $result['longitude'] = $res['longitude'] ?? null;
                                $result['connection_type'] = $res['connection']['type'] ?? null;
                                break;

                            case 'ipstack':
                                $result['country'] = $res['country_name'] ?? null;
                                $result['country_code'] = $res['country_code'] ?? null;
                                $result['region'] = $res['region_name'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['latitude'] = $res['latitude'] ?? null;
                                $result['longitude'] = $res['longitude'] ?? null;
                                $result['connection_type'] = $res['connection']['type'] ?? null;
                                $result['is_proxy'] = $res['security']['proxy'] ?? false;
                                $result['is_vpn'] = $res['security']['vpn'] ?? false;
                                $result['is_tor'] = $res['security']['tor'] ?? false;
                                $result['threat_level'] = $res['security']['threat_level'] ?? null;
                                break;

                            case 'ipinfo':
                                $result['country'] = $res['country'] ?? null;
                                $result['region'] = $res['region'] ?? null;
                                $result['city'] = $res['city'] ?? null;
                                $result['isp'] = $res['org'] ?? null;
                                $result['postal_code'] = $res['postal'] ?? null;
                                $result['latitude'] = isset($res['loc']) ? explode(',', $res['loc'])[0] ?? null : null;
                                $result['longitude'] = isset($res['loc']) ? explode(',', $res['loc'])[1] ?? null : null;
                                $result['company_type'] = isset($res['company']) && isset($res['company']['type']) ? $res['company']['type'] : null;
                                break;

                            case 'maxmind':
                                $result['country'] = $res['country']['names']['en'] ?? null;
                                $result['country_code'] = $res['country']['iso_code'] ?? null;
                                $result['region'] = isset($res['subdivisions'][0]['names']['en']) ? $res['subdivisions'][0]['names']['en'] : null;
                                $result['city'] = isset($res['city']['names']['en']) ? $res['city']['names']['en'] : null;
                                $result['postal_code'] = isset($res['postal']['code']) ? $res['postal']['code'] : null;
                                $result['latitude'] = isset($res['location']['latitude']) ? $res['location']['latitude'] : null;
                                $result['longitude'] = isset($res['location']['longitude']) ? $res['location']['longitude'] : null;
                                $result['is_proxy'] = isset($res['traits']['is_anonymous_proxy']) ? $res['traits']['is_anonymous_proxy'] : false;
                                $result['is_vpn'] = isset($res['traits']['is_anonymous_vpn']) ? $res['traits']['is_anonymous_vpn'] : false;
                                $result['is_tor'] = isset($res['traits']['is_tor_exit_node']) ? $res['traits']['is_tor_exit_node'] : false;
                                break;
                        }

                        // Eğer herhangi bir güvenlik riski varsa proxy olarak işaretle
                        if ($result['is_vpn'] || $result['is_tor'] || $result['is_datacenter']) {
                            $result['is_proxy'] = true;
                        }

                        // Eğer yeterli veri varsa sonucu döndür
                        if ($result['country'] !== null && $result['city'] !== null) {
                            return $result;
                        }
                    }
                }
            }
            
            return null;
        } catch (\Exception $e) {
            $this->logError('IP Location Net Error: ' . $e->getMessage());
            return null;
        }
    }

    public function getIPLocationData(string $ip): ?array {
        // Önce yeni IP Location servisini dene
        $ipLocationNetData = $this->getIPLocationNetData($ip);
        if ($ipLocationNetData !== null) {
            return $ipLocationNetData;
        }
        
        // Eğer yeni servis başarısız olursa eski yöntemi dene
        try {
            $url = "https://www.iplocation.net/";
            $postData = http_build_query([
                'query' => $ip
            ]);
            
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $postData,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            ]);
            
            $response = curl_exec($ch);
            curl_close($ch);
            
            $result = [];
            
            if (preg_match('/ISP:\s*([^<\n]+)/', $response, $matches)) {
                $result['isp'] = trim($matches[1]);
            }
            
            if (preg_match('/Host Name:\s*([^<\n]+)/', $response, $matches)) {
                $result['hostname'] = trim($matches[1]);
            }
            
            return $result;
        } catch (\Exception $e) {
            $this->logError('IP Location Error: ' . $e->getMessage());
            return null;
        }
    }

    public function isTurkishISP(string $ispName): bool {
        $turkishISPs = [
            'turk telekom', 'turktelekom', 'ttnet',
            'superonline', 'vodafone', 'turkcell',
            'turknet', 'turksat', 'millenicom',
            'd-smart', 'dsmart'
        ];
        
        $ispName = strtolower($ispName);
        foreach ($turkishISPs as $isp) {
            if (stripos($ispName, $isp) !== false) {
                return true;
            }
        }
        
            return false;
        }
        
    private function isISP(string $ip): bool {
        try {
            // Önce IP Location'dan kontrol et
            $ipLocationData = $this->getIPLocationData($ip);
            if ($ipLocationData !== null) {
                // ISP kontrolü
                if (isset($ipLocationData['isp']) && $this->isTurkishISP($ipLocationData['isp'])) {
                    return true;
                }
                
                // Hostname kontrolü
                if (isset($ipLocationData['hostname']) && $this->isTurkishISP($ipLocationData['hostname'])) {
                return true;
            }
        }
        
            // IP2Location'dan kontrol et
            $ip2locationData = $this->getIP2LocationData($ip);
            if ($ip2locationData !== null) {
                if (strpos(strtolower($ip2locationData['usage_type']), 'isp') !== false) {
                return true;
                }
            }

            // IP-API'den ISP bilgisini kontrol et
            $url = "http://ip-api.com/json/{$ip}?fields=isp,org,as";
            $response = @file_get_contents($url);
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['as'])) {
                    // AS numarasını temizle
                    $asn = preg_replace('/^(AS\d+).*$/', '$1', $data['as']);
                    
                    // Türk ISP'leri ve ASN numaraları
                    $turkishISPs = [
                        'AS9121',  // Turk Telekom
                        'AS34984', // Tellcom/Superonline
                        'AS8386',  // Vodafone
                        'AS16135', // Turkcell
                        'AS15897', // Vodafone TR
                        'AS196978', // TurkNet
                        'AS20978',  // Türksat
                        'AS34296',  // Millenicom
                        'AS43260',  // D-Smart
                        'AS205813', // Superonline Iletisim
                        'AS211557', // Turknet
                        'AS47524',  // Turksat
                    ];

                    if (in_array($asn, $turkishISPs)) {
                    return true;
                }
            }
            }
        } catch (\Exception $e) {
            $this->logError('ISP Check Error: ' . $e->getMessage());
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
        
        // Kara liste kontrolleri
        $checks['blacklist_status'] = $this->checkBlacklists($ip);
        
        return $checks;
    }

    private function checkProxy(string $ip): bool {
        try {
            // IP2Location kontrolü
            $usageType = $this->getUsageType($ip);
            if ($usageType === 'PROXY') {
                    return true;
                }

            // IP Location kontrolü
            $ipLocationData = $this->getIPLocationData($ip);
            if ($ipLocationData !== null && isset($ipLocationData['is_proxy']) && $ipLocationData['is_proxy'] === true) {
                return true;
            }

            // IP-API kontrolü
            $url = "http://ip-api.com/json/{$ip}?fields=proxy,status";
                $response = @file_get_contents($url);
                if ($response !== false) {
                    $data = json_decode($response, true);
                if ($data && isset($data['status']) && $data['status'] === 'success' && isset($data['proxy'])) {
                    if ((bool)$data['proxy'] === true) {
                        return true;
                    }
                }
            }

            // Proxy port kontrolü
            $commonProxyPorts = [80, 81, 83, 88, 8080, 8081, 8888, 3128];
            foreach ($commonProxyPorts as $port) {
                $connection = @fsockopen($ip, $port, $errno, $errstr, 1);
                if ($connection) {
                    fclose($connection);
                    return true;
                }
            }

            // DNS blacklist kontrolü
            $reverseIp = implode('.', array_reverse(explode('.', $ip)));
            $proxyBlacklists = [
                'proxy.bl.gweep.ca',
                'proxy.block.transip.nl',
                'proxy.mind.net.pl',
                'socks.dnsbl.sorbs.net',
                'misc.dnsbl.sorbs.net'
            ];

            foreach ($proxyBlacklists as $bl) {
                if (checkdnsrr("{$reverseIp}.{$bl}.", 'A')) {
                    return true;
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
            if (isset($this->config['api_keys']['abuseipdb']) && !empty($this->config['api_keys']['abuseipdb'])) {
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
        // Datacenter kontrolü - En yüksek öncelik
        if ($this->isDatacenter($ip)) {
            return 'DCH';
        }

        // IP Location'dan kontrol et
        $ipLocationData = $this->getIPLocationData($ip);
        if ($ipLocationData !== null) {
        // Datacenter kontrolü
            if (isset($ipLocationData['is_datacenter']) && $ipLocationData['is_datacenter']) {
            return 'DCH';
        }
        
            // Şirket ve bağlantı tipi kontrolü
            $companyType = strtolower($ipLocationData['company_type'] ?? '');
            $connectionType = strtolower($ipLocationData['connection_type'] ?? '');

            if (in_array($companyType, ['hosting', 'datacenter', 'server', 'business', 'datacenter/hosting']) ||
                in_array($connectionType, ['hosting', 'datacenter', 'server', 'business', 'datacenter/hosting'])) {
                return 'DCH';
            }

            // ISP kontrolü
            $ispName = $ipLocationData['isp'] ?? '';
            $orgName = $ipLocationData['org_name'] ?? '';
            if ($this->isTurkishISP($ispName) || $this->isTurkishISP($orgName)) {
                // Eğer datacenter değilse ISP olarak işaretle
                if (!$this->isDatacenter($ip)) {
                    return 'ISP';
                }
            }

            // Proxy/VPN/TOR kontrolü
            if ((isset($ipLocationData['is_proxy']) && $ipLocationData['is_proxy']) ||
                (isset($ipLocationData['is_vpn']) && $ipLocationData['is_vpn']) ||
                (isset($ipLocationData['is_tor']) && $ipLocationData['is_tor'])) {
                return 'PROXY';
            }

            // Mobil ve uydu kontrolü
            if (isset($ipLocationData['is_mobile']) && $ipLocationData['is_mobile']) {
                return 'MOB';
            }
            if (isset($ipLocationData['is_satellite']) && $ipLocationData['is_satellite']) {
                return 'SAT';
            }
        }

        // IP2Location kontrolü
        $ip2locationData = $this->getIP2LocationData($ip);
        if ($ip2locationData !== null && isset($ip2locationData['usage_type'])) {
            $usageType = strtoupper($ip2locationData['usage_type']);
            
            switch ($usageType) {
                case 'DCH':
                case 'DATACENTER':
                case 'HOSTING':
                case 'BUSINESS':
                case 'DATACENTER/HOSTING':
                    return 'DCH';
                case 'ISP':
                    if (isset($ip2locationData['isp']) && $this->isTurkishISP($ip2locationData['isp'])) {
                        // Eğer datacenter değilse ISP olarak işaretle
                        if (!$this->isDatacenter($ip)) {
                            return 'ISP';
                        }
                    }
                    break;
                case 'PROXY':
                case 'VPN':
                case 'TOR':
                    return 'PROXY';
                case 'PUB':
                case 'RES':
                case 'RESIDENTIAL':
                    return 'PUB';
                case 'MOB':
                case 'MOBILE':
                    return 'MOB';
                case 'SAT':
                case 'SATELLITE':
                    return 'SAT';
            }
        }

        // IP-API kontrolü
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=isp,org,as,hosting";
            $response = @file_get_contents($url);
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data) {
                    if (isset($data['hosting']) && $data['hosting'] === true) {
                        return 'DCH';
                    }
                    
                    if (isset($data['isp']) && $this->isTurkishISP($data['isp'])) {
                        // Eğer datacenter değilse ISP olarak işaretle
                        if (!$this->isDatacenter($ip)) {
                            return 'ISP';
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            $this->logError('IP-API Check Error: ' . $e->getMessage());
        }

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

    private function isDatacenter(string $ip): bool {
        try {
            // Önce veritabanından kontrol et
            if ($this->isDatacenterFromDatabase($ip)) {
                return true;
            }

            // IP Location'dan kontrol et
            $ipLocationData = $this->getIPLocationData($ip);
            if ($ipLocationData !== null) {
                // Doğrudan datacenter kontrolü
                if (isset($ipLocationData['is_datacenter']) && $ipLocationData['is_datacenter']) {
                    return true;
                }

                // Bağlantı tipi kontrolü
                $connectionType = strtolower($ipLocationData['connection_type'] ?? '');
                if (in_array($connectionType, ['hosting', 'datacenter', 'server'])) {
                    return true;
                }

                // Şirket tipi kontrolü
                $companyType = strtolower($ipLocationData['company_type'] ?? '');
                if (in_array($companyType, ['hosting', 'datacenter', 'server'])) {
                    return true;
                }
            }

            // IP-API'den kontrol et
            $url = "http://ip-api.com/json/{$ip}?fields=hosting";
            $response = @file_get_contents($url);
            if ($response !== false) {
                $data = json_decode($response, true);
                if ($data && isset($data['hosting']) && $data['hosting'] === true) {
                    return true;
                }
            }

            return false;
        } catch (\Exception $e) {
            $this->logError('Datacenter Check Error: ' . $e->getMessage());
            return false;
        }
    }

    private function getIP2LocationData(string $ip): ?array {
        try {
            if (!$this->config['ip2location_enabled']) {
                return null;
            }

            // Eğer daha önce yüklenmiş veri varsa onu kullan
            if ($this->ip2locationData !== null) {
                return $this->ip2locationData;
            }

            // IP2Location API'sini kullan
            $url = "https://api.ip2location.io/lookup-ip.json?ip={$ip}&token=d18229d26e1f9600ac90930207556628f2da942acb4d106400f505bf8ff12819";
            $response = @file_get_contents($url);
            
            if ($response === false) {
                return null;
            }
            
            $data = json_decode($response, true);
            if (!$data) {
                return null;
            }

            // Sonuçları cache'le
            $this->ip2locationData = [
                'country_code' => $data['country_code'] ?? null,
                'country_name' => $data['country_name'] ?? null,
                'region_name' => $data['region_name'] ?? null,
                'city_name' => $data['city_name'] ?? null,
                'isp' => $data['isp'] ?? null,
                'domain' => $data['domain'] ?? null,
                'zip_code' => $data['zip_code'] ?? null,
                'time_zone' => $data['time_zone'] ?? null,
                'net_speed' => $data['net_speed'] ?? null,
                'elevation' => $data['elevation'] ?? null,
                'usage_type' => $data['usage_type'] ?? null,
                'address_type' => $data['address_type'] ?? null,
                'category' => $data['category'] ?? null,
                'district' => $data['district'] ?? null,
                'asn' => $data['asn'] ?? null,
                'as_name' => $data['as'] ?? null,
                'latitude' => $data['latitude'] ?? null,
                'longitude' => $data['longitude'] ?? null,
                'area_code' => $data['area_code'] ?? null,
                'idd_code' => $data['idd_code'] ?? null,
                'weather_station_code' => $data['weather_station_code'] ?? null,
                'weather_station_name' => $data['weather_station_name'] ?? null,
                'mcc' => $data['mcc'] ?? null,
                'mnc' => $data['mnc'] ?? null,
                'mobile_brand' => $data['mobile_brand'] ?? null,
                'is_proxy' => isset($data['is_proxy']) ? (bool)$data['is_proxy'] : false,
                'proxy_type' => isset($data['proxy']) && isset($data['proxy']['proxy_type']) ? $data['proxy']['proxy_type'] : null,
                'threat' => isset($data['proxy']) && isset($data['proxy']['threat']) ? $data['proxy']['threat'] : null
            ];

            return $this->ip2locationData;

        } catch (\Exception $e) {
            $this->logError('IP2Location Error: ' . $e->getMessage());
            return null;
        }
    }
} 