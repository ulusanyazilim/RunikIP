<?php
namespace Security;

class IPSecurityLibrary {
    private $ipInfo;
    private $config;
    private $cache;
    private static $instance = null;
    
    private const CACHE_DURATION = 3600; // 1 saat
    
    private function __construct(array $config = []) {
        $this->config = array_merge([
            'cache_enabled' => true,
            'geolocation_provider' => 'ip-api',
            'log_enabled' => true,
            'log_path' => 'security_logs/',
            'proxy_check_enabled' => true,
            'tor_check_enabled' => true,
            'vpn_check_enabled' => true,
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
    
    public function analyzeIP(string $ip = null): array {
        $ip = $ip ?? $this->getClientIP();
        
        // Cache kontrolü
        $cacheKey = 'ip_analysis_' . md5($ip);
        if ($this->config['cache_enabled'] && $cached = $this->cache->get($cacheKey)) {
            return $cached;
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
            'operating_system' => $this->getOperatingSystem()
        ];
        
        // Sonuçları cache'le
        if ($this->config['cache_enabled']) {
            $this->cache->set($cacheKey, $analysis, self::CACHE_DURATION);
        }
        
        $this->logAnalysis($analysis);
        
        return $analysis;
    }
    
    private function performBasicChecks(string $ip): array {
        return [
            'is_valid' => $this->isValidIP($ip),
            'is_public' => $this->isPublicIP($ip),
            'ip_version' => $this->getIPVersion($ip),
            'is_blacklisted' => $this->isBlacklisted($ip)
        ];
    }
    
    private function performSecurityChecks(string $ip): array {
        $checks = [
            'is_proxy' => $this->config['proxy_check_enabled'] ? $this->isProxy($ip) : null,
            'is_vpn' => $this->config['vpn_check_enabled'] ? $this->isVPN($ip) : null,
            'is_tor' => $this->config['tor_check_enabled'] ? $this->isTorExit($ip) : null,
            'is_datacenter' => $this->isDatacenter($ip),
            'threat_score' => $this->calculateThreatScore($ip),
            'abuse_confidence_score' => $this->getAbuseConfidenceScore($ip)
        ];
        
        return array_filter($checks, function($value) {
            return $value !== null;
        });
    }
    
    private function getGeolocationData(string $ip): ?array {
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting";
            
            $response = @file_get_contents($url);
            if ($response === false) {
                throw new \Exception("Failed to get IP-API data");
            }
            
            $data = json_decode($response, true);
            if (!$data || $data['status'] === 'fail') {
                throw new \Exception($data['message'] ?? 'Unknown error');
            }
            
            // Konum bilgilerini düzenle
            return [
                'country' => [
                    'name' => $data['country'] ?? 'Unknown',
                    'code' => $data['countryCode'] ?? 'Unknown',
                    'flag' => $this->getCountryFlag($data['countryCode'] ?? '')
                ],
                'region' => [
                    'name' => $data['regionName'] ?? 'Unknown',
                    'code' => $data['region'] ?? 'Unknown'
                ],
                'city' => $data['city'] ?? 'Unknown',
                'district' => $data['district'] ?? 'Unknown',
                'postal_code' => $data['zip'] ?? 'Unknown',
                'location' => [
                    'latitude' => $data['lat'] ?? 0,
                    'longitude' => $data['lon'] ?? 0
                ],
                'isp' => $data['isp'] ?? 'Unknown',
                'organization' => $data['org'] ?? 'Unknown',
                'timezone' => $data['timezone'] ?? 'Unknown'
            ];
        } catch (\Exception $e) {
            $this->logError('Geolocation Error: ' . $e->getMessage());
            return null;
        }
    }
    
    private function assessRisk(string $ip): array {
        $riskFactors = [
            'geolocation_risk' => $this->calculateGeolocationRisk($ip),
            'proxy_risk' => $this->calculateProxyRisk($ip),
            'behavior_risk' => $this->calculateBehaviorRisk($ip),
            'reputation_risk' => $this->calculateReputationRisk($ip)
        ];
        
        $totalRiskScore = array_sum($riskFactors);
        
        return [
            'risk_factors' => $riskFactors,
            'total_risk_score' => $totalRiskScore,
            'risk_level' => $this->determineRiskLevel($totalRiskScore),
            'recommendations' => $this->generateSecurityRecommendations($totalRiskScore, $riskFactors)
        ];
    }
    
    private function determineRiskLevel(float $riskScore): string {
        if ($riskScore >= $this->config['risk_threshold']['low']) {
            return 'LOW';
        } elseif ($riskScore >= $this->config['risk_threshold']['medium']) {
            return 'MEDIUM';
        }
        return 'HIGH';
    }
    
    private function generateSecurityRecommendations(float $riskScore, array $riskFactors): array {
        $recommendations = [];
        
        if ($riskScore < $this->config['risk_threshold']['medium']) {
            $recommendations[] = 'Enable CAPTCHA verification';
            $recommendations[] = 'Implement rate limiting';
            
            if ($riskFactors['proxy_risk'] > 0.5) {
                $recommendations[] = 'Block access through proxy/VPN';
            }
            
            if ($riskFactors['geolocation_risk'] > 0.7) {
                $recommendations[] = 'Restrict access from high-risk countries';
            }
        }
        
        return $recommendations;
    }
    
    private function logAnalysis(array $analysis): void {
        if (!$this->config['log_enabled']) {
            return;
        }
        
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $analysis['ip'],
            'risk_level' => $analysis['risk_assessment']['risk_level'],
            'security_flags' => $analysis['security_checks']
        ];
        
        $logFile = $this->config['log_path'] . 'security_' . date('Y-m-d') . '.log';
        file_put_contents($logFile, json_encode($logEntry) . "\n", FILE_APPEND);
    }
    
    private function logError(string $message): void {
        if ($this->config['log_enabled']) {
            $logFile = $this->config['log_path'] . 'errors_' . date('Y-m-d') . '.log';
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - {$message}\n", FILE_APPEND);
        }
    }
    
    // Yardımcı metodlar
    private function isValidIP(string $ip): bool {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false;
    }
    
    private function isPublicIP(string $ip): bool {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }
    
    private function getIPVersion(string $ip): ?int {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 4;
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 6;
        }
        return null;
    }

    private function getClientDetails(): array {
        return [
            'browser' => $this->getBrowserInfo(),
            'operating_system' => $this->getOperatingSystem(),
            'device' => $this->getDeviceInfo(),
            'screen' => $this->getScreenInfo(),
            'language' => $this->getClientLanguage(),
            'timezone' => $this->getClientTimezone()
        ];
    }

    private function getBrowserInfo(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $browser = [
            'user_agent' => $userAgent,
            'name' => 'Unknown',
            'version' => 'Unknown',
            'platform' => 'Unknown',
            'pattern' => 'Unknown'
        ];

        if (preg_match('/(opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i', $userAgent, $matches)) {
            $browser['name'] = $matches[1];
            $browser['version'] = $matches[2];
        }

        // Tarayıcı özellikleri
        $browser['features'] = [
            'cookies_enabled' => isset($_SERVER['HTTP_COOKIE']),
            'javascript_enabled' => true, // Client-side ile kontrol edilmeli
            'language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'Unknown',
            'do_not_track' => $_SERVER['HTTP_DNT'] ?? 'Unknown'
        ];

        return $browser;
    }

    private function getOperatingSystem(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $os = [
            'name' => 'Unknown',
            'version' => 'Unknown',
            'architecture' => 'Unknown'
        ];

        $osPatterns = [
            '/windows nt 10/i'      => ['Windows 10', 'NT 10.0'],
            '/windows nt 6.3/i'     => ['Windows 8.1', 'NT 6.3'],
            '/windows nt 6.2/i'     => ['Windows 8', 'NT 6.2'],
            '/windows nt 6.1/i'     => ['Windows 7', 'NT 6.1'],
            '/windows nt 6.0/i'     => ['Windows Vista', 'NT 6.0'],
            '/windows nt 5.2/i'     => ['Windows Server 2003/XP x64', 'NT 5.2'],
            '/windows nt 5.1/i'     => ['Windows XP', 'NT 5.1'],
            '/windows xp/i'         => ['Windows XP', 'NT 5.1'],
            '/macintosh|mac os x/i' => ['Mac OS X', ''],
            '/mac_powerpc/i'        => ['Mac OS 9', ''],
            '/linux/i'              => ['Linux', ''],
            '/ubuntu/i'             => ['Ubuntu', ''],
            '/iphone/i'             => ['iPhone', 'iOS'],
            '/ipod/i'               => ['iPod', 'iOS'],
            '/ipad/i'               => ['iPad', 'iOS'],
            '/android/i'            => ['Android', ''],
            '/webos/i'              => ['Mobile', '']
        ];

        foreach ($osPatterns as $pattern => $osInfo) {
            if (preg_match($pattern, $userAgent)) {
                $os['name'] = $osInfo[0];
                $os['version'] = $osInfo[1];
                break;
            }
        }

        return $os;
    }

    private function getDeviceInfo(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        return [
            'type' => $this->getDeviceType($userAgent),
            'brand' => $this->getDeviceBrand($userAgent),
            'model' => $this->getDeviceModel($userAgent),
            'screen_resolution' => $this->getScreenResolution(),
            'is_mobile' => $this->isMobileDevice($userAgent),
            'is_tablet' => $this->isTabletDevice($userAgent),
            'is_desktop' => $this->isDesktopDevice($userAgent)
        ];
    }

    private function getDetailedLocation(array $geoData): array {
        $location = [
            'continent' => [
                'code' => $geoData['continent_code'] ?? 'Unknown',
                'name' => $geoData['continent_name'] ?? 'Unknown'
            ],
            'country' => [
                'code' => $geoData['country_code'] ?? 'Unknown',
                'name' => $geoData['country_name'] ?? 'Unknown',
                'is_eu' => $geoData['is_eu'] ?? false
            ],
            'region' => [
                'code' => $geoData['region_code'] ?? 'Unknown',
                'name' => $geoData['region_name'] ?? 'Unknown'
            ],
            'city' => [
                'name' => $geoData['city'] ?? 'Unknown',
                'district' => $geoData['district'] ?? 'Unknown',
                'postal_code' => $geoData['postal_code'] ?? 'Unknown'
            ],
            'location' => [
                'latitude' => $geoData['latitude'] ?? 0,
                'longitude' => $geoData['longitude'] ?? 0,
                'accuracy_radius' => $geoData['accuracy_radius'] ?? 0,
                'time_zone' => $geoData['time_zone'] ?? 'Unknown'
            ],
            'network' => [
                'autonomous_system_number' => $geoData['autonomous_system_number'] ?? 'Unknown',
                'autonomous_system_organization' => $geoData['autonomous_system_organization'] ?? 'Unknown',
                'isp' => $geoData['isp'] ?? 'Unknown',
                'organization' => $geoData['organization'] ?? 'Unknown',
                'connection_type' => $geoData['connection_type'] ?? 'Unknown'
            ],
            'additional' => [
                'currency' => $this->getCurrencyByCountry($geoData['country_code'] ?? ''),
                'calling_code' => $this->getCallingCode($geoData['country_code'] ?? ''),
                'flag' => $this->getCountryFlag($geoData['country_code'] ?? '')
            ]
        ];

        // Ekstra konum detayları için Google Geocoding API kullanımı
        if ($this->config['google_maps_api_key']) {
            $location['detailed_address'] = $this->getDetailedAddressFromGoogle(
                $geoData['latitude'] ?? 0,
                $geoData['longitude'] ?? 0
            );
        }

        return $location;
    }

    private function getDetailedAddressFromGoogle(float $lat, float $lng): ?array {
        if (empty($this->config['google_maps_api_key'])) {
            return null;
        }

        $url = sprintf(
            'https://maps.googleapis.com/maps/api/geocode/json?latlng=%f,%f&key=%s',
            $lat,
            $lng,
            $this->config['google_maps_api_key']
        );

        try {
            $response = @file_get_contents($url);
            if ($response === false) {
                throw new \Exception("Failed to get Google Geocoding data");
            }

            $data = json_decode($response, true);
            if (!$data || $data['status'] !== 'OK') {
                throw new \Exception($data['error_message'] ?? 'Unknown error');
            }

            // İlk sonucu al ve adres bileşenlerini parse et
            $result = $data['results'][0] ?? null;
            if (!$result) {
                return null;
            }

            return $this->parseGoogleAddressComponents($result['address_components']);
        } catch (\Exception $e) {
            $this->logError('Google Geocoding Error: ' . $e->getMessage());
            return null;
        }
    }

    private function parseGoogleAddressComponents(array $components): array {
        $address = [
            'street_number' => '',
            'route' => '',
            'neighborhood' => '',
            'district' => '',
            'city' => '',
            'state' => '',
            'country' => '',
            'postal_code' => '',
            'formatted_address' => ''
        ];

        foreach ($components as $component) {
            $types = $component['types'] ?? [];
            $value = $component['long_name'] ?? '';

            switch (true) {
                case in_array('street_number', $types):
                    $address['street_number'] = $value;
                    break;
                case in_array('route', $types):
                    $address['route'] = $value;
                    break;
                case in_array('neighborhood', $types):
                    $address['neighborhood'] = $value;
                    break;
                case in_array('sublocality', $types):
                    $address['district'] = $value;
                    break;
                case in_array('locality', $types):
                    $address['city'] = $value;
                    break;
                case in_array('administrative_area_level_1', $types):
                    $address['state'] = $value;
                    break;
                case in_array('country', $types):
                    $address['country'] = $value;
                    break;
                case in_array('postal_code', $types):
                    $address['postal_code'] = $value;
                    break;
            }
        }

        $address['formatted_address'] = implode(' ', array_filter([
            $address['street_number'],
            $address['route'],
            $address['neighborhood'],
            $address['district'],
            $address['city'],
            $address['state'],
            $address['country'],
            $address['postal_code']
        ]));

        return $address;
    }

    private function getScreenInfo(): array {
        // JavaScript ile client tarafında alınması gereken bilgiler
        return [
            'width' => $_COOKIE['screen_width'] ?? 'Unknown',
            'height' => $_COOKIE['screen_height'] ?? 'Unknown',
            'color_depth' => $_COOKIE['color_depth'] ?? 'Unknown',
            'pixel_ratio' => $_COOKIE['pixel_ratio'] ?? 'Unknown',
            'orientation' => $_COOKIE['screen_orientation'] ?? 'Unknown'
        ];
    }

    private function getClientLanguage(): array {
        $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $languages = [];
        
        if (!empty($acceptLanguage)) {
            // Dil kodlarını ayır ve öncelik sırasına göre sırala
            $langs = explode(',', $acceptLanguage);
            foreach ($langs as $lang) {
                $parts = explode(';q=', $lang);
                $code = trim($parts[0]);
                $priority = $parts[1] ?? 1.0;
                $languages[] = [
                    'code' => $code,
                    'priority' => (float)$priority,
                    'name' => $this->getLanguageName($code)
                ];
            }
            usort($languages, function($a, $b) {
                return $b['priority'] <=> $a['priority'];
            });
        }
        
        return [
            'primary' => $languages[0] ?? ['code' => 'Unknown', 'name' => 'Unknown'],
            'all' => $languages
        ];
    }

    private function getClientTimezone(): array {
        return [
            'offset' => $_COOKIE['timezone_offset'] ?? 'Unknown',
            'name' => $_COOKIE['timezone_name'] ?? 'Unknown',
            'region' => $_COOKIE['timezone_region'] ?? 'Unknown'
        ];
    }

    private function getDeviceType(string $userAgent): string {
        $deviceTypes = [
            'mobile' => [
                '/iphone/i',
                '/ipod/i',
                '/android.*mobile/i',
                '/windows.*phone/i',
                '/blackberry/i',
            ],
            'tablet' => [
                '/ipad/i',
                '/android(?!.*mobile)/i',
                '/windows.*touch/i',
            ],
            'desktop' => [
                '/windows/i',
                '/macintosh/i',
                '/linux/i',
            ]
        ];
        
        foreach ($deviceTypes as $type => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $userAgent)) {
                    return $type;
                }
            }
        }
        
        return 'unknown';
    }

    private function getDeviceBrand(string $userAgent): string {
        $brands = [
            'Apple' => '/iphone|ipad|ipod|macintosh/i',
            'Samsung' => '/samsung/i',
            'Huawei' => '/huawei/i',
            'Xiaomi' => '/xiaomi|redmi/i',
            'LG' => '/lg/i',
            'Sony' => '/sony/i',
            'HTC' => '/htc/i',
            'Motorola' => '/motorola/i',
            'Nokia' => '/nokia/i',
            'Microsoft' => '/windows phone/i',
            'Google' => '/pixel/i'
        ];
        
        foreach ($brands as $brand => $pattern) {
            if (preg_match($pattern, strtolower($userAgent))) {
                return $brand;
            }
        }
        
        return 'Unknown';
    }

    private function getDeviceModel(string $userAgent): string {
        // iPhone modelleri
        if (preg_match('/iPhone\s*(\d+,\d+)/i', $userAgent, $matches)) {
            return 'iPhone ' . $matches[1];
        }
        
        // iPad modelleri
        if (preg_match('/iPad\s*(\d+,\d+)/i', $userAgent, $matches)) {
            return 'iPad ' . $matches[1];
        }
        
        // Android cihazlar
        if (preg_match('/Android.*?;\s*([\w\s-]+)\s+Build/i', $userAgent, $matches)) {
            return trim($matches[1]);
        }
        
        return 'Unknown';
    }

    private function getLanguageName(string $code): string {
        $languages = [
            'tr' => 'Türkçe',
            'en' => 'English',
            'de' => 'Deutsch',
            'fr' => 'Français',
            'es' => 'Español',
            'it' => 'Italiano',
            'ru' => 'Русский',
            'ar' => 'العربية',
            'zh' => '中文',
            'ja' => '日本語'
        ];
        
        $code = strtolower(substr($code, 0, 2));
        return $languages[$code] ?? $code;
    }

    private function isMobileDevice(string $userAgent): bool {
        return preg_match('/Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated/i', $userAgent) === 1;
    }

    private function isTabletDevice(string $userAgent): bool {
        return preg_match('/iPad|Android(?!.*Mobile)|Tablet|Kindle|PlayBook/i', $userAgent) === 1;
    }

    private function isDesktopDevice(string $userAgent): bool {
        return !$this->isMobileDevice($userAgent) && !$this->isTabletDevice($userAgent);
    }

    private function getScreenResolution(): array {
        return [
            'width' => $_COOKIE['screen_width'] ?? 'Unknown',
            'height' => $_COOKIE['screen_height'] ?? 'Unknown'
        ];
    }

    private function getClientIP(): string {
        $ipSources = [
            // Cloudflare
            'HTTP_CF_CONNECTING_IP',
            
            // CDN ve Proxy Servisleri
            'HTTP_TRUE_CLIENT_IP', // Akamai ve bazı CDN'ler
            'HTTP_X_REAL_IP',      // Nginx proxy
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            
            // Load Balancer ve Proxy Sunucular
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_CLIENT_IP',
            
            // AWS, Google Cloud ve Azure
            'HTTP_X_AWS_FORWARDED_FOR',
            'HTTP_X_GOOGLE_REAL_IP',
            'HTTP_X_AZURE_CLIENTIP',
            
            // VPN ve Proxy Kontrolleri
            'HTTP_VIA',
            'HTTP_X_COMING_FROM',
            'HTTP_COMING_FROM',
            
            // Son çare olarak doğrudan IP
            'REMOTE_ADDR'
        ];

        foreach ($ipSources as $source) {
            if (!empty($_SERVER[$source])) {
                if ($source === 'HTTP_X_FORWARDED_FOR') {
                    // X-Forwarded-For başlığında birden fazla IP olabilir
                    $ips = explode(',', $_SERVER[$source]);
                    // İlk geçerli IP'yi bul
                    foreach ($ips as $ip) {
                        $ip = trim($ip);
                        if ($this->isValidPublicIP($ip)) {
                            return $ip;
                        }
                    }
                } else {
                    $ip = trim($_SERVER[$source]);
                    if ($this->isValidPublicIP($ip)) {
                        return $ip;
                    }
                }
            }
        }

        // Hiçbir geçerli IP bulunamazsa
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function isValidPublicIP(string $ip): bool {
        if (empty($ip)) {
            return false;
        }

        // IP formatı kontrolü
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            return false;
        }

        // Özel IP aralıklarını kontrol et
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            // IP adresinin bazı özel durumlarını kontrol et
            $invalidIPs = [
                '0.0.0.0',
                '::1',
                'localhost',
                '127.0.0.1'
            ];

            if (!in_array($ip, $invalidIPs)) {
                return true;
            }
        }

        return false;
    }

    private function isBlacklisted(string $ip): bool {
        // Kara liste kontrolü
        $blacklistedIPs = $this->getBlacklistedIPs();
        return in_array($ip, $blacklistedIPs);
    }

    private function getBlacklistedIPs(): array {
        // Kara listeyi bir dosyadan veya veritabanından okuyabilirsiniz
        // Şimdilik örnek bir liste döndürelim
        return [
            '1.2.3.4',
            '5.6.7.8',
            // Diğer yasaklı IP'ler...
        ];
    }

    private function isVPN(string $ip): bool {
        // VPN kontrolü
        return false; // Şimdilik varsayılan olarak false döndürüyoruz
    }

    private function isTorExit(string $ip): bool {
        // Tor çıkış noktası kontrolü
        return false; // Şimdilik varsayılan olarak false döndürüyoruz
    }

    private function isDatacenter(string $ip): bool {
        // Datacenter IP kontrolü
        return false; // Şimdilik varsayılan olarak false döndürüyoruz
    }

    private function calculateThreatScore(string $ip): float {
        // Tehdit skoru hesaplama
        $score = 0.0;
        
        // IP kara listede mi?
        if ($this->isBlacklisted($ip)) {
            $score += 5.0;
        }
        
        // VPN/Proxy kontrolü
        if ($this->isProxy($ip)) {
            $score += 2.0;
        }
        
        // Tor çıkış noktası kontrolü
        if ($this->isTorExit($ip)) {
            $score += 3.0;
        }
        
        return $score;
    }

    private function getAbuseConfidenceScore(string $ip): float {
        // Kötüye kullanım güven skoru
        return 0.0; // Şimdilik varsayılan olarak 0 döndürüyoruz
    }

    private function calculateGeolocationRisk(string $ip): float {
        // Coğrafi konum risk hesaplaması
        return 0.0; // Şimdilik varsayılan olarak 0 döndürüyoruz
    }

    private function calculateProxyRisk(string $ip): float {
        // Proxy risk hesaplaması
        $risk = 0.0;
        
        if ($this->isProxy($ip)) {
            $risk += 0.5;
        }
        
        if ($this->isVPN($ip)) {
            $risk += 0.3;
        }
        
        if ($this->isTorExit($ip)) {
            $risk += 0.7;
        }
        
        return $risk;
    }

    private function calculateBehaviorRisk(string $ip): float {
        // Davranış risk hesaplaması
        return 0.0; // Şimdilik varsayılan olarak 0 döndürüyoruz
    }

    private function calculateReputationRisk(string $ip): float {
        // İtibar risk hesaplaması
        return 0.0; // Şimdilik varsayılan olarak 0 döndürüyoruz
    }

    private function isProxy(string $ip): bool {
        // Proxy kontrolü
        $proxyHeaders = [
            'HTTP_VIA',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR_IP',
            'VIA',
            'X_FORWARDED_FOR',
            'FORWARDED_FOR',
            'X_FORWARDED',
            'FORWARDED',
            'CLIENT_IP',
            'FORWARDED_FOR_IP',
            'HTTP_PROXY_CONNECTION'
        ];

        foreach ($proxyHeaders as $header) {
            if (isset($_SERVER[$header])) {
                return true;
            }
        }

        return false;
    }

    private function getCurrencyByCountry(string $countryCode): string {
        $currencies = [
            'TR' => 'TRY',
            'US' => 'USD',
            'GB' => 'GBP',
            'EU' => 'EUR',
            // Diğer ülkeler eklenebilir
        ];
        
        return $currencies[strtoupper($countryCode)] ?? 'Unknown';
    }

    private function getCallingCode(string $countryCode): string {
        $callingCodes = [
            'TR' => '+90',
            'US' => '+1',
            'GB' => '+44',
            'DE' => '+49',
            // Diğer ülkeler eklenebilir
        ];
        
        return $callingCodes[strtoupper($countryCode)] ?? 'Unknown';
    }

    private function getCountryFlag(string $countryCode): string {
        // Unicode bayrak emojisi oluştur
        if (strlen($countryCode) === 2) {
            $flag = mb_convert_encoding('&#' . (127397 + ord(strtoupper($countryCode[0]))) . ';', 'UTF-8', 'HTML-ENTITIES');
            $flag .= mb_convert_encoding('&#' . (127397 + ord(strtoupper($countryCode[1]))) . ';', 'UTF-8', 'HTML-ENTITIES');
            return $flag;
        }
        
        return '🏳️'; // Bilinmeyen ülke için beyaz bayrak
    }
}

// Kullanım örneği:
try {
    $config = [
        'cache_enabled' => true,
        'geolocation_provider' => 'ip-api',
        'log_enabled' => true,
        'api_keys' => [
            'maxmind' => 'your_api_key',
            'ipqualityscore' => 'your_api_key'
        ]
    ];
    
    $security = IPSecurityLibrary::getInstance($config);
    $analysis = $security->analyzeIP();
    
    // Sonuçları kullan
    if ($analysis['risk_assessment']['risk_level'] === 'HIGH') {
        // Yüksek riskli ziyaretçi için önlemler al
        // Örnek: CAPTCHA göster, erişimi engelle vb.
    }
    
} catch (\Exception $e) {
    // Hata yönetimi
    error_log("IP Security Error: " . $e->getMessage());
}
?> 