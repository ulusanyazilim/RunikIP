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
            '/windows nt 11/i'      => ['Windows 11', 'NT 11.0'],
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
            '/debian/i'             => ['Debian', ''],
            '/fedora/i'             => ['Fedora', ''],
            '/centos/i'             => ['CentOS', ''],
            '/redhat/i'             => ['Red Hat', ''],
            '/mint/i'               => ['Linux Mint', ''],
            '/arch/i'               => ['Arch Linux', ''],
            '/iphone/i'             => ['iPhone', 'iOS'],
            '/ipod/i'               => ['iPod', 'iOS'],
            '/ipad/i'               => ['iPad', 'iOS'],
            '/android/i'            => ['Android', ''],
            '/webos/i'              => ['Mobile', ''],
            '/chromeos|cros/i'      => ['Chrome OS', ''],
            '/freebsd/i'            => ['FreeBSD', ''],
            '/openbsd/i'            => ['OpenBSD', ''],
            '/netbsd/i'             => ['NetBSD', ''],
            '/sunos/i'              => ['SunOS', ''],
            '/solaris/i'            => ['Solaris', ''],
            '/playstation/i'        => ['PlayStation', ''],
            '/xbox/i'               => ['Xbox', ''],
            '/nintendo/i'           => ['Nintendo', ''],
            '/roku/i'               => ['Roku', ''],
            '/tizen/i'              => ['Tizen', ''],
            '/sailfish/i'           => ['Sailfish OS', ''],
            '/harmony/i'            => ['Harmony OS', ''],
            '/kaios/i'              => ['KaiOS', '']
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
            'Apple' => '/iphone|ipad|ipod|macintosh|mac os|iwatch|airpods/i',
            'Samsung' => '/samsung|galaxy|sm-[a-z0-9]+/i',
            'Huawei' => '/huawei|honor|h60|h30|mate|p[0-9]+|nova/i',
            'Xiaomi' => '/xiaomi|redmi|poco|mi [0-9]|mi note|mi max|mi mix|mi pad/i',
            'LG' => '/lg|lge|lm-[a-z0-9]+/i',
            'Sony' => '/sony|xperia|sonyericsson/i',
            'HTC' => '/htc|htc_|htc-/i',
            'Motorola' => '/motorola|moto [a-z]|moto[a-z][0-9]|moto g|moto e|moto x/i',
            'Nokia' => '/nokia|lumia|maemo/i',
            'Microsoft' => '/windows phone|windows mobile|microsoft|lumia/i',
            'Google' => '/pixel|nexus/i',
            'OnePlus' => '/oneplus|one plus|op[0-9][0-9]|nord/i',
            'OPPO' => '/oppo|cph[0-9]+|find x|reno/i',
            'Vivo' => '/vivo|v[0-9]+[a-z]?/i',
            'Realme' => '/realme|rmx[0-9]+/i',
            'Asus' => '/asus|zenfone|zenpad|zenbook|rog phone/i',
            'Lenovo' => '/lenovo|thinkpad|ideapad|yoga/i',
            'Acer' => '/acer|aspire|predator/i',
            'Dell' => '/dell|xps|inspiron|latitude|precision/i',
            'HP' => '/hp|hewlett-packard|pavilion|envy|spectre|omen/i',
            'Toshiba' => '/toshiba|satellite|portege|tecra/i',
            'BlackBerry' => '/blackberry|bb[0-9]+|rim tablet/i',
            'ZTE' => '/zte|blade|axon|nubia/i',
            'Alcatel' => '/alcatel|one touch/i',
            'TCL' => '/tcl|alcatel|idol/i',
            'Meizu' => '/meizu|m[0-9]+/i',
            'Sharp' => '/sharp|aquos/i',
            'Philips' => '/philips|phl/i',
            'BQ' => '/bq|aquaris/i',
            'Wiko' => '/wiko|view|sunny|lenny|jerry/i',
            'Nothing' => '/nothing phone/i',
            'Fairphone' => '/fairphone/i'
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
            'ja' => '日本語',
            'ko' => '한국어',
            'pt' => 'Português',
            'nl' => 'Nederlands',
            'pl' => 'Polski',
            'sv' => 'Svenska',
            'da' => 'Dansk',
            'fi' => 'Suomi',
            'no' => 'Norsk',
            'cs' => 'Čeština',
            'hu' => 'Magyar',
            'el' => 'Ελληνικά',
            'he' => 'עברית',
            'hi' => 'हिन्दी',
            'th' => 'ไทย',
            'vi' => 'Tiếng Việt',
            'id' => 'Bahasa Indonesia',
            'ms' => 'Bahasa Melayu',
            'fa' => 'فارسی',
            'uk' => 'Українська',
            'ro' => 'Română',
            'bg' => 'Български',
            'hr' => 'Hrvatski',
            'sr' => 'Српски',
            'sk' => 'Slovenčina',
            'sl' => 'Slovenščina',
            'et' => 'Eesti',
            'lv' => 'Latviešu',
            'lt' => 'Lietuvių',
            'az' => 'Azərbaycan',
            'kk' => 'Қазақша',
            'uz' => 'O\'zbek',
            'hy' => 'Հայերեն',
            'ka' => 'ქართული',
            'bn' => 'বাংলা',
            'ur' => 'اردو',
            'ta' => 'தமிழ்',
            'te' => 'తెలుగు',
            'ml' => 'മലയാളം',
            'mr' => 'मराठी',
            'ne' => 'नेपाली',
            'si' => 'සිංහල',
            'km' => 'ខ្មែរ',
            'lo' => 'ລາວ',
            'my' => 'မြန်မာ'
        ];
        
        $code = strtolower(substr($code, 0, 2));
        return $languages[$code] ?? $code;
    }

    private function isMobileDevice(string $userAgent): bool {
        $mobilePatterns = [
            // Genel mobil belirteçler
            '/Mobile|Portable|Tablet|Android|Touch/i',
            
            // Apple cihazlar
            '/iP(hone|od|ad)|iOS|iPhone OS/i',
            
            // Android cihazlar
            '/Android.*Mobile|Android.*Chrome|Android.*Firefox/i',
            
            // Windows mobil cihazlar
            '/Windows Phone|Windows Mobile|Windows CE|IEMobile|WPDesktop|ZuneWP7/i',
            
            // Diğer mobil işletim sistemleri
            '/BlackBerry|BB10|RIM Tablet OS|webOS|PalmOS|bada|Tizen|Kindle|Silk|KF[A-Z][A-Z]|FBAN|FBAV/i',
            
            // Mobil tarayıcılar
            '/Opera Mini|Opera Mobi|OPiOS|Coast|Instagram|FBAN|FBAV/i',
            
            // Akıllı saatler ve giyilebilir cihazlar
            '/Watch|Glass|Gear|Fitbit|Galaxy Watch|Mi Band|Apple Watch/i',
            
            // Oyun konsolları
            '/Nintendo|PlayStation|Xbox|PS[0-9]|PSP/i',
            
            // Diğer mobil cihazlar
            '/Symbian|Series[0-9]|S60|SonyEricsson|Nokia|DoCoMo|KDDI|UP.Browser|J2ME|MIDP|cldc|NetFront|Dolfin|Jasmine|Fennec/i',
            
            // Mobil operatör belirteçleri
            '/Vodafone|T-Mobile|Sprint|AT&T|Verizon|O2|Orange|Turkcell|Turk Telekom|TTNET/i'
        ];
        
        foreach ($mobilePatterns as $pattern) {
            if (preg_match($pattern, $userAgent) === 1) {
                return true;
            }
        }
        
        return false;
    }

    private function isTabletDevice(string $userAgent): bool {
        $tabletPatterns = [
            // Genel tablet belirteçler
            '/Tablet|tab/i',
            
            // iPad ve iOS tabletler
            '/iPad|iPad.*Mobile|iPad.*Safari/i',
            
            // Android tabletler (mobil olmayan)
            '/Android(?!.*Mobile)|Android.*Chrome(?!.*Mobile)|Android.*Firefox(?!.*Mobile)/i',
            
            // Windows tabletler
            '/Windows.*Touch|Windows.*Tablet|Windows NT.*Touch|Windows.*ARM|KFAPWI/i',
            
            // Amazon Kindle ve Fire tabletler
            '/Kindle|Silk|KFTT|KFOT|KFJWA|KFJWI|KFSOWI|KFTHWA|KFTHWI|KFAPWA|KFAPWI|KFARWI|KFASWI|KFTBWI|KFMEWI|KFFOWI|KFSAWA|KFSAWI|KFARWI|KFASWI|KFTBWI|KFMEWI|KFFOWI/i',
            
            // Samsung tabletler
            '/SM-T|GT-P|SC-01C|SCH-I800|SGH-I987|SGH-T849|SGH-T859|SGH-T869|SPH-P100|GT-P1000|GT-P3100|GT-P3110|GT-P5100|GT-P5110|GT-P6200|GT-P6800|GT-P7100|GT-P7300|GT-P7310|GT-P7500|GT-P7510|SCH-I800|SCH-I815|SCH-I905|SGH-I957|SGH-I987|SGH-T849|SGH-T859|SGH-T869|SPH-P100|GT-P3113|GT-P5113|GT-P8110|GT-N8000|GT-N8010|GT-N8020|GT-N5100|GT-N5110|SHV-E140K|SHV-E140L|SHV-E140S|SHV-E150S|SHV-E230K|SHV-E230L|SHV-E230S|SHW-M180K|SHW-M180L|SHW-M180S|SHW-M180W|SHW-M300W|SHW-M305W|SHW-M380K|SHW-M380S|SHW-M380W|SHW-M430W|SHW-M480K|SHW-M480S|SHW-M480W|SHW-M485W|SHW-M486W|SHW-M500W|GT-I9500|GT-I9502|GT-I9505|GT-I9508|SM-P900|SM-P901|SM-P905|SM-T111|SM-T210|SM-T211|SM-T230|SM-T231|SM-T235|SM-T280|SM-T285|SM-T310|SM-T311|SM-T315|SM-T320|SM-T321|SM-T325|SM-T330|SM-T331|SM-T335|SM-T350|SM-T355|SM-T360|SM-T365|SM-T370|SM-T375|SM-T377|SM-T380|SM-T385|SM-T510|SM-T515|SM-T520|SM-T525|SM-T530|SM-T535|SM-T550|SM-T555|SM-T560|SM-T561|SM-T580|SM-T585|SM-T587|SM-T590|SM-T595|SM-T597|SM-T710|SM-T713|SM-T715|SM-T719|SM-T720|SM-T725|SM-T810|SM-T815|SM-T817|SM-T819|SM-T820|SM-T825|SM-T827|SM-T830|SM-T835|SM-T837|SM-T860|SM-T865|SM-T867|SM-P610|SM-P615|SM-T290|SM-T295|SM-T500|SM-T505|SM-T220|SM-T225|SM-T970|SM-T975|SM-T976|SM-T870|SM-T875|SM-T876|SM-T730|SM-T735|SM-T736|SM-X700|SM-X706|SM-X800|SM-X806|SM-X900|SM-X906/i',
            
            // Huawei tabletler
            '/MediaPad|HUAWEI.*MediaPad|MediaPad.*Huawei|AGS2-W09|AGS2-L09|AGS2-L03|AGS2-W19|BAH2-W19|BAH2-L09|BAH2-W09|BAH-W09|BAH-L09|BG2-W09|CMR-W09|CMR-AL09|CMR-W19|CPN-W09|CPN-AL00|JDN2-W09|JDN2-L09|M2-801L|M2-801W|M2-802L|M2-803L|M3-801L|M3-801W|M3-802L|M3-803L|M5-801L|M5-801W|M5-802L|M5-803L|M6-801L|M6-801W|M6-802L|M6-803L|SCM-W09|SHT-W09|SHT-AL09|AGS3-W09|AGS3-L09|DBY-W09|DBY-L09|HarmonyOS|MatePad/i',
            
            // Lenovo tabletler
            '/Lenovo.*Tab|IdeaTab|IdeaPad|Lenovo.*Yoga|Yoga.*Tab|TB-X103F|TB-X304F|TB-X304L|TB-X304X|TB-X505F|TB-X505L|TB-X505X|TB-X605F|TB-X605L|TB-X605LC|TB-X606F|TB-X606FA|TB-X606X|TB-J606F|TB-J606L|TB-8504F|TB-8504X|TB-8504L|TB-8704F|TB-8704X|TB-8704V|TB-8704N|TB-7504F|TB-7504X|TB-7504L|TB-7304F|TB-7304X|TB-7304I|TB-7304L|TB-X304F|TB-X304L|TB-X304X|TB-X505F|TB-X505L|TB-X505X|TB-X605F|TB-X605L|TB-X605LC|TB-X606F|TB-X606FA|TB-X606X|TB-J606F|TB-J606L/i',
            
            // Asus tabletler
            '/ASUS.*Pad|Transformer|TF101|TF201|TF300|TF700|TF701|TF810|ME171|ME172|ME173|ME176|ME176C|ME176CE|ME181|ME181C|ME302|ME302C|ME302KL|ME371|ME372|ME372CG|ME372CL|ME572|ME572C|ME572CL|ME176|ME176C|ME176CE|ME181|ME181C|ME302|ME302C|ME302KL|ME371|ME372|ME372CG|ME372CL|ME572|ME572C|ME572CL|P01Y|P01Z|P01T|P01V|P01MA|P01W|P00C|P00I|P00A|P01W|P01V|P01MA|P01T|P01Z|P01Y|P00C|P00I|P00A/i',
            
            // Diğer tablet üreticileri
            '/PlayBook|RIM Tablet|HTC.*Flyer|HTC.*Jetstream|HTC.*Tablet|Nexus 7|Nexus 9|Nexus 10|Dell.*Streak|Dell.*Venue|Dell.*Latitude|HP.*TouchPad|Venue 8|Venue 7|Venue 10|XiaoMi.*Pad|Mi.*Pad|Redmi.*Pad|OPPO.*Pad|vivo.*Pad|realme.*Pad|TCL.*Tab|Honor.*Pad|Nokia.*Tab/i'
        ];
        
        foreach ($tabletPatterns as $pattern) {
            if (preg_match($pattern, $userAgent) === 1) {
                return true;
            }
        }
        
        // Mobil olmayan Android cihazları tablet olarak kabul et
        if (preg_match('/Android/i', $userAgent) === 1 && preg_match('/Mobile/i', $userAgent) === 0) {
            return true;
        }
        
        return false;
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