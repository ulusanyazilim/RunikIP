<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once 'IPSecurityLibrary.php';
require_once 'SimpleCache.php';

use Security\IPSecurityLibrary;

// Log klasörünü kontrol et ve oluştur
$logDir = 'logs';
if (!is_dir($logDir)) {
    mkdir($logDir, 0755, true);
}

try {
    // IP adresi parametresini al
    $ip = $_GET['ip'] ?? null;
    
    // API anahtarı kontrolü (isteğe bağlı)
    $apiKey = $_GET['api_key'] ?? null;
    if ($apiKey !== null && $apiKey !== 'YOUR_API_KEY') {
        throw new Exception('Geçersiz API anahtarı', 403);
    }
    
    // Konfigürasyon
    $config = [
        'cache_enabled' => true,
        'geolocation_provider' => 'ip-api',
        'log_enabled' => true,
        'log_path' => 'security_logs/',
        'proxy_check_enabled' => true,
        'tor_check_enabled' => true,
        'vpn_check_enabled' => true,
        'asn_database_path' => 'databases/IP2LOCATION-LITE-ASN.CSV',
        'datacenter_database_path' => 'databases/IP2LOCATION-DATACENTER.CSV',
        'ip2location_enabled' => true,
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
    ];
    
    // IP Güvenlik Kütüphanesini başlat
    $ipSecurity = IPSecurityLibrary::getInstance($config);
    
    // IP analizini gerçekleştir
    $result = $ipSecurity->analyzeIP($ip);
    
    // IP Location verilerini al
    $ipLocationData = $ipSecurity->getIPLocationData($ip);
    
    // Sadece gerekli bilgileri içeren array oluştur
    $response = [
        'success' => true,
        'data' => [
            'ip' => $result['ip'],
            'timestamp' => date('Y-m-d H:i:s'),
            'location' => $result['geolocation'] ?? null,
            'network_info' => [
                'is_datacenter' => $result['network_info']['is_datacenter'] ?? false,
                'is_isp' => $result['network_info']['is_isp'] ?? false,
                'asn_info' => $result['network_info']['asn_info'] ?? null,
                'proxy_type' => $result['network_info']['proxy_type'] ?? null,
                'usage_type' => $result['network_info']['usage_type'] ?? null,
                'fraud_score' => $result['network_info']['fraud_score'] ?? 0,
                'ip_location' => [
                    'is_proxy' => $ipLocationData['is_proxy'] ?? false,
                    'is_datacenter' => $ipLocationData['is_datacenter'] ?? false,
                    'is_vpn' => $ipLocationData['is_vpn'] ?? false,
                    'is_tor' => $ipLocationData['is_tor'] ?? false,
                    'is_mobile' => $ipLocationData['is_mobile'] ?? false,
                    'is_satellite' => $ipLocationData['is_satellite'] ?? false,
                    'company_type' => $ipLocationData['company_type'] ?? null,
                    'source' => $ipLocationData['source'] ?? null,
                    'country' => $ipLocationData['country'] ?? null,
                    'country_code' => $ipLocationData['country_code'] ?? null,
                    'region' => $ipLocationData['region'] ?? null,
                    'city' => $ipLocationData['city'] ?? null,
                    'isp' => $ipLocationData['isp'] ?? null,
                    'org_name' => $ipLocationData['org_name'] ?? null,
                    'as_no' => $ipLocationData['as_no'] ?? null,
                    'postal_code' => $ipLocationData['postal_code'] ?? null,
                    'latitude' => $ipLocationData['latitude'] ?? null,
                    'longitude' => $ipLocationData['longitude'] ?? null,
                    'abuse_score' => $ipLocationData['abuse_score'] ?? null,
                    'asn_abuse_score' => $ipLocationData['asn_abuse_score'] ?? null,
                    'connection_type' => $ipLocationData['connection_type'] ?? null,
                    'proxy_type' => $ipLocationData['proxy_type'] ?? null,
                    'threat_level' => $ipLocationData['threat_level'] ?? null,
                    'threat_types' => $ipLocationData['threat_types'] ?? [],
                    'confidence_score' => $ipLocationData['confidence_score'] ?? null
                ]
            ],
            'device_info' => [
                'type' => $result['device_info']['type'] ?? 'Unknown',
                'brand' => $result['device_info']['brand'] ?? 'Unknown',
                'model' => $result['device_info']['model'] ?? 'Unknown',
                'is_mobile' => $result['device_info']['is_mobile'] ?? false,
                'is_tablet' => $result['device_info']['is_tablet'] ?? false,
                'is_desktop' => $result['device_info']['is_desktop'] ?? false
            ],
            'operating_system' => [
                'name' => $result['operating_system']['name'] ?? 'Unknown',
                'version' => $result['operating_system']['version'] ?? 'Unknown',
                'architecture' => $result['operating_system']['architecture'] ?? 'Unknown'
            ],
            'browser' => [
                'name' => $result['browser_info']['name'] ?? 'Unknown',
                'version' => $result['browser_info']['version'] ?? 'Unknown',
                'user_agent' => $result['browser_info']['user_agent'] ?? 'Unknown',
                'features' => $result['browser_info']['features'] ?? []
            ],
            'language' => [
                'code' => $result['language_info']['primary']['code'] ?? 'Unknown',
                'name' => $result['language_info']['primary']['name'] ?? 'Unknown',
                'all' => $result['language_info']['all'] ?? []
            ],
            'security' => [
                'risk_level' => $result['risk_assessment']['level'] ?? 'unknown',
                'risk_score' => $result['risk_assessment']['score'] ?? 0,
                'risk_factors' => $result['risk_assessment']['factors'] ?? [],
                'is_proxy' => $result['security_checks']['is_proxy'] ?? false,
                'is_vpn' => $result['security_checks']['is_vpn'] ?? false,
                'is_tor' => $result['security_checks']['is_tor'] ?? false,
                'threat_score' => $ipLocationData['threat_level'] ?? 0,
                'abuse_confidence_score' => $ipLocationData['abuse_score'] ?? 0
            ],
            'cached' => $config['cache_enabled']
        ],
        'timestamp' => time()
    ];
    
    // Log dosyası oluştur
    $date = date('Y-m-d_H-i-s');
    $logFile = "{$logDir}/{$date}.txt";
    
    // Log içeriği
    $logContent = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $result['ip'],
        'request_ip' => $ip ?? 'auto',
        'response' => $response
    ];
    
    // Log dosyasına yaz
    file_put_contents(
        $logFile, 
        json_encode($logContent, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
    );
    
    // Yanıtı gönder
    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    
} catch (Exception $e) {
    http_response_code($e->getCode() ?: 500);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage(),
        'code' => $e->getCode()
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
} 