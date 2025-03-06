<?php
require_once 'SimpleCache.php';
require_once 'IPSecurityLibrary.php';

use Security\IPSecurityLibrary;

// CORS başlıkları (gerekirse)
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json; charset=utf-8');

// Log klasörünü kontrol et ve oluştur
$logDir = 'logs';
if (!is_dir($logDir)) {
    mkdir($logDir, 0755, true);
}

try {
    $config = [
        'cache_enabled' => true,
        'geolocation_provider' => 'ip-api',
        'log_enabled' => true
    ];
    
    $security = IPSecurityLibrary::getInstance($config);
    
    // IP parametresi varsa onu kullan, yoksa ziyaretçinin IP'sini al
    $ip = $_GET['ip'] ?? null;
    $analysis = $security->analyzeIP($ip);
    
    // Sadece gerekli bilgileri içeren array oluştur
    $response = [
        'success' => true,
        'data' => [
            'ip' => $analysis['ip'],
            'timestamp' => date('Y-m-d H:i:s'),
            'location' => $analysis['geolocation'] ?? null,
            'network_info' => [
                'is_datacenter' => $analysis['network_info']['is_datacenter'] ?? false,
                'is_isp' => $analysis['network_info']['is_isp'] ?? false,
                'asn_info' => $analysis['network_info']['asn_info'] ?? null,
                'proxy_type' => $analysis['network_info']['proxy_type'] ?? null,
                'usage_type' => $analysis['network_info']['usage_type'] ?? null,
                'fraud_score' => $analysis['network_info']['fraud_score'] ?? 0
            ],
            'device_info' => [
                'type' => $analysis['device_info']['type'] ?? 'Unknown',
                'brand' => $analysis['device_info']['brand'] ?? 'Unknown',
                'model' => $analysis['device_info']['model'] ?? 'Unknown',
                'is_mobile' => $analysis['device_info']['is_mobile'] ?? false,
                'is_tablet' => $analysis['device_info']['is_tablet'] ?? false,
                'is_desktop' => $analysis['device_info']['is_desktop'] ?? false
            ],
            'operating_system' => [
                'name' => $analysis['operating_system']['name'] ?? 'Unknown',
                'version' => $analysis['operating_system']['version'] ?? 'Unknown',
                'architecture' => $analysis['operating_system']['architecture'] ?? 'Unknown'
            ],
            'browser' => [
                'name' => $analysis['browser_info']['name'] ?? 'Unknown',
                'version' => $analysis['browser_info']['version'] ?? 'Unknown',
                'user_agent' => $analysis['browser_info']['user_agent'] ?? 'Unknown',
                'features' => $analysis['browser_info']['features'] ?? []
            ],
            'language' => [
                'code' => $analysis['language_info']['primary']['code'] ?? 'Unknown',
                'name' => $analysis['language_info']['primary']['name'] ?? 'Unknown',
                'all' => $analysis['language_info']['all'] ?? []
            ],
            'security' => [
                'risk_level' => $analysis['risk_assessment']['risk_level'],
                'risk_score' => $analysis['risk_assessment']['total_risk_score'],
                'risk_factors' => $analysis['risk_assessment']['risk_factors'] ?? [],
                'recommendations' => $analysis['risk_assessment']['recommendations'] ?? [],
                'is_proxy' => $analysis['security_checks']['is_proxy'] ?? false,
                'is_vpn' => $analysis['security_checks']['is_vpn'] ?? false,
                'is_tor' => $analysis['security_checks']['is_tor'] ?? false,
                'threat_score' => $analysis['security_checks']['threat_score'] ?? 0,
                'abuse_confidence_score' => $analysis['security_checks']['abuse_confidence_score'] ?? 0
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
        'ip' => $analysis['ip'],
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
    $errorResponse = [
        'success' => false,
        'error' => $e->getMessage(),
        'timestamp' => time()
    ];
    
    // Hata logunu kaydet
    $date = date('Y-m-d_H-i-s');
    $logFile = "{$logDir}/error_{$date}.txt";
    
    $logContent = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_GET['ip'] ?? 'auto',
        'error' => $e->getMessage(),
        'response' => $errorResponse
    ];
    
    file_put_contents(
        $logFile, 
        json_encode($logContent, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
    );
    
    http_response_code(500);
    echo json_encode($errorResponse);
} 