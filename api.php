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
            'location' => $analysis['geolocation'] ?? null,
            'browser' => [
                'name' => $analysis['browser_info']['name'] ?? 'Unknown',
                'version' => $analysis['browser_info']['version'] ?? 'Unknown',
                'user_agent' => $analysis['browser_info']['user_agent'] ?? 'Unknown'
            ],
            'language' => [
                'code' => $analysis['language_info']['primary']['code'] ?? 'Unknown',
                'name' => $analysis['language_info']['primary']['name'] ?? 'Unknown'
            ],
            'security' => [
                'risk_level' => $analysis['risk_assessment']['risk_level'],
                'risk_score' => $analysis['risk_assessment']['total_risk_score'],
                'is_proxy' => $analysis['security_checks']['is_proxy'] ?? false,
                'is_vpn' => $analysis['security_checks']['is_vpn'] ?? false,
                'is_tor' => $analysis['security_checks']['is_tor'] ?? false
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