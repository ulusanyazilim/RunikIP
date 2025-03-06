<?php
/* Author: ulusanyazilim@gmail.com */
require_once 'SimpleCache.php';
require_once 'IPSecurityLibrary.php';

use Security\IPSecurityLibrary;

// Stil ve başlık kısmı
echo '<html><head>';
echo '<title>IP Bilgi Sistemi - Dokümantasyon</title>';
echo '<style>
    body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
    .section { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    .section h2 { margin-top: 0; color: #333; }
    .endpoint { background: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }
    .method { color: #009900; font-weight: bold; }
    .param { color: #0066cc; }
    .example { background: #fff; padding: 10px; border: 1px solid #eee; margin: 10px 0; }
    .response { background: #f8f8f8; padding: 10px; border-left: 4px solid #009900; }
    .button {
        display: inline-block;
        padding: 10px 20px;
        background: #007bff;
        color: white;
        text-decoration: none;
        border-radius: 5px;
        margin: 10px 0;
    }
    .button:hover {
        background: #0056b3;
    }
    code {
        background: #f8f8f8;
        padding: 2px 5px;
        border-radius: 3px;
    }
</style>';
echo '</head><body>';

// Mevcut IP'yi al
$security = IPSecurityLibrary::getInstance();
$currentIP = $security->analyzeIP()['ip'];

// Demo butonu
echo "<div class='section'>";
echo "<h2>🔍 Canlı Demo</h2>";
echo "<p>Mevcut IP adresiniz: <strong>{$currentIP}</strong></p>";
echo "<a href='api.php?ip={$currentIP}' target='_blank' class='button'>API Sonucunu Görüntüle</a>";
echo "</div>";

// API Dokümantasyonu
echo "<div class='section'>";
echo "<h2>📚 API Dokümantasyonu</h2>";

// Endpoint Bilgisi
echo "<h3>Endpoint</h3>";
echo "<div class='endpoint'><span class='method'>GET</span> /api.php</div>";

// Parametreler
echo "<h3>Parametreler</h3>";
echo "<ul>";
echo "<li><code>ip</code> (opsiyonel) - Sorgulanacak IP adresi. Belirtilmezse ziyaretçinin IP'si kullanılır.</li>";
echo "</ul>";

// Örnek Kullanımlar
echo "<h3>Örnek Kullanımlar</h3>";
echo "<div class='example'>";
echo "1. Belirli bir IP için sorgu:<br>";
echo "<code>GET /api.php?ip=8.8.8.8</code><br><br>";
echo "2. Ziyaretçinin IP'si için sorgu:<br>";
echo "<code>GET /api.php</code>";
echo "</div>";

// Örnek Yanıt
echo "<h3>Örnek Yanıt</h3>";
echo "<pre class='response'>";
echo htmlspecialchars('{
    "success": true,
    "data": {
        "ip": "8.8.8.8",
        "location": {
            "country": {
                "name": "United States",
                "code": "US",
                "flag": "🇺🇸"
            },
            "region": {
                "name": "California",
                "code": "CA"
            },
            "city": "Mountain View",
            "postal_code": "94043",
            "location": {
                "latitude": 37.4223,
                "longitude": -122.0847
            },
            "isp": "Google LLC",
            "timezone": "America/Los_Angeles"
        },
        "browser": {
            "name": "Chrome",
            "version": "121",
            "user_agent": "Mozilla/5.0 ..."
        },
        "language": {
            "code": "en-US",
            "name": "English"
        },
        "security": {
            "risk_level": "LOW",
            "risk_score": 0,
            "is_proxy": false,
            "is_vpn": false,
            "is_tor": false
        },
        "cached": true
    },
    "timestamp": 1707242486
}', ENT_QUOTES);
echo "</pre>";

// Hata Yanıtı
echo "<h3>Hata Yanıtı</h3>";
echo "<pre class='response'>";
echo htmlspecialchars('{
    "success": false,
    "error": "Invalid IP address",
    "timestamp": 1707242486
}', ENT_QUOTES);
echo "</pre>";

// Notlar
echo "<h3>Notlar</h3>";
echo "<ul>";
echo "<li>API yanıtları JSON formatındadır</li>";
echo "<li>Başarılı yanıtlarda HTTP 200 kodu döner</li>";
echo "<li>Hata durumunda HTTP 500 kodu döner</li>";
echo "<li>Cache sistemi varsayılan olarak aktiftir (1 saat)</li>";
echo "</ul>";

echo "</div>";

echo '</body></html>';
?> 