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
echo "<h3>Dönen Veri Alanları</h3>";
echo "<ul>";
echo "<li><code>ip</code> - Sorgulanan IP adresi</li>";
echo "<li><code>timestamp</code> - Sorgu zamanı (Unix timestamp)</li>";
echo "<li><code>location</code> - Coğrafi konum bilgileri
    <ul>
        <li>country (ülke bilgileri)</li>
        <li>region (bölge bilgileri)</li>
        <li>city (şehir)</li>
        <li>postal_code (posta kodu)</li>
        <li>location (enlem/boylam)</li>
    </ul>
</li>";
echo "<li><code>network_info</code> - Ağ bilgileri
    <ul>
        <li>is_datacenter (Datacenter IP mi?)</li>
        <li>is_isp (ISP IP'si mi?)</li>
        <li>asn_info (ASN bilgileri)
            <ul>
                <li>asn (Autonomous System Number)</li>
                <li>organization (Organizasyon adı)</li>
                <li>isp (Internet Service Provider)</li>
            </ul>
        </li>
        <li>proxy_type (Proxy tipi bilgileri)</li>
        <li>usage_type (IP kullanım tipi)
            <ul>
                <li>ISP - Internet servis sağlayıcı</li>
                <li>PUB - Bireysel/Ev kullanıcısı</li>
                <li>MOB - Mobil operatör</li>
                <li>SAT - Uydu bağlantısı</li>
                <li>PROXY - Proxy/VPN/TOR</li>
                <li>DCH - Veri merkezi/Hosting</li>
                <li>COM - Ticari kullanım</li>
            </ul>
        </li>
        <li>ip_location (IP Location detaylı bilgileri)
            <ul>
                <li>is_proxy (Proxy durumu)</li>
                <li>is_datacenter (Datacenter durumu)</li>
                <li>is_vpn (VPN durumu)</li>
                <li>is_tor (TOR durumu)</li>
                <li>is_mobile (Mobil bağlantı durumu)</li>
                <li>is_satellite (Uydu bağlantı durumu)</li>
                <li>company_type (Şirket tipi)</li>
                <li>source (Veri kaynağı)</li>
                <li>connection_type (Bağlantı tipi)</li>
                <li>threat_level (Tehdit seviyesi)</li>
                <li>threat_types (Tehdit tipleri)</li>
                <li>abuse_score (Kötüye kullanım skoru)</li>
                <li>asn_abuse_score (ASN kötüye kullanım skoru)</li>
                <li>confidence_score (Güven skoru)</li>
            </ul>
        </li>
    </ul>
</li>";
echo "<li><code>security</code> - Güvenlik bilgileri
    <ul>
        <li>risk_level (Risk seviyesi: LOW/MEDIUM/HIGH)</li>
        <li>risk_score (Risk skoru)</li>
        <li>risk_factors (Risk faktörleri)</li>
        <li>is_proxy (Proxy kullanımı)</li>
        <li>is_vpn (VPN kullanımı)</li>
        <li>is_tor (TOR kullanımı)</li>
        <li>threat_score (Tehdit skoru)</li>
        <li>abuse_confidence_score (Kötüye kullanım güven skoru)</li>
    </ul>
</li>";
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
        "timestamp": "2024-02-07 15:30:45",
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
            "city": "Mountain View"
        },
        "network_info": {
            "is_datacenter": true,
            "is_isp": false,
            "asn_info": {
                "asn": "AS15169",
                "organization": "Google LLC",
                "isp": "Google LLC"
            },
            "proxy_type": "DCH",
            "usage_type": "DCH",
            "ip_location": {
                "is_proxy": false,
                "is_datacenter": true,
                "is_vpn": false,
                "is_tor": false,
                "is_mobile": false,
                "is_satellite": false,
                "company_type": "hosting",
                "source": "ipapi_is",
                "connection_type": "datacenter",
                "threat_level": "low",
                "threat_types": [],
                "abuse_score": 0,
                "asn_abuse_score": 0,
                "confidence_score": 100
            }
        },
        "security": {
            "risk_level": "LOW",
            "risk_score": 0,
            "risk_factors": ["datacenter_ip"],
            "is_proxy": false,
            "is_vpn": false,
            "is_tor": false,
            "threat_score": 0,
            "abuse_confidence_score": 0
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
    "message": "Invalid IP address",
    "code": 400
}', ENT_QUOTES);
echo "</pre>";

// Notlar
echo "<h3>Notlar</h3>";
echo "<ul>";
echo "<li>API yanıtları JSON formatındadır</li>";
echo "<li>Başarılı yanıtlarda HTTP 200 kodu döner</li>";
echo "<li>Hata durumunda ilgili HTTP kodu döner (400, 403, 500 vb.)</li>";
echo "<li>Cache sistemi varsayılan olarak aktiftir (1 saat)</li>";
echo "<li>Network bilgileri (datacenter/ISP) gerçek zamanlı olarak kontrol edilir</li>";
echo "<li>ASN bilgileri birden fazla kaynaktan doğrulanır</li>";
echo "<li>Datacenter ve ISP tespiti için geniş bir veritabanı kullanılır</li>";
echo "<li>Proxy tipleri ve kullanım tipleri detaylı olarak sınıflandırılır</li>";
echo "<li>Risk skorları ve tehdit seviyeleri çoklu faktöre göre hesaplanır</li>";
echo "<li>Türk ISP'leri için özel optimizasyon yapılmıştır</li>";
echo "</ul>";

echo "</div>";

echo '</body></html>';
?> 