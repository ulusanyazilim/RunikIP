# RunikIP - Gelişmiş IP Analiz ve Güvenlik Kütüphanesi

RunikIP, IP adreslerini analiz eden, güvenlik kontrolü yapan ve detaylı bilgiler sunan güçlü bir PHP kütüphanesidir. Ziyaretçilerinizin IP adreslerini hızlı ve güvenilir bir şekilde analiz ederek, güvenlik risklerini tespit etmenize yardımcı olur.

## 🚀 Özellikler

- **Detaylı IP Analizi**: IP adreslerinin coğrafi konum, ISP, zaman dilimi ve daha fazla bilgisini sağlar
- **Güvenlik Kontrolü**: VPN, Proxy, Tor ve veri merkezi IP'lerini tespit eder
- **Risk Değerlendirmesi**: IP adreslerinin güvenlik riskini hesaplar ve risk seviyesini belirler
- **Tarayıcı ve Cihaz Bilgileri**: Ziyaretçinin tarayıcı, işletim sistemi ve cihaz bilgilerini tespit eder
- **Önbellek Sistemi**: Performansı artırmak için sonuçları önbelleğe alır
- **Detaylı Loglama**: Tüm analizleri ve hataları loglar
- **Kolay Entegrasyon**: Basit API ile her projeye kolayca entegre edilebilir

## 📊 API Kullanımı

### Endpoint

```
GET /api.php
```

### Parametreler

- `ip` (opsiyonel) - Sorgulanacak IP adresi. Belirtilmezse ziyaretçinin IP'si kullanılır.

### Örnek Kullanımlar

1. Belirli bir IP için sorgu:
```
GET /api.php?ip=8.8.8.8
```

2. Ziyaretçinin IP'si için sorgu:
```
GET /api.php
```

### Örnek Yanıt

```json
{
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
}
```

### Hata Yanıtı

```json
{
    "success": false,
    "error": "Invalid IP address",
    "timestamp": 1707242486
}
```

### Notlar

- API yanıtları JSON formatındadır
- Başarılı yanıtlarda HTTP 200 kodu döner
- Hata durumunda HTTP 500 kodu döner
- Önbellek sistemi varsayılan olarak aktiftir (1 saat)

## 📋 Kütüphane Kullanımı

```php
<?php
require_once 'SimpleCache.php';
require_once 'IPSecurityLibrary.php';

use Security\IPSecurityLibrary;

// Konfigürasyon (opsiyonel)
$config = [
    'cache_enabled' => true,
    'geolocation_provider' => 'ip-api',
    'log_enabled' => true
];

// Kütüphaneyi başlat
$security = IPSecurityLibrary::getInstance($config);

// IP analizi yap
$ip = '8.8.8.8'; // veya null kullanarak ziyaretçinin IP'sini al
$analysis = $security->analyzeIP($ip);

// Sonuçları kullan
echo "IP: " . $analysis['ip'] . "\n";
echo "Ülke: " . $analysis['geolocation']['country']['name'] . "\n";
echo "Risk Seviyesi: " . $analysis['risk_assessment']['risk_level'] . "\n";
?>
```

## 📞 İletişim

Soru, öneri ve geri bildirimleriniz için:

- E-posta: ulusanyazilim@gmail.com
- GitHub: [RunikIP GitHub Sayfası](https://github.com/rmb/RunikIP)

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakınız. 