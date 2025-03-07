<?php
/* Author: ulusanyazilim@gmail.com */
require_once 'SimpleCache.php';
require_once 'IPSecurityLibrary.php';

use Security\IPSecurityLibrary;

// Mevcut IP'yi al
$security = IPSecurityLibrary::getInstance();
$currentIP = $security->analyzeIP()['ip'];
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Bilgi Sistemi - Dokümantasyon</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --bg-dark: #0f172a;
            --bg-darker: #1e293b;
            --text-light: #e2e8f0;
            --text-gray: #94a3b8;
            --border-color: #334155;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: "Inter", sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-light);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .hero {
            text-align: center;
            padding: 4rem 0;
            background: linear-gradient(to right, var(--bg-darker), var(--bg-dark));
            border-radius: 1rem;
            margin-bottom: 3rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        .hero h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            background: linear-gradient(to right, #818cf8, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .hero p {
            color: var(--text-gray);
            font-size: 1.1rem;
            margin-bottom: 2rem;
        }

        .search-box {
            background: var(--bg-darker);
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 3rem;
            border: 1px solid var(--border-color);
        }

        .search-input {
            width: 100%;
            padding: 1rem;
            font-size: 1.1rem;
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            color: var(--text-light);
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }

        .search-button {
            background: var(--primary);
            color: white;
            border: none;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            font-size: 1rem;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .search-button:hover {
            background: var(--primary-dark);
        }

        .result-box {
            background: var(--bg-darker);
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
            display: none;
            position: relative;
        }

        .result-box pre {
            max-height: 500px;
            overflow-y: auto;
        }

        .copy-button {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: var(--primary);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .copy-button:hover {
            background: var(--primary-dark);
        }

        .copy-button i {
            font-size: 1rem;
        }

        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            overflow-x: auto;
            padding-bottom: 0.5rem;
        }

        .tab {
            padding: 0.5rem 1rem;
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            color: var(--text-light);
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.3s ease;
        }

        .tab:hover {
            background: var(--primary);
        }

        .tab.active {
            background: var(--primary);
            border-color: var(--primary);
        }

        .code-examples {
            background: var(--bg-darker);
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }

        .code-example {
            display: none;
            position: relative;
        }

        .code-example.active {
            display: block;
        }

        .info-card {
            background: var(--bg-darker);
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }

        .info-card p {
            color: var(--text-gray);
            margin-bottom: 1rem;
        }

        .section {
            background: var(--bg-darker);
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }

        .section h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: var(--primary);
        }

        .endpoint {
            background: var(--bg-dark);
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: monospace;
            margin-bottom: 1rem;
            border: 1px solid var(--border-color);
        }

        .method {
            color: #10b981;
            font-weight: bold;
        }

        code {
            background: var(--bg-dark);
            padding: 0.2rem 0.5rem;
            border-radius: 0.3rem;
            font-family: monospace;
            color: #e879f9;
        }

        .response {
            background: var(--bg-dark);
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: monospace;
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.3rem;
            font-size: 0.875rem;
            font-weight: 500;
            margin: 0.25rem;
        }

        .badge-success { background: #059669; color: white; }
        .badge-danger { background: #dc2626; color: white; }
        .badge-warning { background: #d97706; color: white; }
        .badge-info { background: #0284c7; color: white; }

        .loading {
            display: none;
            text-align: center;
            padding: 1rem;
        }

        .loading i {
            color: var(--primary);
            font-size: 2rem;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            .hero {
                padding: 2rem 1rem;
            }
            .hero h1 {
                font-size: 2rem;
            }
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            color: var(--text-light);
        }
        
        .data-table th, .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .data-table th {
            background-color: var(--bg-dark);
            font-weight: 600;
        }
        
        .data-table tr:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        .data-table code {
            background-color: var(--bg-dark);
            padding: 0.2rem 0.4rem;
            border-radius: 0.25rem;
            font-family: monospace;
            color: #e879f9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>🌐 IP Bilgi Sistemi</h1>
            <p>Gelişmiş IP adresi analiz ve güvenlik kontrolü sistemi</p>
        </div>

        <div class="search-box">
            <h2>IP Adresi Sorgula</h2>
            <input type="text" id="ipInput" class="search-input" placeholder="IP adresi girin (örn: 8.8.8.8)" value="<?php echo $currentIP; ?>">
            <button id="searchButton" class="search-button">
                <i class="fas fa-search"></i> Sorgula
            </button>
            <div class="loading">
                <i class="fas fa-spinner fa-spin"></i>
            </div>
        </div>

        <div id="resultBox" class="result-box"></div>

        <div class="info-card">
            <h2>📌 API Hakkında</h2>
            <p>Bu API, IP adresleri hakkında detaylı bilgi sağlayan güçlü bir araçtır. Coğrafi konum, ağ bilgileri, güvenlik değerlendirmesi ve daha fazlasını tek bir sorgu ile elde edebilirsiniz. Aşağıdaki örneklerde farklı programlama dillerinde nasıl kullanabileceğinizi görebilirsiniz.</p>
        </div>

        <div class="code-examples">
            <h2>🔧 Kullanım Örnekleri</h2>
            <div class="tabs">
                <button class="tab active" data-lang="php">PHP</button>
                <button class="tab" data-lang="python">Python</button>
                <button class="tab" data-lang="javascript">JavaScript</button>
                <button class="tab" data-lang="java">Java</button>
                <button class="tab" data-lang="csharp">C#</button>
                <button class="tab" data-lang="golang">Go</button>
                <button class="tab" data-lang="ruby">Ruby</button>
                <button class="tab" data-lang="curl">cURL</button>
                <button class="tab" data-lang="nodejs">Node.js</button>
                <button class="tab" data-lang="powershell">PowerShell</button>
            </div>

            <div class="code-example active" data-lang="php">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
&lt;?php
$ip = "8.8.8.8";
$response = file_get_contents("https://api.example.com/api.php?ip=" . $ip);
$data = json_decode($response, true);
print_r($data);</pre>
            </div>

            <div class="code-example" data-lang="python">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
import requests

ip = "8.8.8.8"
response = requests.get(f"https://api.example.com/api.php?ip={ip}")
data = response.json()
print(data)</pre>
            </div>

            <div class="code-example" data-lang="javascript">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
fetch("https://api.example.com/api.php?ip=8.8.8.8")
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error(error));</pre>
            </div>

            <div class="code-example" data-lang="java">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
import java.net.URI;
import java.net.http.*;

HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("https://api.example.com/api.php?ip=8.8.8.8"))
        .build();
HttpResponse&lt;String&gt; response = client.send(request, 
        HttpResponse.BodyHandlers.ofString());</pre>
            </div>

            <div class="code-example" data-lang="csharp">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
using System.Net.Http;

var client = new HttpClient();
var response = await client.GetStringAsync(
    "https://api.example.com/api.php?ip=8.8.8.8");
Console.WriteLine(response);</pre>
            </div>

            <div class="code-example" data-lang="golang">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
package main

import (
    "fmt"
    "net/http"
    "io/ioutil"
)

func main() {
    resp, _ := http.Get("https://api.example.com/api.php?ip=8.8.8.8")
    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Println(string(body))
}</pre>
            </div>

            <div class="code-example" data-lang="ruby">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
require 'net/http'
require 'json'

uri = URI('https://api.example.com/api.php?ip=8.8.8.8')
response = Net::HTTP.get(uri)
data = JSON.parse(response)
puts data</pre>
            </div>

            <div class="code-example" data-lang="curl">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
curl -X GET "https://api.example.com/api.php?ip=8.8.8.8"</pre>
            </div>

            <div class="code-example" data-lang="nodejs">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
const axios = require('axios');

axios.get('https://api.example.com/api.php?ip=8.8.8.8')
  .then(response => console.log(response.data))
  .catch(error => console.error(error));</pre>
            </div>

            <div class="code-example" data-lang="powershell">
                <button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>
                <pre class="response">
Invoke-RestMethod -Uri "https://api.example.com/api.php?ip=8.8.8.8"</pre>
            </div>
        </div>

        <div class="section">
            <h2>📚 API Dokümantasyonu</h2>
            <div class="endpoint">
                <span class="method">GET</span> /api.php
            </div>
            <!-- Mevcut dokümantasyon içeriği -->
        </div>

        <div class="section">
            <h2>🔍 JSON Veri Alanları Açıklamaları</h2>
            <p>API'nin döndürdüğü JSON verileri ve anlamları aşağıda açıklanmıştır:</p>
            
            <div class="tabs">
                <button class="tab active" data-desc="general">Genel</button>
                <button class="tab" data-desc="location">Konum</button>
                <button class="tab" data-desc="network">Ağ Bilgileri</button>
                <button class="tab" data-desc="security">Güvenlik</button>
                <button class="tab" data-desc="additional">Ek Bilgiler</button>
            </div>
            
            <div class="code-example active" data-desc="general">
                <h3>Genel Bilgiler</h3>
                <table class="data-table">
                    <tr>
                        <th>Alan</th>
                        <th>Açıklama</th>
                    </tr>
                    <tr>
                        <td><code>success</code></td>
                        <td>İşlemin başarılı olup olmadığını belirtir (true/false)</td>
                    </tr>
                    <tr>
                        <td><code>data.ip</code></td>
                        <td>Sorgulanan IP adresi</td>
                    </tr>
                    <tr>
                        <td><code>data.timestamp</code></td>
                        <td>Sorgunun yapıldığı tarih ve saat</td>
                    </tr>
                    <tr>
                        <td><code>data.cached</code></td>
                        <td>Verinin önbellekten gelip gelmediğini belirtir</td>
                    </tr>
                    <tr>
                        <td><code>timestamp</code></td>
                        <td>Sorgunun yapıldığı Unix zaman damgası</td>
                    </tr>
                </table>
            </div>
            
            <div class="code-example" data-desc="location">
                <h3>Konum Bilgileri</h3>
                <table class="data-table">
                    <tr>
                        <th>Alan</th>
                        <th>Açıklama</th>
                    </tr>
                    <tr>
                        <td><code>data.location.country.name</code></td>
                        <td>IP adresinin bulunduğu ülkenin adı</td>
                    </tr>
                    <tr>
                        <td><code>data.location.country.code</code></td>
                        <td>Ülke kodu (ISO 3166-1 alpha-2)</td>
                    </tr>
                    <tr>
                        <td><code>data.location.country.flag</code></td>
                        <td>Ülke bayrağı emoji</td>
                    </tr>
                    <tr>
                        <td><code>data.location.region.name</code></td>
                        <td>Bölge/Eyalet adı</td>
                    </tr>
                    <tr>
                        <td><code>data.location.region.code</code></td>
                        <td>Bölge/Eyalet kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.location.city</code></td>
                        <td>Şehir adı</td>
                    </tr>
                    <tr>
                        <td><code>data.location.postal_code</code></td>
                        <td>Posta kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.location.location</code></td>
                        <td>Enlem ve boylam koordinatları</td>
                    </tr>
                </table>
            </div>
            
            <div class="code-example" data-desc="network">
                <h3>Ağ Bilgileri</h3>
                <table class="data-table">
                    <tr>
                        <th>Alan</th>
                        <th>Açıklama</th>
                    </tr>
                    <tr>
                        <td><code>data.network_info.is_datacenter</code></td>
                        <td>IP adresinin bir veri merkezine ait olup olmadığı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.is_isp</code></td>
                        <td>IP adresinin bir internet servis sağlayıcısına ait olup olmadığı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.asn_info.asn</code></td>
                        <td>Otonom Sistem Numarası (ASN)</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.asn_info.organization</code></td>
                        <td>ASN'yi işleten organizasyon adı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.asn_info.isp</code></td>
                        <td>İnternet Servis Sağlayıcı adı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.proxy_type</code></td>
                        <td>Proxy tipi (varsa)</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.usage_type</code></td>
                        <td>IP kullanım tipi (ISP, PUB, MOB, SAT, PROXY, DCH, COM)</td>
                    </tr>
                </table>
            </div>
            
            <div class="code-example" data-desc="security">
                <h3>Güvenlik Bilgileri</h3>
                <table class="data-table">
                    <tr>
                        <th>Alan</th>
                        <th>Açıklama</th>
                    </tr>
                    <tr>
                        <td><code>data.security.risk_level</code></td>
                        <td>Risk seviyesi (LOW, MEDIUM, HIGH)</td>
                    </tr>
                    <tr>
                        <td><code>data.security.risk_score</code></td>
                        <td>Risk skoru (0-100 arası)</td>
                    </tr>
                    <tr>
                        <td><code>data.security.risk_factors</code></td>
                        <td>Risk faktörleri listesi</td>
                    </tr>
                    <tr>
                        <td><code>data.security.is_proxy</code></td>
                        <td>Proxy kullanımı tespit edildi mi?</td>
                    </tr>
                    <tr>
                        <td><code>data.security.is_vpn</code></td>
                        <td>VPN kullanımı tespit edildi mi?</td>
                    </tr>
                    <tr>
                        <td><code>data.security.is_tor</code></td>
                        <td>TOR ağı kullanımı tespit edildi mi?</td>
                    </tr>
                    <tr>
                        <td><code>data.security.threat_score</code></td>
                        <td>Tehdit skoru</td>
                    </tr>
                    <tr>
                        <td><code>data.security.abuse_confidence_score</code></td>
                        <td>Kötüye kullanım güven skoru</td>
                    </tr>
                </table>
            </div>
            
            <div class="code-example" data-desc="additional">
                <h3>Ek Bilgiler (IP Location)</h3>
                <table class="data-table">
                    <tr>
                        <th>Alan</th>
                        <th>Açıklama</th>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.is_proxy</code></td>
                        <td>Proxy durumu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.is_datacenter</code></td>
                        <td>Veri merkezi durumu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.is_vpn</code></td>
                        <td>VPN durumu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.is_tor</code></td>
                        <td>TOR ağı durumu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.is_mobile</code></td>
                        <td>Mobil bağlantı durumu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.is_satellite</code></td>
                        <td>Uydu bağlantı durumu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.company_type</code></td>
                        <td>Şirket tipi</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.source</code></td>
                        <td>Veri kaynağı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.connection_type</code></td>
                        <td>Bağlantı tipi</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.threat_level</code></td>
                        <td>Tehdit seviyesi</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.threat_types</code></td>
                        <td>Tehdit tipleri</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.abuse_score</code></td>
                        <td>Kötüye kullanım skoru</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.asn_abuse_score</code></td>
                        <td>ASN kötüye kullanım skoru</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.confidence_score</code></td>
                        <td>Güven skoru</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.net_speed</code></td>
                        <td>Bağlantı hızı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.area_code</code></td>
                        <td>Alan kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.idd_code</code></td>
                        <td>Uluslararası telefon kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.mobile_brand</code></td>
                        <td>Mobil operatör markası</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.mcc</code></td>
                        <td>Mobil Ülke Kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.mnc</code></td>
                        <td>Mobil Ağ Kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.time_zone</code></td>
                        <td>Zaman dilimi</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.weather_station_code</code></td>
                        <td>Hava durumu istasyonu kodu</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.weather_station_name</code></td>
                        <td>Hava durumu istasyonu adı</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.elevation</code></td>
                        <td>Deniz seviyesinden yükseklik (metre)</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.address_type</code></td>
                        <td>Adres tipi</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.category</code></td>
                        <td>IP adresi kategorisi</td>
                    </tr>
                    <tr>
                        <td><code>data.network_info.ip_location.domain</code></td>
                        <td>IP adresine bağlı alan adı</td>
                    </tr>
                </table>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            function searchIP(ip) {
                $(".loading").show();
                $("#resultBox").hide();
                
                $.get("api.php", { ip: ip })
                    .done(function(response) {
                        let html = '<h2>Sonuçlar</h2>' +
                            '<div class="response">' +
                            '<div class="badge badge-info">IP: ' + response.data.ip + '</div>';
                        
                        if (response.data.network_info.is_datacenter) {
                            html += '<div class="badge badge-warning">Datacenter</div>';
                        }
                        
                        if (response.data.network_info.is_isp) {
                            html += '<div class="badge badge-success">ISP</div>';
                        }
                        
                        if (response.data.security.is_proxy) {
                            html += '<div class="badge badge-danger">Proxy Tespit Edildi</div>';
                        }
                        
                        html += '</div>' +
                            '<pre class="response">' + JSON.stringify(response, null, 2) + '</pre>';
                        
                        $("#resultBox").html(html).show();
                        addCopyButtonToResult($("#resultBox"));
                    })
                    .fail(function(error) {
                        $("#resultBox").html(
                            '<div class="badge badge-danger">Hata: ' + 
                            (error.responseJSON ? error.responseJSON.message : "Bir hata oluştu") + 
                            '</div>'
                        ).show();
                    })
                    .always(function() {
                        $(".loading").hide();
                    });
            }

            $("#searchButton").click(function() {
                let ip = $("#ipInput").val().trim();
                searchIP(ip);
            });

            $("#ipInput").keypress(function(e) {
                if(e.which == 13) {
                    $("#searchButton").click();
                }
            });

            // Tab değiştirme fonksiyonu (kod örnekleri için)
            $('.tab[data-lang]').click(function() {
                $('.tab[data-lang]').removeClass('active');
                $(this).addClass('active');
                
                const lang = $(this).data('lang');
                $('.code-example[data-lang]').removeClass('active');
                $('.code-example[data-lang="' + lang + '"]').addClass('active');
            });
            
            // Tab değiştirme fonksiyonu (JSON açıklamaları için)
            $('.tab[data-desc]').click(function() {
                $('.tab[data-desc]').removeClass('active');
                $(this).addClass('active');
                
                const desc = $(this).data('desc');
                $('.code-example[data-desc]').removeClass('active');
                $('.code-example[data-desc="' + desc + '"]').addClass('active');
            });

            // Kopyalama fonksiyonu
            $('.copy-button').click(function() {
                const codeBlock = $(this).siblings('pre').text();
                navigator.clipboard.writeText(codeBlock).then(() => {
                    const originalText = $(this).html();
                    $(this).html('<i class="fas fa-check"></i> Kopyalandı');
                    setTimeout(() => {
                        $(this).html(originalText);
                    }, 2000);
                });
            });

            // Sonuç kutusuna kopyalama butonu ekle
            function addCopyButtonToResult(resultBox) {
                const copyButton = $('<button class="copy-button"><i class="fas fa-copy"></i> Kopyala</button>');
                copyButton.click(function() {
                    const codeBlock = resultBox.find('pre').text();
                    navigator.clipboard.writeText(codeBlock).then(() => {
                        const originalText = $(this).html();
                        $(this).html('<i class="fas fa-check"></i> Kopyalandı');
                        setTimeout(() => {
                            $(this).html(originalText);
                        }, 2000);
                    });
                });
                resultBox.prepend(copyButton);
            }

            // Sayfa yüklendiğinde mevcut IP'yi sorgula
            searchIP("<?php echo $currentIP; ?>");
        });
    </script>
</body>
</html> 