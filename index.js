const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const whois = require('whois-json');
const https = require('https');
const net = require('net');
const app = express();
const PORT = process.env.PORT || 3000;

// Ympäristömuuttujat
const HIBP_API_KEY = process.env.HIBP_API_KEY || 'testaa-ilman-avainta';

app.use(express.static('public'));

// ============================================
// 1. KÄYTTÖLIITTYMÄ (yksinkertainen ja toimiva)
// ============================================
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>White Weasel Recon</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
            .logo { font-size: 2em; font-weight: bold; }
            .weasel { color: #2c3e50; }
            .white { color: #ecf0f1; background: #2c3e50; padding: 2px 8px; border-radius: 5px; }
            input, button { padding: 12px; font-size: 16px; margin: 5px; }
            input { width: 50%; border: 2px solid #bdc3c7; border-radius: 5px; }
            button { background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #2980b9; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .loading { color: #3498db; font-style: italic; }
            .error { color: #e74c3c; font-weight: bold; }
            .success { color: #27ae60; }
            .warning { color: #f39c12; }
            .port-open { color: #e74c3c; font-weight: bold; }
            .port-closed { color: #27ae60; }
            .port-filtered { color: #f39c12; }
            .ssl-valid { color: #27ae60; font-weight: bold; }
            .ssl-expired { color: #e74c3c; font-weight: bold; }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
            .card { background: #f8f9fa; padding: 10px; border-radius: 5px; border-left: 3px solid #3498db; }
            .port-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; margin: 10px 0; }
            .port-item { padding: 8px 12px; border-radius: 4px; font-size: 13px; text-align: center; }
            .port-item.open { background: #fee; color: #c0392b; border: 1px solid #e74c3c; }
            .port-item.closed { background: #e8f8e8; color: #27ae60; border: 1px solid #27ae60; }
            .port-item.filtered { background: #fef9e7; color: #f39c12; border: 1px solid #f39c12; }
            .tech-tag { display: inline-block; background: #2c3e50; color: white; padding: 4px 12px; border-radius: 20px; margin: 4px; font-size: 13px; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
            details { margin: 10px 0; }
            summary { cursor: pointer; font-weight: bold; color: #2c3e50; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        <p>Syötä verkkotunnus (esim. <strong>suomi.fi</strong>)</p>
        <input type="text" id="domain" placeholder="esim. suomi.fi" value="suomi.fi">
        <button onclick="scan()">🔍 Skannaa</button>
        <div id="result">
            <p class="loading">Odota skannausta...</p>
        </div>
        <div class="footer">White Weasel Recon v2.0 — Yksinkertainen ja vakaa</div>

        <script>
        async function scan() {
            const domain = document.getElementById('domain').value.trim();
            if (!domain) {
                alert('Syötä verkkotunnus!');
                return;
            }
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Skannataan...</p>';
            try {
                const response = await fetch('/api/scan?domain=' + encodeURIComponent(domain));
                const data = await response.json();
                if (!response.ok) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + (data.error || 'Tuntematon ongelma') + '</p>';
                    return;
                }
                document.getElementById('result').innerHTML = formatResult(data);
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Yhteysvirhe: ' + error.message + '</p>';
            }
        }

        function formatResult(data) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            if (data.error) return '<p class="error">❌ ' + data.error + '</p>';
            
            html += '<p><strong>🔍 Verkkotunnus:</strong> ' + data.domain + '</p>';

            // Teknologiat
            if (data.technologies && data.technologies.length > 0) {
                html += '<h3>🧩 Teknologiat</h3><div>';
                data.technologies.forEach(t => {
                    html += '<span class="tech-tag">' + t + '</span>';
                });
                html += '</div>';
            }

            // HTTP-headers
            if (data.headers) {
                html += '<h3>🛡️ Turvallisuusheadersit</h3>';
                const important = ['strict-transport-security', 'x-frame-options', 'x-content-type-options', 'content-security-policy'];
                html += '<ul>';
                important.forEach(h => {
                    const value = data.headers[h];
                    if (value) {
                        html += '<li class="success">✅ ' + h + ': ' + value + '</li>';
                    } else {
                        html += '<li class="error">❌ ' + h + ' puuttuu</li>';
                    }
                });
                html += '</ul>';
                
                html += '<details><summary>📋 Kaikki otsikot</summary>';
                html += '<pre>' + JSON.stringify(data.headers, null, 2) + '</pre>';
                html += '</details>';
            }

            // SSL
            if (data.ssl) {
                html += '<h3>🔒 SSL-sertifikaatti</h3>';
                const ssl = data.ssl;
                let statusHtml = '';
                if (ssl.valid) {
                    statusHtml = '<span class="ssl-valid">✅ Voimassa</span>';
                } else if (ssl.expired) {
                    statusHtml = '<span class="ssl-expired">❌ VANHENTUNUT!</span>';
                } else {
                    statusHtml = '<span class="warning">⚠️ Ongelma</span>';
                }
                html += '<div class="card"><strong>Tila:</strong> ' + statusHtml + '</div>';
                html += '<div class="grid">';
                html += '<div class="card"><strong>Myöntäjä:</strong><br>' + (ssl.issuer || 'Ei tiedossa') + '</div>';
                html += '<div class="card"><strong>Voimassa:</strong><br>' + (ssl.validFrom ? new Date(ssl.validFrom).toLocaleDateString('fi-FI') : '?') + ' → ' + (ssl.validTo ? new Date(ssl.validTo).toLocaleDateString('fi-FI') : '?') + '</div>';
                html += '<div class="card"><strong>Salaus:</strong><br>' + (ssl.cipher || 'Ei tiedossa') + '</div>';
                html += '<div class="card"><strong>Protokolla:</strong><br>' + (ssl.protocol || 'Ei tiedossa') + '</div>';
                html += '</div>';
                if (ssl.daysRemaining !== undefined) {
                    const days = ssl.daysRemaining;
                    if (days < 0) {
                        html += '<p class="error">⚠️ Sertifikaatti vanhentui ' + Math.abs(days) + ' päivää sitten!</p>';
                    } else if (days < 30) {
                        html += '<p class="warning">⚠️ Sertifikaatti vanhenee ' + days + ' päivän kuluttua!</p>';
                    } else {
                        html += '<p class="success">✅ Sertifikaatti voimassa ' + days + ' päivää.</p>';
                    }
                }
            }

            // Portit
            if (data.ports) {
                html += '<h3>🚪 Porttiskannaus</h3>';
                const openPorts = data.ports.filter(p => p.state === 'open');
                const closedPorts = data.ports.filter(p => p.state === 'closed');
                const filteredPorts = data.ports.filter(p => p.state === 'filtered');
                
                html += '<p><span class="port-open">🔴 Avoinna: ' + openPorts.length + '</span> | ';
                html += '<span class="port-closed">🟢 Kiinni: ' + closedPorts.length + '</span> | ';
                html += '<span class="port-filtered">🟡 Suodatettu: ' + filteredPorts.length + '</span></p>';

                if (openPorts.length > 0) {
                    html += '<div class="port-grid">';
                    openPorts.forEach(p => {
                        const service = getServiceName(p.port);
                        html += '<div class="port-item open"><strong>' + p.port + '</strong><br>' + service + '</div>';
                    });
                    html += '</div>';
                }

                if (closedPorts.length > 0) {
                    html += '<details><summary>🟢 Suljetut portit (' + closedPorts.length + ')</summary>';
                    html += '<div class="port-grid">';
                    closedPorts.forEach(p => {
                        html += '<div class="port-item closed">' + p.port + '</div>';
                    });
                    html += '</div></details>';
                }

                if (filteredPorts.length > 0) {
                    html += '<details><summary>🟡 Suodatetut portit (' + filteredPorts.length + ')</summary>';
                    html += '<div class="port-grid">';
                    filteredPorts.forEach(p => {
                        html += '<div class="port-item filtered">' + p.port + '</div>';
                    });
                    html += '</div></details>';
                }
            }

            // WHOIS
            if (data.whois) {
                html += '<h3>📋 WHOIS</h3>';
                html += '<pre>' + JSON.stringify(data.whois, null, 2) + '</pre>';
            }

            // DNS
            if (data.dns) {
                html += '<h3>🌐 DNS-tietueet</h3>';
                html += '<pre>' + JSON.stringify(data.dns, null, 2) + '</pre>';
            }

            // HIBP
            if (data.hibp) {
                html += '<h3>🔐 Tietovuodot (HIBP)</h3>';
                if (data.hibp.breaches && data.hibp.breaches.length > 0) {
                    html += '<p class="error">⚠️ Löytyi ' + data.hibp.breaches.length + ' tietomurtoa!</p>';
                    html += '<ul>';
                    data.hibp.breaches.forEach(b => {
                        html += '<li><strong>' + b.Name + '</strong> (' + b.BreachDate + ')</li>';
                    });
                    html += '</ul>';
                } else {
                    html += '<p class="success">✅ Ei löytynyt tietomurtoja.</p>';
                }
            }

            html += '<p><small>' + new Date().toLocaleString('fi-FI') + '</small></p>';
            return html;
        }

        function getServiceName(port) {
            const services = {
                20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
                465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
                3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
                8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
            };
            return services[port] || 'Tuntematon';
        }

        window.onload = function() {
            // Skannaa automaattisesti suomi.fi kun sivu latautuu
            scan();
        };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. SKANNAUSFUNKTIOT
// ============================================

// PORTIT
const COMMON_PORTS = [
    { port: 20, name: 'FTP-data' }, { port: 21, name: 'FTP' }, { port: 22, name: 'SSH' },
    { port: 23, name: 'Telnet' }, { port: 25, name: 'SMTP' }, { port: 53, name: 'DNS' },
    { port: 80, name: 'HTTP' }, { port: 110, name: 'POP3' }, { port: 143, name: 'IMAP' },
    { port: 443, name: 'HTTPS' }, { port: 465, name: 'SMTPS' }, { port: 587, name: 'SMTP' },
    { port: 993, name: 'IMAPS' }, { port: 995, name: 'POP3S' }, { port: 3306, name: 'MySQL' },
    { port: 3389, name: 'RDP' }, { port: 5432, name: 'PostgreSQL' }, { port: 6379, name: 'Redis' },
    { port: 8080, name: 'HTTP-Proxy' }, { port: 8443, name: 'HTTPS-Alt' }, { port: 27017, name: 'MongoDB' }
];

async function checkPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(timeout);
        socket.on('connect', () => { socket.destroy(); resolve({ port, state: 'open' }); });
        socket.on('timeout', () => { socket.destroy(); resolve({ port, state: 'filtered' }); });
        socket.on('error', (err) => { socket.destroy(); resolve({ port, state: err.code === 'ECONNREFUSED' ? 'closed' : 'filtered' }); });
        socket.connect(port, host);
    });
}

async function scanPorts(host) {
    const results = [];
    for (const p of COMMON_PORTS) {
        const result = await checkPort(host, p.port);
        results.push({ ...result, name: p.name });
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    return results;
}

// HTTP-HEADERS
async function fetchHeaders(domain) {
    try {
        const response = await axios.get(`https://${domain}`, { timeout: 10000, maxRedirects: 5 });
        return { headers: response.headers, status: response.status };
    } catch (error) {
        if (error.response) return { headers: error.response.headers || {}, status: error.response.status };
        return { error: error.message };
    }
}

function identifyTechnologies(headers) {
    const techs = [];
    if (headers['server']) {
        const s = headers['server'].toLowerCase();
        if (s.includes('nginx')) techs.push('Nginx');
        else if (s.includes('apache')) techs.push('Apache');
        else if (s.includes('iis')) techs.push('IIS');
        else if (s.includes('cloudflare')) techs.push('Cloudflare');
        else techs.push(headers['server']);
    }
    if (headers['x-powered-by']) {
        const p = headers['x-powered-by'].toLowerCase();
        if (p.includes('php')) techs.push('PHP');
        else if (p.includes('asp.net')) techs.push('ASP.NET');
        else if (p.includes('node')) techs.push('Node.js');
        else techs.push('X-Powered-By: ' + headers['x-powered-by']);
    }
    if (headers['generator']) {
        const g = headers['generator'].toLowerCase();
        if (g.includes('wordpress')) techs.push('WordPress');
        else if (g.includes('drupal')) techs.push('Drupal');
        else if (g.includes('joomla')) techs.push('Joomla');
        else techs.push('Generator: ' + headers['generator']);
    }
    return techs;
}

// SSL
async function checkSSL(domain) {
    return new Promise((resolve) => {
        const options = {
            host: domain,
            port: 443,
            method: 'HEAD',
            rejectUnauthorized: false,
            timeout: 10000
        };

        const req = https.request(options, (res) => {
            const socket = res.socket;
            const cert = socket.getPeerCertificate();
            if (!cert || Object.keys(cert).length === 0) {
                return resolve({ valid: false, error: 'Ei sertifikaattia' });
            }
            const now = new Date();
            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
            resolve({
                valid: true,
                expired: validTo < now,
                issuer: cert.issuer?.CN || cert.issuer?.O || 'Tuntematon',
                validFrom: validFrom.toISOString(),
                validTo: validTo.toISOString(),
                daysRemaining: daysRemaining,
                cipher: socket.getCipher()?.name || 'Ei tiedossa',
                protocol: socket.getProtocol() || 'Ei tiedossa',
                san: cert.subjectaltname ? cert.subjectaltname.split(', ').map(s => s.replace(/^DNS:/, '')) : [],
                subject: cert.subject?.CN || 'Ei tiedossa',
                fingerprint: cert.fingerprint || 'Ei tiedossa'
            });
        });

        req.on('error', (err) => {
            resolve({ valid: false, error: err.message });
        });
        req.on('timeout', () => {
            req.destroy();
            resolve({ valid: false, error: 'Aikakatkaisu' });
        });
        req.end();
    });
}

// YHDISTETTY SKANNAUS
async function performScan(domain) {
    const result = { domain, timestamp: new Date().toISOString() };
    try {
        // HTTP-headers
        const headerData = await fetchHeaders(domain);
        if (headerData.error) {
            result.error = headerData.error;
            return result;
        }
        result.headers = headerData.headers;
        result.technologies = identifyTechnologies(headerData.headers);
        
        // SSL
        result.ssl = await checkSSL(domain);
        
        // Portit
        result.ports = await scanPorts(domain);
        
        // DNS
        try {
            result.dns = {
                A: await dns.resolve4(domain).catch(() => []),
                MX: await dns.resolveMx(domain).catch(() => []),
                NS: await dns.resolveNs(domain).catch(() => []),
                TXT: await dns.resolveTxt(domain).catch(() => [])
            };
        } catch (e) {
            result.dns = { error: e.message };
        }
        
        // WHOIS
        try {
            result.whois = await whois(domain);
        } catch (e) {
            result.whois = { error: e.message };
        }

        // HIBP
        if (HIBP_API_KEY && HIBP_API_KEY !== 'testaa-ilman-avainta') {
            try {
                const hibpResponse = await axios.get(
                    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(domain)}?truncateResponse=true`,
                    {
                        headers: {
                            'hibp-api-key': HIBP_API_KEY,
                            'User-Agent': 'WhiteWeaselRecon/1.0 (https://whiteweasel.fi)'
                        }
                    }
                );
                result.hibp = { breaches: hibpResponse.data || [] };
            } catch (e) {
                if (e.response && e.response.status === 404) {
                    result.hibp = { breaches: [] };
                } else {
                    result.hibp = { error: e.message };
                }
            }
        } else {
            result.hibp = { message: 'HIBP ei käytössä' };
        }
    } catch (e) {
        result.error = e.message;
    }
    return result;
}

// ============================================
// 3. API-REITIT
// ============================================

// Yksittäinen skannaus
app.get('/api/scan', async (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain puuttuu' });
    }
    try {
        const result = await performScan(domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// 4. KÄYNNISTYS
// ============================================
app.listen(PORT, () => {
    console.log('🦡 White Weasel Recon v2.0 — Yksinkertainen ja vakaa');
    console.log('✅ Palvelin käynnissä portissa ' + PORT);
    console.log('📝 Ei automaattisia skannauksia — vain manuaaliset pyynnöt');
});
