const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const whois = require('whois-json');
const fs = require('fs').promises;
const path = require('path');
const https = require('https');
const net = require('net');
const app = express();
const PORT = process.env.PORT || 3000;

// HIBP API-avain
const HIBP_API_KEY = process.env.HIBP_API_KEY || 'testaa-ilman-avainta';

// Automaattinen skannaus
const AUTO_SCAN_ENABLED = process.env.AUTO_SCAN_ENABLED !== 'false';
const SCAN_INTERVAL = parseInt(process.env.SCAN_INTERVAL) || 3600000; // 1 tunti

app.use(express.static('public'));

// ============================================
// 1. KÄYTTÖLIITTYMÄ
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
            button.danger { background: #e74c3c; }
            button.danger:hover { background: #c0392b; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            #autostatus { margin-top: 10px; padding: 10px; background: #e8f4f8; border-radius: 5px; border-left: 4px solid #3498db; }
            .loading { color: #3498db; font-style: italic; }
            .error { color: #e74c3c; font-weight: bold; }
            .success { color: #27ae60; }
            .warning { color: #f39c12; }
            .port-open { color: #e74c3c; font-weight: bold; }
            .port-closed { color: #27ae60; }
            .port-filtered { color: #f39c12; }
            .ssl-valid { color: #27ae60; font-weight: bold; }
            .ssl-expired { color: #e74c3c; font-weight: bold; }
            .ssl-warning { color: #f39c12; font-weight: bold; }
            pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 13px; }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
            .card { background: #f8f9fa; padding: 10px; border-radius: 5px; border-left: 3px solid #3498db; }
            .port-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px; margin: 10px 0; }
            .port-item { padding: 8px 12px; border-radius: 4px; font-size: 14px; text-align: center; }
            .port-item.open { background: #fee; color: #c0392b; border: 1px solid #e74c3c; }
            .port-item.closed { background: #e8f8e8; color: #27ae60; border: 1px solid #27ae60; }
            .port-item.filtered { background: #fef9e7; color: #f39c12; border: 1px solid #f39c12; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        <p>Syötä verkkotunnus (esim. <strong>suomi.fi</strong>)</p>
        <input type="text" id="domain" placeholder="esim. suomi.fi" value="suomi.fi">
        <button onclick="scan()">🔍 Skannaa</button>
        <button onclick="scanAll()">🔄 Skannaa kaikki</button>
        <div id="autostatus">
            <span id="statusText">⏳ Ladataan tilaa...</span>
        </div>
        <div id="result">
            <p class="loading">Odota skannausta...</p>
        </div>
        <div class="footer">White Weasel Recon v0.4 — Porttiskannauksella</div>

        <script>
        async function scan() {
            const domain = document.getElementById('domain').value.trim();
            if (!domain) {
                document.getElementById('result').innerHTML = '<p class="error">Syötä verkkotunnus!</p>';
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
                document.getElementById('result').innerHTML = formatResult(domain, data);
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Yhteysvirhe: ' + error.message + '</p>';
            }
        }

        async function scanAll() {
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään automaattinen skannaus...</p>';
            try {
                const response = await fetch('/api/scan-all', { method: 'POST' });
                const data = await response.json();
                document.getElementById('result').innerHTML = '<p class="success">✅ ' + data.message + '</p>';
                updateStatus();
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
            }
        }

        async function updateStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                const statusText = document.getElementById('statusText');
                if (data.status === 'idle') {
                    statusText.innerHTML = '🟢 Joutilaana. Viimeisin skannaus: ' + (data.lastScan ? new Date(data.lastScan).toLocaleString('fi-FI') : 'Ei vielä') + ' | Tuloksia: ' + data.resultsCount;
                } else if (data.status === 'scanning') {
                    statusText.innerHTML = '🟡 Skannaus käynnissä... Kohde ' + data.currentIndex + '/' + data.total + ': ' + data.currentDomain;
                } else {
                    statusText.innerHTML = '⚪ Tila: ' + data.status;
                }
            } catch (e) {}
        }

        function formatResult(domain, data) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            html += '<p><strong>🔍 Verkkotunnus:</strong> ' + domain + '</p>';

            // PORTIT (uusi!)
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
                    statusHtml = '<span class="ssl-warning">⚠️ Ongelma</span>';
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
                if (ssl.san && ssl.san.length > 0) {
                    html += '<div class="card"><strong>Kattaa nämä nimet (SAN):</strong><br>' + ssl.san.join(', ') + '</div>';
                }
            } else {
                html += '<h3>🔒 SSL-sertifikaatti</h3>';
                html += '<p class="error">❌ SSL-yhteyttä ei voitu muodostaa.</p>';
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
                20: 'FTP-data',
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                465: 'SMTPS',
                587: 'SMTP',
                993: 'IMAPS',
                995: 'POP3S',
                3306: 'MySQL',
                3389: 'RDP',
                5432: 'PostgreSQL',
                6379: 'Redis',
                8080: 'HTTP-Proxy',
                8443: 'HTTPS-Alt',
                27017: 'MongoDB'
            };
            return services[port] || 'Tuntematon';
        }

        window.onload = function() {
            scan();
            updateStatus();
            setInterval(updateStatus, 5000);
        };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. PORTTISKANNAUS (uusi!)
// ============================================
const COMMON_PORTS = [
    { port: 20, name: 'FTP-data' },
    { port: 21, name: 'FTP' },
    { port: 22, name: 'SSH' },
    { port: 23, name: 'Telnet' },
    { port: 25, name: 'SMTP' },
    { port: 53, name: 'DNS' },
    { port: 80, name: 'HTTP' },
    { port: 110, name: 'POP3' },
    { port: 143, name: 'IMAP' },
    { port: 443, name: 'HTTPS' },
    { port: 465, name: 'SMTPS' },
    { port: 587, name: 'SMTP' },
    { port: 993, name: 'IMAPS' },
    { port: 995, name: 'POP3S' },
    { port: 3306, name: 'MySQL' },
    { port: 3389, name: 'RDP' },
    { port: 5432, name: 'PostgreSQL' },
    { port: 6379, name: 'Redis' },
    { port: 8080, name: 'HTTP-Proxy' },
    { port: 8443, name: 'HTTPS-Alt' },
    { port: 27017, name: 'MongoDB' }
];

async function checkPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
        const startTime = Date.now();
        const socket = new net.Socket();

        socket.setTimeout(timeout);

        socket.on('connect', () => {
            const duration = Date.now() - startTime;
            socket.destroy();
            resolve({ port, state: 'open', duration });
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve({ port, state: 'filtered', duration: timeout });
        });

        socket.on('error', (err) => {
            socket.destroy();
            if (err.code === 'ECONNREFUSED') {
                resolve({ port, state: 'closed', duration: Date.now() - startTime });
            } else if (err.code === 'ENOTFOUND') {
                resolve({ port, state: 'error', error: 'Host not found' });
            } else {
                resolve({ port, state: 'filtered', error: err.code });
            }
        });

        socket.connect(port, host);
    });
}

async function scanPorts(host) {
    console.log(`🚪 Skannataan portteja kohteelle ${host}...`);
    const results = [];
    
    for (const p of COMMON_PORTS) {
        const result = await checkPort(host, p.port);
        results.push({
            ...result,
            name: p.name
        });
        // Pieni viive, ettei kuormiteta liikaa
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    return results;
}

// ============================================
// 3. SSL-TARKISTUS
// ============================================
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
                return resolve({
                    valid: false,
                    error: 'Ei sertifikaattia'
                });
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
            resolve({
                valid: false,
                error: err.message
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({
                valid: false,
                error: 'Aikakatkaisu'
            });
        });

        req.end();
    });
}

// ============================================
// 4. SKANNAUSLOGIIKKA (päivitetty porteilla)
// ============================================
async function performScan(domain) {
    const result = { domain, whois: null, dns: null, hibp: null, ssl: null, ports: null };
    
    try {
        // PORTIT (uusi!)
        try {
            result.ports = await scanPorts(domain);
        } catch (e) {
            result.ports = { error: e.message };
        }

        // SSL
        try {
            result.ssl = await checkSSL(domain);
        } catch (e) {
            result.ssl = { valid: false, error: e.message };
        }

        // WHOIS
        try {
            result.whois = await whois(domain);
        } catch (e) {
            result.whois = { error: e.message };
        }

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
// 5. AUTOMAATTINEN SKANNAUS
// ============================================
const TARGET_DOMAINS = [
    'suomi.fi',
    'valtioneuvosto.fi',
    'eduskunta.fi',
    'traficom.fi',
    'kyberturvallisuuskeskus.fi',
    'digi.fi',
    'verohallinto.fi',
    'kela.fi',
    'migri.fi',
    'polisi.fi',
    'om.fi',
    'vm.fi',
    'defmin.fi'
];

let scanState = {
    status: 'idle',
    currentIndex: 0,
    total: TARGET_DOMAINS.length,
    currentDomain: '',
    lastScan: null,
    results: []
};

const RESULTS_FILE = path.join(__dirname, 'scan_results.json');

async function loadResults() {
    try {
        const data = await fs.readFile(RESULTS_FILE, 'utf8');
        scanState.results = JSON.parse(data);
        console.log(`📂 Ladattu ${scanState.results.length} aiempaa tulosta`);
    } catch (e) {
        scanState.results = [];
        console.log('📂 Ei aiempaa dataa');
    }
}

async function saveResults() {
    try {
        await fs.writeFile(RESULTS_FILE, JSON.stringify(scanState.results, null, 2));
        console.log(`💾 Tallennettu ${scanState.results.length} tulosta`);
    } catch (e) {
        console.error('❌ Tallennus epäonnistui:', e.message);
    }
}

async function runAutoScan() {
    if (scanState.status === 'scanning') {
        console.log('⏳ Skannaus jo käynnissä');
        return;
    }

    console.log('🚀 Käynnistetään automaattinen skannaus (portit mukaanlukien)!');
    scanState.status = 'scanning';
    scanState.results = [];

    for (let i = 0; i < TARGET_DOMAINS.length; i++) {
        const domain = TARGET_DOMAINS[i];
        scanState.currentIndex = i + 1;
        scanState.currentDomain = domain;
        console.log(`🦡 [${i+1}/${TARGET_DOMAINS.length}] Skannataan: ${domain}`);

        const result = await performScan(domain);
        scanState.results.push(result);

        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    scanState.status = 'idle';
    scanState.lastScan = new Date().toISOString();
    scanState.currentDomain = '';
    await saveResults();
    console.log('🏁 Automaattinen skannaus valmis!');
}

// ============================================
// 6. API-REITIT
// ============================================
app.get('/api/scan', async (req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.status(400).json({ error: 'Domain puuttuu' });
    try {
        const result = await performScan(domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/scan-all', async (req, res) => {
    if (scanState.status === 'scanning') {
        return res.status(409).json({ message: 'Skannaus jo käynnissä!' });
    }
    runAutoScan().catch(console.error);
    res.json({ message: 'Skannaus käynnistetty!' });
});

app.get('/api/status', (req, res) => {
    res.json({
        status: scanState.status,
        currentIndex: scanState.currentIndex,
        total: scanState.total,
        currentDomain: scanState.currentDomain,
        lastScan: scanState.lastScan,
        resultsCount: scanState.results.length
    });
});

app.get('/api/results', (req, res) => {
    res.json(scanState.results);
});

// ============================================
// 7. KÄYNNISTYS
// ============================================
app.listen(PORT, async () => {
    console.log(`🦡 White Weasel Recon v0.4 — Porttiskannauksella`);
    console.log(`📋 ${TARGET_DOMAINS.length} kohdetta listassa`);
    console.log(`🚪 Skannataan ${COMMON_PORTS.length} yleistä porttia per kohde`);
    await loadResults();

    if (AUTO_SCAN_ENABLED) {
        console.log('⏳ Ensimmäinen skannaus 10 sekunnin kuluttua...');
        setTimeout(() => runAutoScan().catch(console.error), 10000);
        setInterval(() => runAutoScan().catch(console.error), SCAN_INTERVAL);
        console.log(`⏰ Skannausväli: ${SCAN_INTERVAL/60000} minuuttia`);
    }
});
