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
// 1. KÄYTTÖLIITTYMÄ
// ============================================
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>White Weasel Recon</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
            .logo { font-size: 2em; font-weight: bold; }
            .weasel { color: #2c3e50; }
            .white { color: #ecf0f1; background: #2c3e50; padding: 2px 8px; border-radius: 5px; }
            input, button { padding: 12px; font-size: 16px; margin: 5px; }
            input { width: 40%; border: 2px solid #bdc3c7; border-radius: 5px; }
            button { background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #2980b9; }
            button.danger { background: #e74c3c; }
            button.danger:hover { background: #c0392b; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            #status { margin-top: 10px; padding: 10px; background: #e8f4f8; border-radius: 5px; border-left: 4px solid #3498db; }
            .loading { color: #3498db; font-style: italic; }
            .error { color: #e74c3c; font-weight: bold; }
            .success { color: #27ae60; }
            .warning { color: #f39c12; }
            .port-open { color: #e74c3c; font-weight: bold; }
            .ssl-valid { color: #27ae60; font-weight: bold; }
            .ssl-expired { color: #e74c3c; font-weight: bold; }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
            .card { background: #f8f9fa; padding: 10px; border-radius: 5px; border-left: 3px solid #3498db; }
            .port-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 6px; margin: 10px 0; }
            .port-item { padding: 6px 10px; border-radius: 4px; font-size: 12px; text-align: center; }
            .port-item.open { background: #fee; color: #c0392b; border: 1px solid #e74c3c; }
            .tech-tag { display: inline-block; background: #2c3e50; color: white; padding: 4px 12px; border-radius: 20px; margin: 4px; font-size: 13px; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
            details { margin: 10px 0; }
            summary { cursor: pointer; font-weight: bold; color: #2c3e50; }
            .progress-bar { width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; margin: 10px 0; }
            .progress-fill { height: 100%; background: #3498db; transition: width 0.3s; }
            .domain-list { max-height: 300px; overflow-y: auto; font-size: 13px; }
            .domain-item { padding: 4px 8px; border-bottom: 1px solid #ecf0f1; }
            .domain-item.done { color: #27ae60; }
            .domain-item.error { color: #e74c3c; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        <p>Syötä verkkotunnus (esim. <strong>suomi.fi</strong>)</p>
        <input type="text" id="domain" placeholder="esim. suomi.fi" value="suomi.fi">
        <button onclick="scan()">🔍 Skannaa</button>
        <button onclick="scanBatch()" class="danger">🔄 Skannaa 30 .fi-kohdetta</button>
        <div id="status">
            <span id="statusText">⏳ Ladataan...</span>
        </div>
        <div id="result">
            <p class="loading">Odota skannausta...</p>
        </div>
        <div class="footer">White Weasel Recon v2.1 — Massaskannauksella</div>

        <script>
        let batchStatus = { running: false, total: 0, current: 0, domain: '', results: [] };

        async function scan() {
            const domain = document.getElementById('domain').value.trim();
            if (!domain) { alert('Syötä verkkotunnus!'); return; }
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Skannataan...</p>';
            try {
                const response = await fetch('/api/scan?domain=' + encodeURIComponent(domain));
                const data = await response.json();
                document.getElementById('result').innerHTML = formatResult(data);
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
            }
        }

        async function scanBatch() {
            if (batchStatus.running) {
                alert('Skannaus on jo käynnissä!');
                return;
            }
            if (!confirm('Skannataan 30 satunnaista .fi-domainia. Tämä voi kestää 5-10 minuuttia. Jatketaanko?')) return;
            
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään massaskannaus...</p>';
            batchStatus.running = true;
            batchStatus.results = [];
            
            try {
                const response = await fetch('/api/scan-batch', { method: 'POST' });
                const data = await response.json();
                if (data.error) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ ' + data.error + '</p>';
                    batchStatus.running = false;
                    return;
                }
                document.getElementById('result').innerHTML = '<p class="success">✅ ' + data.message + '</p>';
                // Aloitetaan statuspäivitys
                updateBatchStatus();
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
                batchStatus.running = false;
            }
        }

        async function updateBatchStatus() {
            if (!batchStatus.running) return;
            
            try {
                const response = await fetch('/api/batch-status');
                const data = await response.json();
                
                const statusText = document.getElementById('statusText');
                if (data.status === 'idle') {
                    statusText.innerHTML = '🟢 Valmis! Skannattu ' + data.total + ' kohdetta.';
                    batchStatus.running = false;
                    // Hae tulokset
                    fetchBatchResults();
                    return;
                } else if (data.status === 'scanning') {
                    statusText.innerHTML = '🟡 Skannaus käynnissä... ' + data.currentIndex + '/' + data.total + ': ' + data.currentDomain;
                } else {
                    statusText.innerHTML = '⚪ Tila: ' + data.status;
                }
                
                // Päivitä edistymispalkki
                const progress = data.total > 0 ? (data.currentIndex / data.total * 100) : 0;
                
                setTimeout(updateBatchStatus, 3000);
            } catch (e) {
                setTimeout(updateBatchStatus, 5000);
            }
        }

        async function fetchBatchResults() {
            try {
                const response = await fetch('/api/batch-results');
                const data = await response.json();
                document.getElementById('result').innerHTML = formatBatchResults(data);
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Tulosten haku epäonnistui: ' + error.message + '</p>';
            }
        }

        function formatResult(data) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            if (data.error) return '<p class="error">❌ ' + data.error + '</p>';
            
            html += '<p><strong>🔍 Verkkotunnus:</strong> ' + data.domain + '</p>';

            if (data.technologies && data.technologies.length > 0) {
                html += '<h3>🧩 Teknologiat</h3><div>';
                data.technologies.forEach(t => {
                    html += '<span class="tech-tag">' + t + '</span>';
                });
                html += '</div>';
            }

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
            }

            if (data.ssl) {
                html += '<h3>🔒 SSL-sertifikaatti</h3>';
                const ssl = data.ssl;
                let statusHtml = '';
                if (ssl.valid && !ssl.expired) {
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
                html += '</div>';
                if (ssl.daysRemaining !== undefined) {
                    const days = ssl.daysRemaining;
                    if (days < 0) {
                        html += '<p class="error">⚠️ Vanhentui ' + Math.abs(days) + ' päivää sitten!</p>';
                    } else if (days < 30) {
                        html += '<p class="warning">⚠️ Vanhenee ' + days + ' päivän kuluttua!</p>';
                    } else {
                        html += '<p class="success">✅ Voimassa ' + days + ' päivää.</p>';
                    }
                }
            }

            if (data.ports) {
                html += '<h3>🚪 Avoimet portit</h3>';
                const openPorts = data.ports.filter(p => p.state === 'open');
                if (openPorts.length > 0) {
                    html += '<div class="port-grid">';
                    openPorts.forEach(p => {
                        const service = getServiceName(p.port);
                        html += '<div class="port-item open"><strong>' + p.port + '</strong><br>' + service + '</div>';
                    });
                    html += '</div>';
                } else {
                    html += '<p class="success">✅ Ei avoimia portteja</p>';
                }
            }

            if (data.hibp) {
                html += '<h3>🔐 Tietovuodot (HIBP)</h3>';
                if (data.hibp.breaches && data.hibp.breaches.length > 0) {
                    html += '<p class="error">⚠️ ' + data.hibp.breaches.length + ' tietomurtoa!</p>';
                } else {
                    html += '<p class="success">✅ Ei tietomurtoja.</p>';
                }
            }

            html += '<p><small>' + new Date().toLocaleString('fi-FI') + '</small></p>';
            return html;
        }

        function formatBatchResults(data) {
            let html = '<h2>📊 Massaskannauksen tulokset</h2>';
            html += '<p><strong>Skannattuja kohteita:</strong> ' + data.results.length + '</p>';
            
            // Yhteenveto
            const secure = data.results.filter(r => r.ssl && r.ssl.valid && !r.ssl.expired).length;
            const risky = data.results.filter(r => r.ports && r.ports.some(p => p.state === 'open' && ![80, 443].includes(p.port))).length;
            
            html += '<div class="grid">';
            html += '<div class="card"><strong>🔒 SSL-voimassa:</strong> ' + secure + '/' + data.results.length + '</div>';
            html += '<div class="card"><strong>🚪 Avoimia portteja:</strong> ' + risky + '/' + data.results.length + '</div>';
            html += '</div>';

            // Yksittäiset tulokset
            html += '<details><summary>📋 Yksityiskohtaiset tulokset</summary>';
            html += '<div class="domain-list">';
            data.results.forEach((r, i) => {
                const status = r.error ? '❌' : (r.ssl && r.ssl.valid ? '✅' : '⚠️');
                html += '<div class="domain-item">' + (i+1) + '. ' + status + ' <strong>' + r.domain + '</strong>';
                if (r.error) {
                    html += ' <span class="error">' + r.error + '</span>';
                } else if (r.ports) {
                    const openPorts = r.ports.filter(p => p.state === 'open');
                    if (openPorts.length > 0) {
                        html += ' <span class="error">Portit: ' + openPorts.map(p => p.port).join(', ') + '</span>';
                    }
                }
                html += '</div>';
            });
            html += '</div></details>';

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
            scan();
        };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. 30 SATUNNAISTA .fi-DOMAINIA (pieniä sivustoja)
// ============================================
const TARGET_DOMAINS = [
    // Pienet kaupungit ja kunnat
    'kangasala.fi', 'nokia.fi', 'ylojarvi.fi', 'pirkkala.fi', 'lempaala.fi',
    'vesilahti.fi', 'hameenkyro.fi', 'iittala.fi', 'kuhmoinen.fi', 'padasjoki.fi',
    
    // Pienet yritykset ja järjestöt
    'kangasalanopisto.fi', 'pirkanmaanteko.fi', 'nokianvene.fi', 'hameenlinna.fi',
    'sastamala.fi', 'huittinen.fi', 'kankaanpaa.fi', 'parkano.fi', 'viljakkala.fi',
    
    // Pienet kylät ja paikalliset palvelut
    'kuru.fi', 'ruovesi.fi', 'mantta.fi', 'virrat.fi', 'alavus.fi',
    'kuortane.fi', 'lapua.fi', 'kauhava.fi', 'nurmo.fi', 'seina.fi',
    
    // Paikallislehdet ja blogit
    'kangasalanlehti.fi', 'valkeakoskenlehti.fi', 'sastamalanlehti.fi',
    'hameenkyronlehti.fi', 'nokianlehti.fi',
    
    // Harrastus- ja paikallisseurat
    'kangasalankirjasto.fi', 'nokianmuseo.fi', 'hameenlinnalainen.fi',
    'vesilahtiseura.fi', 'ylojarviseura.fi'
];

// Poistetaan mahdolliset duplikaatit ja otetaan 30 ensimmäistä
const uniqueDomains = [...new Set(TARGET_DOMAINS)].slice(0, 30);

console.log('📋 ' + uniqueDomains.length + ' kohdetta listassa');

// ============================================
// 3. SKANNAUSFUNKTIOT
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
                protocol: socket.getProtocol() || 'Ei tiedossa'
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

// YHDISTETTY SKANNAUS (kevyt versio massaskannaukseen)
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
        
        // Portit (vain tärkeimmät massaskannauksessa)
        const portsToScan = [80, 443, 22, 21, 25, 3306, 8080];
        const portResults = [];
        for (const port of portsToScan) {
            const res = await checkPort(domain, port);
            portResults.push(res);
            await new Promise(resolve => setTimeout(resolve, 30));
        }
        result.ports = portResults;

        // HIBP (kevyt)
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
// 4. MASSASKANNAUS
// ============================================
let batchState = {
    status: 'idle', // idle | scanning
    currentIndex: 0,
    total: uniqueDomains.length,
    currentDomain: '',
    results: [],
    lastScan: null
};

async function runBatchScan() {
    if (batchState.status === 'scanning') {
        console.log('⏳ Skannaus jo käynnissä');
        return;
    }

    console.log('🚀 Käynnistetään massaskannaus (' + uniqueDomains.length + ' kohdetta)...');
    batchState.status = 'scanning';
    batchState.results = [];
    batchState.currentIndex = 0;

    for (let i = 0; i < uniqueDomains.length; i++) {
        const domain = uniqueDomains[i];
        batchState.currentIndex = i + 1;
        batchState.currentDomain = domain;
        console.log('🦡 [' + (i+1) + '/' + uniqueDomains.length + '] Skannataan: ' + domain);

        const result = await performScan(domain);
        batchState.results.push(result);
        await new Promise(resolve => setTimeout(resolve, 500));
    }

    batchState.status = 'idle';
    batchState.lastScan = new Date().toISOString();
    batchState.currentDomain = '';
    console.log('🏁 Massaskannaus valmis!');
}

// ============================================
// 5. API-REITIT
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

// Massaskannaus (käynnistä)
app.post('/api/scan-batch', async (req, res) => {
    if (batchState.status === 'scanning') {
        return res.status(409).json({ error: 'Skannaus jo käynnissä!' });
    }
    // Käynnistä taustalla
    runBatchScan().catch(console.error);
    res.json({ message: 'Massaskannaus käynnistetty! Seuraa edistymistä.' });
});

// Massaskannauksen tila
app.get('/api/batch-status', (req, res) => {
    res.json({
        status: batchState.status,
        currentIndex: batchState.currentIndex,
        total: batchState.total,
        currentDomain: batchState.currentDomain,
        lastScan: batchState.lastScan,
        resultsCount: batchState.results.length
    });
});

// Massaskannauksen tulokset
app.get('/api/batch-results', (req, res) => {
    res.json({
        results: batchState.results,
        total: batchState.results.length,
        timestamp: new Date().toISOString()
    });
});

// ============================================
// 6. KÄYNNISTYS
// ============================================
app.listen(PORT, () => {
    console.log('🦡 White Weasel Recon v2.1 — Massaskannauksella');
    console.log('✅ Palvelin käynnissä portissa ' + PORT);
    console.log('📋 ' + uniqueDomains.length + ' kohdetta listassa');
    console.log('📝 Ei automaattisia skannauksia — vain manuaaliset');
});
