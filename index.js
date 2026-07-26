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

// ============================================
// HAETAAN KOHDELISTA OMISTA TIEDOSTOSTAAN
// ============================================
let TARGET_DOMAINS = [];
try {
    const targets = require('./targets.js');
    TARGET_DOMAINS = targets.TARGET_DOMAINS || [];
    console.log('✅ Kohdelista ladattu targets.js:stä (' + TARGET_DOMAINS.length + ' kohdetta)');
} catch (error) {
    console.error('⚠️ targets.js-tiedostoa ei löytynyt, käytetään oletuslistaa');
    // Oletuslista (jos targets.js puuttuu)
    TARGET_DOMAINS = [
        'suomi.fi', 'valtioneuvosto.fi', 'eduskunta.fi',
        'helsinki.fi', 'tampere.fi', 'turku.fi'
    ];
}

// Poistetaan duplikaatit
const uniqueDomains = [...new Set(TARGET_DOMAINS)];
console.log('📋 ' + uniqueDomains.length + ' kohdetta listassa');

// ============================================
// 1. KÄYTTÖLIITTYMÄ
// ============================================
app.get('/', (req, res) => {
    const targetCount = uniqueDomains.length;
    res.send(`<!DOCTYPE html>
    <html>
    <head>
        <title>White Weasel Recon</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
            .logo { font-size: 2em; font-weight: bold; }
            .weasel { color: #2c3e50; }
            .white { color: #ecf0f1; background: #2c3e50; padding: 2px 8px; border-radius: 5px; }
            input, button { padding: 12px; font-size: 16px; margin: 5px; }
            input { width: 35%; border: 2px solid #bdc3c7; border-radius: 5px; }
            button { background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #2980b9; }
            button.danger { background: #e74c3c; }
            button.danger:hover { background: #c0392b; }
            button.secondary { background: #2c3e50; }
            button.secondary:hover { background: #1a252f; }
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
            .tech-tag { display: inline-block; background: #2c3e50; color: white; padding: 4px 12px; border-radius: 20px; margin: 4px; font-size: 13px; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
            .filter-buttons { margin: 15px 0; display: flex; flex-wrap: wrap; gap: 8px; }
            .filter-btn { padding: 6px 14px; border: 2px solid #bdc3c7; border-radius: 20px; background: white; cursor: pointer; font-size: 13px; }
            .filter-btn.active { border-color: #2c3e50; background: #2c3e50; color: white; }
            .filter-btn.critical { border-color: #e74c3c; color: #e74c3c; }
            .filter-btn.critical.active { background: #e74c3c; color: white; }
            .filter-btn.high { border-color: #e67e22; color: #e67e22; }
            .filter-btn.high.active { background: #e67e22; color: white; }
            .filter-btn.medium { border-color: #f39c12; color: #f39c12; }
            .filter-btn.medium.active { background: #f39c12; color: white; }
            .filter-btn.low { border-color: #3498db; color: #3498db; }
            .filter-btn.low.active { background: #3498db; color: white; }
            .filter-btn.secure { border-color: #27ae60; color: #27ae60; }
            .filter-btn.secure.active { background: #27ae60; color: white; }
            .filter-btn.all { border-color: #2c3e50; color: #2c3e50; }
            .filter-btn.all.active { background: #2c3e50; color: white; }
            .domain-list { max-height: 400px; overflow-y: auto; font-size: 13px; }
            .domain-item { padding: 6px 10px; border-bottom: 1px solid #ecf0f1; display: flex; justify-content: space-between; align-items: center; }
            .risk-critical { color: #e74c3c; background: #fde8e8; border-left: 4px solid #e74c3c; }
            .risk-high { color: #e67e22; background: #fef5e7; border-left: 4px solid #e67e22; }
            .risk-medium { color: #f39c12; background: #fef9e7; border-left: 4px solid #f39c12; }
            .risk-low { color: #3498db; background: #ebf5fb; border-left: 4px solid #3498db; }
            .risk-none { color: #27ae60; background: #eafaf1; border-left: 4px solid #27ae60; }
            .result-count { margin: 10px 0; font-size: 14px; color: #7f8c8d; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        <p>Syötä verkkotunnus (esim. <strong>suomi.fi</strong>)</p>
        <input type="text" id="domain" placeholder="esim. suomi.fi" value="suomi.fi">
        <button onclick="scan()">🔍 Skannaa</button>
        <button onclick="scanBatch()" class="danger">🔄 Skannaa ${targetCount} kohdetta</button>
        <button onclick="showReport()" class="secondary">📊 Raportti</button>
        <div id="status"><span id="statusText">⏳ Ladataan...</span></div>
        <div id="result"><p class="loading">Odota skannausta...</p></div>
        <div class="footer">White Weasel Recon v2.5 — Kohdelista targets.js:stä</div>

        <script>
        let batchStatus = { running: false };
        let allResults = [];
        let currentFilter = 'all';
        const targetCount = ${targetCount};

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
            if (batchStatus.running) { alert('Skannaus on jo käynnissä!'); return; }
            if (!confirm('Skannataan ' + targetCount + ' kohdetta. Tämä voi kestää 8-12 minuuttia. Jatketaanko?')) return;
            
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään massaskannaus...</p>';
            batchStatus.running = true;
            
            try {
                const response = await fetch('/api/scan-batch', { method: 'POST' });
                const data = await response.json();
                if (data.error) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ ' + data.error + '</p>';
                    batchStatus.running = false;
                    return;
                }
                document.getElementById('result').innerHTML = '<p class="success">✅ ' + data.message + '</p>';
                updateBatchStatus();
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
                batchStatus.running = false;
            }
        }

        async function showReport() {
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Haetaan tuloksia...</p>';
            try {
                const response = await fetch('/api/batch-results');
                const data = await response.json();
                if (data.error) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ ' + data.error + '</p>';
                    return;
                }
                if (!data.results || data.results.length === 0) {
                    document.getElementById('result').innerHTML = '<p class="warning">⚠️ Ei skannattuja kohteita. Suorita ensin massaskannaus.</p>';
                    return;
                }
                allResults = data.results;
                document.getElementById('result').innerHTML = renderFilteredResults(allResults, 'all');
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
            }
        }

        function renderFilteredResults(results, filter) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            html += '<div class="filter-buttons">';
            html += '<button class="filter-btn all active" onclick="applyFilter(\'all\')">📋 Kaikki (' + results.length + ')</button>';
            const critical = results.filter(r => getRiskLevel(r) === 'critical');
            const high = results.filter(r => getRiskLevel(r) === 'high');
            const medium = results.filter(r => getRiskLevel(r) === 'medium');
            const low = results.filter(r => getRiskLevel(r) === 'low');
            const secure = results.filter(r => getRiskLevel(r) === 'secure');
            html += '<button class="filter-btn critical" onclick="applyFilter(\'critical\')">🔴 Kriittinen (' + critical.length + ')</button>';
            html += '<button class="filter-btn high" onclick="applyFilter(\'high\')">🟠 Korkea (' + high.length + ')</button>';
            html += '<button class="filter-btn medium" onclick="applyFilter(\'medium\')">🟡 Keskitaso (' + medium.length + ')</button>';
            html += '<button class="filter-btn low" onclick="applyFilter(\'low\')">🔵 Matala (' + low.length + ')</button>';
            html += '<button class="filter-btn secure" onclick="applyFilter(\'secure\')">🟢 Turvallinen (' + secure.length + ')</button>';
            html += '</div>';

            let filtered = filter === 'all' ? results : results.filter(r => getRiskLevel(r) === filter);
            html += '<div class="result-count">Näytetään ' + filtered.length + ' / ' + results.length + ' kohdetta</div>';
            if (filtered.length === 0) {
                html += '<p class="success">✅ Ei kohteita tällä riskitasolla.</p>';
                return html;
            }
            html += '<div class="domain-list">';
            filtered.forEach((r, i) => {
                const risk = getRiskLevel(r);
                const status = r.error ? '❌' : (r.ssl && r.ssl.valid ? '✅' : '⚠️');
                const issues = getIssues(r);
                html += '<div class="domain-item risk-' + risk + '">';
                html += '<span><strong>' + (i+1) + '.</strong> ' + status + ' ' + r.domain + '</span>';
                if (issues.length > 0) html += '<span style="font-size:12px;">' + issues.join(', ') + '</span>';
                html += '</div>';
            });
            html += '</div><p><small>' + new Date().toLocaleString('fi-FI') + '</small></p>';
            return html;
        }

        function getRiskLevel(result) {
            if (result.error) return 'critical';
            let risk = 'secure';
            if (result.ssl && !result.ssl.valid) risk = 'high';
            else if (result.ssl && result.ssl.daysRemaining < 30) risk = 'medium';
            if (result.ports) {
                const riskyPorts = result.ports.filter(p => p.state === 'open' && ![80, 443].includes(p.port));
                if (riskyPorts.length > 0) risk = 'high';
            }
            if (result.headers) {
                const important = ['strict-transport-security', 'x-frame-options', 'x-content-type-options'];
                const missing = important.filter(h => !result.headers[h]);
                if (missing.length >= 3 && risk === 'secure') risk = 'medium';
                else if (missing.length > 0 && risk === 'secure') risk = 'low';
            }
            return risk;
        }

        function getIssues(result) {
            const issues = [];
            if (result.error) { issues.push('Virhe: ' + result.error); return issues; }
            if (result.ssl && !result.ssl.valid) issues.push('SSL-virhe');
            else if (result.ssl && result.ssl.daysRemaining < 30) issues.push('SSL vanhenee ' + result.ssl.daysRemaining + ' päivässä');
            if (result.ports) {
                const riskyPorts = result.ports.filter(p => p.state === 'open' && ![80, 443].includes(p.port));
                if (riskyPorts.length > 0) issues.push('Avoimet portit: ' + riskyPorts.map(p => p.port).join(', '));
            }
            if (result.headers) {
                const important = ['strict-transport-security', 'x-frame-options', 'x-content-type-options'];
                const missing = important.filter(h => !result.headers[h]);
                if (missing.length > 0) issues.push('Puuttuu: ' + missing.join(', '));
            }
            return issues.slice(0, 3);
        }

        function applyFilter(filter) {
            currentFilter = filter;
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.classList.contains(filter)) btn.classList.add('active');
            });
            document.getElementById('result').innerHTML = renderFilteredResults(allResults, filter);
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
                    const res = await fetch('/api/batch-results');
                    const results = await res.json();
                    if (results.results && results.results.length > 0) {
                        allResults = results.results;
                        document.getElementById('result').innerHTML = renderFilteredResults(allResults, 'all');
                    }
                    return;
                } else if (data.status === 'scanning') {
                    statusText.innerHTML = '🟡 Skannaus käynnissä... ' + data.currentIndex + '/' + data.total + ': ' + data.currentDomain;
                }
                setTimeout(updateBatchStatus, 3000);
            } catch (e) { setTimeout(updateBatchStatus, 5000); }
        }

        function formatResult(data) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            if (data.error) return '<p class="error">❌ ' + data.error + '</p>';
            html += '<p><strong>🔍 Verkkotunnus:</strong> ' + data.domain + '</p>';
            if (data.technologies && data.technologies.length > 0) {
                html += '<h3>🧩 Teknologiat</h3><div>';
                data.technologies.forEach(t => { html += '<span class="tech-tag">' + t + '</span>'; });
                html += '</div>';
            }
            if (data.headers) {
                html += '<h3>🛡️ Turvallisuusheadersit</h3><ul>';
                ['strict-transport-security', 'x-frame-options', 'x-content-type-options', 'content-security-policy'].forEach(h => {
                    const value = data.headers[h];
                    html += value ? '<li class="success">✅ ' + h + ': ' + value + '</li>' : '<li class="error">❌ ' + h + ' puuttuu</li>';
                });
                html += '</ul>';
            }
            if (data.ssl) {
                html += '<h3>🔒 SSL-sertifikaatti</h3>';
                const ssl = data.ssl;
                let statusHtml = ssl.valid && !ssl.expired ? '<span class="ssl-valid">✅ Voimassa</span>' : (ssl.expired ? '<span class="ssl-expired">❌ VANHENTUNUT!</span>' : '<span class="warning">⚠️ Ongelma</span>');
                html += '<div class="card"><strong>Tila:</strong> ' + statusHtml + '</div>';
                html += '<div class="grid"><div class="card"><strong>Myöntäjä:</strong><br>' + (ssl.issuer || 'Ei tiedossa') + '</div>';
                html += '<div class="card"><strong>Voimassa:</strong><br>' + (ssl.validFrom ? new Date(ssl.validFrom).toLocaleDateString('fi-FI') : '?') + ' → ' + (ssl.validTo ? new Date(ssl.validTo).toLocaleDateString('fi-FI') : '?') + '</div></div>';
                if (ssl.daysRemaining !== undefined) {
                    const days = ssl.daysRemaining;
                    html += days < 0 ? '<p class="error">⚠️ Vanhentui ' + Math.abs(days) + ' päivää sitten!</p>' : (days < 30 ? '<p class="warning">⚠️ Vanhenee ' + days + ' päivän kuluttua!</p>' : '<p class="success">✅ Voimassa ' + days + ' päivää.</p>');
                }
            }
            if (data.ports) {
                html += '<h3>🚪 Avoimet portit</h3>';
                const openPorts = data.ports.filter(p => p.state === 'open');
                if (openPorts.length > 0) {
                    html += '<ul>';
                    openPorts.forEach(p => { html += '<li class="port-open">' + p.port + ' (' + getServiceName(p.port) + ')</li>'; });
                    html += '</ul>';
                } else {
                    html += '<p class="success">✅ Ei avoimia portteja</p>';
                }
            }
            if (data.hibp) {
                html += '<h3>🔐 Tietovuodot (HIBP)</h3>';
                html += (data.hibp.breaches && data.hibp.breaches.length > 0) ? '<p class="error">⚠️ ' + data.hibp.breaches.length + ' tietomurtoa!</p>' : '<p class="success">✅ Ei tietomurtoja.</p>';
            }
            html += '<p><small>' + new Date().toLocaleString('fi-FI') + '</small></p>';
            return html;
        }

        function getServiceName(port) {
            const services = { 20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB' };
            return services[port] || 'Tuntematon';
        }

        window.onload = function() { scan(); };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. SKANNAUSFUNKTIOT
// ============================================
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

async function checkSSL(domain) {
    return new Promise((resolve) => {
        const options = { host: domain, port: 443, method: 'HEAD', rejectUnauthorized: false, timeout: 10000 };
        const req = https.request(options, (res) => {
            const socket = res.socket;
            const cert = socket.getPeerCertificate();
            if (!cert || Object.keys(cert).length === 0) return resolve({ valid: false, error: 'Ei sertifikaattia' });
            const now = new Date();
            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
            resolve({ valid: true, expired: validTo < now, issuer: cert.issuer?.CN || cert.issuer?.O || 'Tuntematon', validFrom: validFrom.toISOString(), validTo: validTo.toISOString(), daysRemaining });
        });
        req.on('error', (err) => resolve({ valid: false, error: err.message }));
        req.on('timeout', () => { req.destroy(); resolve({ valid: false, error: 'Aikakatkaisu' }); });
        req.end();
    });
}

async function performScan(domain) {
    const result = { domain, timestamp: new Date().toISOString() };
    try {
        const headerData = await fetchHeaders(domain);
        if (headerData.error) { result.error = headerData.error; return result; }
        result.headers = headerData.headers;
        result.technologies = identifyTechnologies(headerData.headers);
        result.ssl = await checkSSL(domain);
        result.ports = await scanPorts(domain);
        if (HIBP_API_KEY && HIBP_API_KEY !== 'testaa-ilman-avainta') {
            try {
                const hibpResponse = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(domain)}?truncateResponse=true`, { headers: { 'hibp-api-key': HIBP_API_KEY, 'User-Agent': 'WhiteWeaselRecon/1.0' } });
                result.hibp = { breaches: hibpResponse.data || [] };
            } catch (e) {
                result.hibp = { breaches: [] };
            }
        } else {
            result.hibp = { message: 'HIBP ei käytössä' };
        }
    } catch (e) { result.error = e.message; }
    return result;
}

// ============================================
// 3. MASSASKANNAUS
// ============================================
let batchState = { status: 'idle', currentIndex: 0, total: uniqueDomains.length, currentDomain: '', results: [], lastScan: null };

async function runBatchScan() {
    if (batchState.status === 'scanning') return;
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
        await new Promise(resolve => setTimeout(resolve, 300));
    }
    batchState.status = 'idle';
    batchState.lastScan = new Date().toISOString();
    batchState.currentDomain = '';
    console.log('🏁 Massaskannaus valmis!');
}

// ============================================
// 4. API-REITIT
// ============================================
app.get('/api/scan', async (req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.status(400).json({ error: 'Domain puuttuu' });
    try { res.json(await performScan(domain)); } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/scan-batch', async (req, res) => {
    if (batchState.status === 'scanning') return res.status(409).json({ error: 'Skannaus jo käynnissä!' });
    runBatchScan().catch(console.error);
    res.json({ message: 'Massaskannaus käynnistetty! Seuraa edistymistä tilapalkista.' });
});

app.get('/api/batch-status', (req, res) => {
    res.json({ status: batchState.status, currentIndex: batchState.currentIndex, total: batchState.total, currentDomain: batchState.currentDomain, lastScan: batchState.lastScan, resultsCount: batchState.results.length });
});

app.get('/api/batch-results', (req, res) => {
    if (batchState.results.length === 0) return res.status(404).json({ error: 'Ei skannattuja kohteita. Suorita ensin massaskannaus.' });
    res.json({ results: batchState.results, total: batchState.results.length, timestamp: new Date().toISOString() });
});

// ============================================
// 5. KÄYNNISTYS
// ============================================
app.listen(PORT, () => {
    console.log('🦡 White Weasel Recon v2.5');
    console.log('✅ Palvelin käynnissä portissa ' + PORT);
    console.log('📋 ' + uniqueDomains.length + ' kohdetta listassa');
    console.log('📝 Skannaus käynnistyy vain napista painamalla');
});
