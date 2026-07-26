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
const SCAN_INTERVAL = parseInt(process.env.SCAN_INTERVAL) || 86400000; // 24h

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
            input { width: 45%; border: 2px solid #bdc3c7; border-radius: 5px; }
            button { background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #2980b9; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            #autostatus { margin-top: 10px; padding: 10px; background: #e8f4f8; border-radius: 5px; border-left: 4px solid #3498db; }
            .loading { color: #3498db; font-style: italic; }
            .error { color: #e74c3c; font-weight: bold; }
            .success { color: #27ae60; }
            .warning { color: #f39c12; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
            .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
            .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #3498db; }
            .stat-number { font-size: 28px; font-weight: bold; color: #2c3e50; }
            .stat-label { color: #7f8c8d; font-size: 14px; }
            .risk-critical { color: #e74c3c; font-weight: bold; }
            .risk-high { color: #e67e22; font-weight: bold; }
            .risk-medium { color: #f39c12; font-weight: bold; }
            .risk-low { color: #3498db; font-weight: bold; }
            .risk-none { color: #27ae60; font-weight: bold; }
            pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 13px; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        <p>Syötä verkkotunnus (esim. <strong>suomi.fi</strong>)</p>
        <input type="text" id="domain" placeholder="esim. suomi.fi" value="suomi.fi">
        <button onclick="scan()">🔍 Skannaa</button>
        <button onclick="scanAll()">🔄 Skannaa 100 .fi-kohdetta</button>
        <button onclick="generateReport()">📊 Luo raportti</button>
        <div id="autostatus">
            <span id="statusText">⏳ Ladataan tilaa...</span>
        </div>
        <div id="result">
            <p class="loading">Odota skannausta...</p>
        </div>
        <div class="footer">White Weasel Recon v0.6 — Massaskannaus ja raportointi</div>

        <script>
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

        async function scanAll() {
            if (!confirm('Skannataan 100 satunnaista .fi-domainia. Tämä voi kestää useita minuutteja. Jatketaanko?')) return;
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään massaskannaus...</p>';
            try {
                const response = await fetch('/api/scan-batch', { method: 'POST' });
                const data = await response.json();
                document.getElementById('result').innerHTML = '<p class="success">✅ ' + data.message + '</p>';
                updateStatus();
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
            }
        }

        async function generateReport() {
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Luodaan raporttia...</p>';
            try {
                const response = await fetch('/api/report');
                const data = await response.json();
                document.getElementById('result').innerHTML = formatReport(data);
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
                    statusText.innerHTML = '🟢 Joutilaana. Skannattuja: ' + data.resultsCount + ' | Viimeisin: ' + (data.lastScan ? new Date(data.lastScan).toLocaleString('fi-FI') : 'Ei vielä');
                } else if (data.status === 'scanning') {
                    statusText.innerHTML = '🟡 Skannaus käynnissä... ' + data.currentIndex + '/' + data.total + ': ' + data.currentDomain;
                } else {
                    statusText.innerHTML = '⚪ Tila: ' + data.status;
                }
            } catch (e) {}
        }

        function formatResult(data) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            if (data.error) return '<p class="error">❌ ' + data.error + '</p>';
            
            html += '<p><strong>🔍 Verkkotunnus:</strong> ' + data.domain + '</p>';
            
            if (data.technologies && data.technologies.length > 0) {
                html += '<h3>🧩 Teknologiat</h3><div>';
                data.technologies.forEach(t => {
                    html += '<span style="display:inline-block;background:#2c3e50;color:white;padding:4px 12px;border-radius:20px;margin:4px;font-size:13px;">' + t + '</span>';
                });
                html += '</div>';
            }

            if (data.headers) {
                html += '<h3>🛡️ Turvallisuusheadersit</h3><ul>';
                const important = ['strict-transport-security', 'x-frame-options', 'x-content-type-options', 'content-security-policy'];
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
                html += '<h3>🔒 SSL</h3>';
                if (data.ssl.valid) {
                    html += '<p class="success">✅ Voimassa, ' + data.ssl.daysRemaining + ' päivää jäljellä</p>';
                } else {
                    html += '<p class="error">❌ Ongelma: ' + (data.ssl.error || 'Vanhentunut') + '</p>';
                }
            }

            if (data.ports) {
                const openPorts = data.ports.filter(p => p.state === 'open');
                if (openPorts.length > 0) {
                    html += '<h3>🚪 Avoimet portit</h3><p class="error">⚠️ ' + openPorts.map(p => p.port + ' (' + p.name + ')').join(', ') + '</p>';
                }
            }

            return html;
        }

        function formatReport(data) {
            if (data.error) return '<p class="error">❌ ' + data.error + '</p>';
            
            let html = '<h2>📊 White Weasel - Raportti</h2>';
            html += '<p><strong>Skannausajankohta:</strong> ' + new Date(data.timestamp).toLocaleString('fi-FI') + '</p>';
            html += '<p><strong>Skannattuja kohteita:</strong> ' + data.totalScanned + '</p>';

            html += '<h3>📈 Yhteenveto</h3>';
            html += '<div class="stat-grid">';
            html += '<div class="stat-card"><div class="stat-number">' + data.summary.total + '</div><div class="stat-label">Skannatut kohteet</div></div>';
            html += '<div class="stat-card" style="border-left-color:#e74c3c;"><div class="stat-number">' + data.summary.critical + '</div><div class="stat-label">Kriittiset riskit</div></div>';
            html += '<div class="stat-card" style="border-left-color:#e67e22;"><div class="stat-number">' + data.summary.high + '</div><div class="stat-label">Korkeat riskit</div></div>';
            html += '<div class="stat-card" style="border-left-color:#f39c12;"><div class="stat-number">' + data.summary.medium + '</div><div class="stat-label">Keskitasoiset riskit</div></div>';
            html += '<div class="stat-card" style="border-left-color:#3498db;"><div class="stat-number">' + data.summary.low + '</div><div class="stat-label">Matalat riskit</div></div>';
            html += '<div class="stat-card" style="border-left-color:#27ae60;"><div class="stat-number">' + data.summary.secure + '</div><div class="stat-label">Turvalliset</div></div>';
            html += '</div>';

            if (data.topTechnologies && data.topTechnologies.length > 0) {
                html += '<h3>🧩 Yleisimmät teknologiat</h3><ul>';
                data.topTechnologies.forEach(t => {
                    html += '<li><strong>' + t.name + '</strong>: ' + t.count + ' kohdetta (' + t.percentage + '%)</li>';
                });
                html += '</ul>';
            }

            if (data.missingHeaders && data.missingHeaders.length > 0) {
                html += '<h3>🛡️ Yleisimmin puuttuvat turvallisuusheadersit</h3><ul>';
                data.missingHeaders.forEach(h => {
                    html += '<li><strong>' + h.name + '</strong>: puuttuu ' + h.count + ' kohteelta (' + h.percentage + '%)</li>';
                });
                html += '</ul>';
            }

            if (data.openPorts && data.openPorts.length > 0) {
                html += '<h3>🚪 Yleisimmät avoimet portit</h3><ul>';
                data.openPorts.forEach(p => {
                    html += '<li><strong>Portti ' + p.port + '</strong> (' + p.name + '): auki ' + p.count + ' kohteella (' + p.percentage + '%)</li>';
                });
                html += '</ul>';
            }

            if (data.observations && data.observations.length > 0) {
                html += '<h3>💡 Huomioitavaa</h3><ul>';
                data.observations.forEach(o => {
                    html += '<li>' + o + '</li>';
                });
                html += '</ul>';
            }

            if (data.recommendations && data.recommendations.length > 0) {
                html += '<h3>🎯 Suositukset</h3><ul>';
                data.recommendations.forEach(r => {
                    html += '<li><strong>' + r.priority + ':</strong> ' + r.text + '</li>';
                });
                html += '</ul>';
            }

            html += '<p><small>Raportti luotu: ' + new Date().toLocaleString('fi-FI') + '</small></p>';
            html += '<button onclick="window.location.href=\'/api/report/download\'">📥 Lataa raportti (JSON)</button>';
            return html;
        }

        window.onload = function() {
            updateStatus();
            setInterval(updateStatus, 5000);
        };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. DOMAIN LISTA (100 satunnaista .fi)
// ============================================
const FIXED_DOMAINS = [
    'suomi.fi', 'valtioneuvosto.fi', 'eduskunta.fi', 'traficom.fi',
    'kyberturvallisuuskeskus.fi', 'digi.fi', 'verohallinto.fi',
    'kela.fi', 'migri.fi', 'polisi.fi', 'om.fi', 'vm.fi', 'defmin.fi',
    'helsinki.fi', 'tampere.fi', 'turku.fi', 'oulu.fi', 'jyvaskyla.fi',
    'lahti.fi', 'kuopio.fi', 'pori.fi', 'lappeenranta.fi', 'rovaniemi.fi',
    'aalto.fi', 'tuni.fi', 'utu.fi',
    'nokia.fi', 'kone.fi', 'valmet.fi', 'fortum.fi', 'storaenso.fi',
    'kesko.fi', 's-group.fi', 'lidl.fi', 'prisma.fi', 'tokmanni.fi',
    'verkkokauppa.fi', 'gigantti.fi', 'power.fi', 'sokos.fi',
    'aleksi.fi', 'johanssons.fi', 'otavanopus.fi',
    'kansalliskirjasto.fi', 'musiikkitalo.fi', 'kansallismuseo.fi',
    'ateneum.fi', 'omakaupunki.fi', 'yritys.fi',
    'savonsanomat.fi', 'karjalainen.fi', 'lapinkansa.fi',
    'is.fi', 'hs.fi', 'ts.fi', 'aamulehti.fi', 'kaleva.fi',
    'kestavyys.fi', 'luontoon.fi', 'suomenluonto.fi',
    'talouselama.fi', 'taloussanomat.fi', 'arvopaperi.fi',
    'videon.fi', 'digikanava.fi', 'suoratoisto.fi',
    'tiedoteliikenne.fi', 'verkko.fi', 'digi-verkko.fi'
];

function generateRandomDomains(count) {
    const words = ['kettu', 'susikarhu', 'hirvi', 'lohi', 'sammal', 'kivi', 'metsa', 'jarvi', 'tuli', 'vesi', 'tuuli', 'pilvi', 'lumi', 'ranta', 'niemi', 'saari', 'kangas', 'aho', 'salo', 'korpela'];
    const domains = [];
    const used = new Set(FIXED_DOMAINS);
    
    for (const d of FIXED_DOMAINS) used.add(d);
    
    let attempts = 0;
    while (domains.length < count && attempts < 10000) {
        attempts++;
        const word1 = words[Math.floor(Math.random() * words.length)];
        const word2 = words[Math.floor(Math.random() * words.length)];
        const domain = word1 + word2 + '.fi';
        if (!used.has(domain)) {
            used.add(domain);
            domains.push(domain);
        }
    }
    return domains;
}

let TARGET_DOMAINS = [...FIXED_DOMAINS];
const randomDomains = generateRandomDomains(100 - FIXED_DOMAINS.length);
TARGET_DOMAINS = TARGET_DOMAINS.concat(randomDomains);
TARGET_DOMAINS = TARGET_DOMAINS.slice(0, 100);

console.log(`📋 ${TARGET_DOMAINS.length} kohdetta listassa (${FIXED_DOMAINS.length} kiinteää + ${TARGET_DOMAINS.length - FIXED_DOMAINS.length} satunnaista)`);

// ============================================
// 3. SKANNAUSFUNKTIOT
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
        const response = await axios.get(`https://${domain}`, { timeout: 8000, maxRedirects: 5 });
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
        else techs.push('Generator: ' + headers['generator']);
    }
    return techs;
}

async function checkSSL(domain) {
    return new Promise((resolve) => {
        const req = https.request({ host: domain, port: 443, method: 'HEAD', rejectUnauthorized: false, timeout: 8000 }, (res) => {
            const cert = res.socket.getPeerCertificate();
            if (!cert || Object.keys(cert).length === 0) return resolve({ valid: false });
            const now = new Date();
            const validTo = new Date(cert.valid_to);
            const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
            resolve({ valid: true, expired: validTo < now, daysRemaining, issuer: cert.issuer?.CN || 'Tuntematon' });
        });
        req.on('error', () => resolve({ valid: false, error: 'Yhteysvirhe' }));
        req.on('timeout', () => { req.destroy(); resolve({ valid: false, error: 'Aikakatkaisu' }); });
        req.end();
    });
}

async function performScan(domain) {
    const result = { domain, timestamp: new Date().toISOString() };
    try {
        const headerData = await fetchHeaders(domain);
        if (headerData.error) {
            result.error = headerData.error;
            return result;
        }
        result.headers = headerData.headers;
        result.technologies = identifyTechnologies(headerData.headers);
        
        result.ssl = await checkSSL(domain);
        result.ports = await scanPorts(domain);
        
        try {
            result.dns = {
                A: await dns.resolve4(domain).catch(() => []),
                MX: await dns.resolveMx(domain).catch(() => [])
            };
        } catch (e) { result.dns = { error: e.message }; }
        
    } catch (e) {
        result.error = e.message;
    }
    return result;
}

// ============================================
// 4. RISKIANALYYSI JA RAPORTOINTI
// ============================================
function analyzeRisks(results) {
    const findings = [];
    let critical = 0, high = 0, medium = 0, low = 0, secure = 0;

    results.forEach(r => {
        let riskLevel = 'secure';
        const issues = [];

        if (r.ssl && !r.ssl.valid) {
            issues.push('SSL-sertifikaatti vanhentunut tai virheellinen');
            riskLevel = 'high';
        } else if (r.ssl && r.ssl.daysRemaining < 30) {
            issues.push('SSL-sertifikaatti vanhenee ' + r.ssl.daysRemaining + ' päivän kuluttua');
            if (riskLevel === 'secure') riskLevel = 'medium';
        }

        const importantHeaders = ['strict-transport-security', 'x-frame-options', 'x-content-type-options'];
        let missingHeaders = importantHeaders.filter(h => !r.headers || !r.headers[h]);
        if (missingHeaders.length > 0) {
            issues.push('Puuttuvat turvallisuusheadersit: ' + missingHeaders.join(', '));
            if (riskLevel === 'secure') riskLevel = 'medium';
        }

        if (r.ports) {
            const riskyPorts = r.ports.filter(p => p.state === 'open' && ![80, 443].includes(p.port));
            if (riskyPorts.length > 0) {
                issues.push('Avoimet portit: ' + riskyPorts.map(p => p.port + ' (' + p.name + ')').join(', '));
                riskLevel = 'high';
            }
        }

        if (r.headers && r.headers['server'] && r.headers['server'].match(/\d+\.\d+/)) {
            issues.push('Palvelinversio paljastuu: ' + r.headers['server']);
            if (riskLevel === 'secure') riskLevel = 'low';
        }

        findings.push({ domain: r.domain, riskLevel, issues, technologies: r.technologies || [] });
        
        if (riskLevel === 'critical') critical++;
        else if (riskLevel === 'high') high++;
        else if (riskLevel === 'medium') medium++;
        else if (riskLevel === 'low') low++;
        else secure++;
    });

    return { findings, summary: { total: results.length, critical, high, medium, low, secure } };
}

function generateReportData(results) {
    const analysis = analyzeRisks(results);
    
    const techCount = {};
    analysis.findings.forEach(f => {
        f.technologies.forEach(t => {
            techCount[t] = (techCount[t] || 0) + 1;
        });
    });
    const topTechnologies = Object.entries(techCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([name, count]) => ({
            name,
            count,
            percentage: Math.round((count / results.length) * 100)
        }));

    const missingHeadersCount = {};
    analysis.findings.forEach(f => {
        if (f.issues.some(i => i.includes('Puuttuvat turvallisuusheadersit'))) {
            const match = f.issues.find(i => i.includes('Puuttuvat turvallisuusheadersit'));
            if (match) {
                const headers = match.replace('Puuttuvat turvallisuusheadersit: ', '').split(', ');
                headers.forEach(h => {
                    missingHeadersCount[h] = (missingHeadersCount[h] || 0) + 1;
                });
            }
        }
    });
    const missingHeaders = Object.entries(missingHeadersCount)
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({
            name,
            count,
            percentage: Math.round((count / results.length) * 100)
        }));

    const portsCount = {};
    results.forEach(r => {
        if (r.ports) {
            r.ports.filter(p => p.state === 'open').forEach(p => {
                const key = p.port + ':' + p.name;
                portsCount[key] = (portsCount[key] || 0) + 1;
            });
        }
    });
    const openPorts = Object.entries(portsCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([key, count]) => {
            const [port, name] = key.split(':');
            return { port: parseInt(port), name, count, percentage: Math.round((count / results.length) * 100) };
        });

    const observations = [];
    const secureCount = analysis.summary.secure;
    if (secureCount === results.length) {
        observations.push('Kaikki skannatut kohteet ovat turvallisia! Hyvä työ!');
    } else if (secureCount > results.length * 0.5) {
        observations.push('Yli puolet kohteista on turvallisia. Hyvä perustaso.');
    } else {
        observations.push('Vain ' + secureCount + '/' + results.length + ' kohdetta on turvallisia. On parantamisen varaa.');
    }
    if (analysis.summary.high > 0) {
        observations.push(analysis.summary.high + ' kohteella on korkean riskin ongelmia (SSL-virheet, avoimet portit).');
    }
    if (topTechnologies.length > 0) {
        observations.push('Yleisin teknologia on ' + topTechnologies[0].name + ' (' + topTechnologies[0].percentage + '% kohteista).');
    }

    const recommendations = [];
    if (analysis.summary.high > 0) {
        recommendations.push({ priority: 'Kriittinen', text: 'Korjaa korkean riskin ongelmat: päivitä SSL-sertifikaatit ja sulje tarpeettomat portit.' });
    }
    if (missingHeaders.length > 0) {
        recommendations.push({ priority: 'Korkea', text: 'Lisää puuttuvat turvallisuusheadersit: ' + missingHeaders.map(h => h.name).join(', ') });
    }
    if (analysis.summary.medium > 0) {
        recommendations.push({ priority: 'Keskitaso', text: 'Tarkista SSL-sertifikaattien vanhenemispäivämäärät ja varmista, että ne uusitaan ajoissa.' });
    }
    if (topTechnologies.some(t => t.name.includes('Apache') || t.name.includes('IIS'))) {
        recommendations.push({ priority: 'Matala', text: 'Harkitse palvelinversioiden piilottamista (Server-otsikon poistaminen).' });
    }
    if (recommendations.length === 0) {
        recommendations.push({ priority: 'Hyvä', text: 'Kaikki hyvin! Jatka hyvää työtä.' });
    }

    return {
        timestamp: new Date().toISOString(),
        totalScanned: results.length,
        summary: analysis.summary,
        topTechnologies,
        missingHeaders,
        openPorts,
        observations,
        recommendations,
        findings: analysis.findings.slice(0, 20)
    };
}

// ============================================
// 5. API-REITIT
// ============================================
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

async function runBatchScan() {
    if (scanState.status === 'scanning') {
        console.log('⏳ Skannaus jo käynnissä');
        return;
    }

    console.log(`🚀 Käynnistetään massaskannaus (${TARGET_DOMAINS.length} kohdetta)...`);
    scanState.status = 'scanning';
    scanState.results = [];

    for (let i = 0; i < TARGET_DOMAINS.length; i++) {
        const domain = TARGET_DOMAINS[i];
        scanState.currentIndex = i + 1;
        scanState.currentDomain = domain;
        console.log(`🦡 [${i+1}/${TARGET_DOMAINS.length}] Skannataan: ${domain}`);

        const result = await performScan(domain);
        scanState.results.push(result);
        await new Promise(resolve => setTimeout(resolve, 500)); // Pieni viive
    }

    scanState.status = 'idle';
    scanState.lastScan = new Date().toISOString();
    scanState.currentDomain = '';
    await saveResults();
    console.log('🏁 Massaskannaus valmis!');
}

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

app.post('/api/scan-batch', async (req, res) => {
    if (scanState.status === 'scanning') {
        return res.status(409).json({ message: 'Skannaus jo käynnissä!' });
    }
    runBatchScan().catch(console.error);
    res.json({ message: 'Massaskannaus käynnistetty!' });
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

app.get('/api/report', (req, res) => {
    if (scanState.results.length === 0) {
        return res.status(404).json({ error: 'Ei skannattuja kohteita. Suorita ensin skannaus.' });
    }
    const report = generateReportData(scanState.results);
    res.json(report);
});

app.get('/api/report/download', async (req, res) => {
    if (scanState.results.length === 0) {
        return res.status(404).json({ error: 'Ei skannattuja kohteita.' });
    }
    const report = generateReportData(scanState.results);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=white-weasel-report-${new Date().toISOString().slice(0,10)}.json`);
    res.json(report);
});

// ============================================
// 6. KÄYNNISTYS
// ============================================
app.listen(PORT, async () => {
    console.log(`🦡 White Weasel Recon v0.6 — Massaskannaus ja raportointi`);
    console.log(`📋 ${TARGET_DOMAINS.length} kohdetta listassa`);
    await loadResults();

    if (AUTO_SCAN_ENABLED) {
        console.log('⏳ Ensimmäinen massaskannaus 30 sekunnin kuluttua...');
        setTimeout(() => runBatchScan().catch(console.error), 30000);
        setInterval(() => runBatchScan().catch(console.error), SCAN_INTERVAL);
        console.log(`⏰ Skannausväli: ${SCAN_INTERVAL/3600000} tuntia`);
    }
});
