const express = require('express');
const axios = require('axios');
const https = require('https');
const net = require('net');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// VERSIO
// ============================================
const VERSION = '3.3.1';

// ============================================
// KOHDELISTA (sisältää IP-osoitteen)
// ============================================
const TARGET_DOMAINS = [
    '185.192.15.123',   // IP-osoite (testikohde)
    'suomi.fi', 
    'valtioneuvosto.fi', 
    'eduskunta.fi',
    'helsinki.fi', 
    'tampere.fi', 
    'turku.fi',
    'oulu.fi', 
    'jyvaskyla.fi', 
    'lahti.fi',
    'kuopio.fi', 
    'pori.fi', 
    'lappeenranta.fi'
];

console.log('🦡 White Weasel v' + VERSION);
console.log('📋 ' + TARGET_DOMAINS.length + ' kohdetta listassa (mm. IP 185.192.15.123)');

// ============================================
// 1. KÄYTTÖLIITTYMÄ (sama kuin aiemmin, versionumero päivitetty)
// ============================================
app.get('/', (req, res) => {
    const targetCount = TARGET_DOMAINS.length;
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>White Weasel Recon</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
            .logo { font-size: 2em; }
            .weasel { color: #2c3e50; }
            .white { color: #ecf0f1; background: #2c3e50; padding: 2px 8px; border-radius: 5px; }
            .version { font-size: 14px; color: #7f8c8d; margin-left: 10px; }
            button { padding: 12px 24px; font-size: 16px; margin: 5px; cursor: pointer; border: none; border-radius: 5px; transition: all 0.3s; }
            button:hover { transform: scale(1.05); }
            button.danger { background: #e74c3c; color: white; }
            button.danger:hover { background: #c0392b; }
            button.primary { background: #3498db; color: white; }
            button.primary:hover { background: #2980b9; }
            button.success { background: #27ae60; color: white; }
            button.success:hover { background: #219a52; }
            button.secondary { background: #2c3e50; color: white; }
            button.secondary:hover { background: #1a252f; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            #status { margin-top: 10px; padding: 10px; background: #e8f4f8; border-radius: 5px; border-left: 4px solid #3498db; }
            .loading { color: #3498db; }
            .error { color: #e74c3c; }
            .success { color: #27ae60; }
            .warning { color: #f39c12; }
            .domain-item { padding: 8px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
            .report-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
            .report-card { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #3498db; }
            .report-number { font-size: 28px; font-weight: bold; color: #2c3e50; }
            .report-label { color: #7f8c8d; font-size: 14px; }
            .risk-critical { background: #fde8e8; border-left-color: #e74c3c; }
            .risk-high { background: #fef5e7; border-left-color: #e67e22; }
            .risk-medium { background: #fef9e7; border-left-color: #f39c12; }
            .risk-low { background: #ebf5fb; border-left-color: #3498db; }
            .risk-secure { background: #eafaf1; border-left-color: #27ae60; }
            .report-download { margin: 20px 0; text-align: center; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; border-top: 1px solid #ddd; padding-top: 15px; }
            .header-ok { color: #27ae60; }
            .header-missing { color: #e74c3c; }
            .header-warning { color: #f39c12; }
            .tech-tag { display: inline-block; background: #2c3e50; color: white; padding: 4px 12px; border-radius: 20px; margin: 4px; font-size: 13px; }
            .ssh-banner { background: #2c3e50; color: #ecf0f1; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 13px; margin: 5px 0; }
        </style>
    </head>
    <body>
        <h1>
            <span class="white">White</span><span class="weasel">Weasel</span> 🦡
            <span class="version">v${VERSION}</span>
        </h1>
        
        <div>
            <button onclick="scanBatch()" class="danger">🔄 Skannaa ${targetCount} kohdetta</button>
            <button onclick="showReport()" class="primary" id="reportBtn" disabled>📊 Näytä raportti</button>
            <button onclick="downloadReport()" class="success" id="downloadBtn" disabled>📥 Lataa raportti (JSON)</button>
        </div>
        
        <div id="status">
            <span id="statusText">⏳ Valmis...</span>
        </div>
        
        <div id="result">
            <p>Valmis skannaamaan ${targetCount} kohdetta (mukana IP 185.192.15.123). Paina "Skannaa"-nappia aloittaaksesi.</p>
        </div>
        
        <div class="footer">White Weasel v${VERSION} — IP-tuki, SSH-banneri, headerit</div>

        <script>
        const VERSION = '${VERSION}';
        let isRunning = false;
        let results = [];
        let reportData = null;

        async function scanBatch() {
            if (isRunning) { alert('Skannaus on jo käynnissä!'); return; }
            if (!confirm('Skannataan ${targetCount} kohdetta. Tämä voi kestää 5-10 minuuttia. Jatketaanko?')) return;
            
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään massaskannaus...</p>';
            document.getElementById('reportBtn').disabled = true;
            document.getElementById('downloadBtn').disabled = true;
            isRunning = true;
            
            try {
                const response = await fetch('/api/scan-batch', { method: 'POST' });
                const data = await response.json();
                if (data.error) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ ' + data.error + '</p>';
                    isRunning = false;
                    return;
                }
                document.getElementById('result').innerHTML = '<p class="success">✅ ' + data.message + '</p>';
                updateStatus();
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
                isRunning = false;
            }
        }

        async function updateStatus() {
            if (!isRunning) return;
            try {
                const response = await fetch('/api/batch-status');
                const data = await response.json();
                const statusText = document.getElementById('statusText');
                if (data.status === 'idle') {
                    statusText.innerHTML = '🟢 Valmis! Skannattu ' + data.total + ' kohdetta.';
                    isRunning = false;
                    const res = await fetch('/api/batch-results');
                    const resultsData = await res.json();
                    if (resultsData.results && resultsData.results.length > 0) {
                        results = resultsData.results;
                        document.getElementById('reportBtn').disabled = false;
                        document.getElementById('downloadBtn').disabled = false;
                        showBasicResults(results);
                    }
                    return;
                } else if (data.status === 'scanning') {
                    statusText.innerHTML = '🟡 Skannaus käynnissä... ' + data.currentIndex + '/' + data.total + ': ' + data.currentDomain;
                }
                setTimeout(updateStatus, 3000);
            } catch (e) {
                setTimeout(updateStatus, 5000);
            }
        }

        function showBasicResults(results) {
            let html = '<h2>📊 Skannaus valmis!</h2>';
            html += '<p>Skannattiin ' + results.length + ' kohdetta. Paina "Näytä raportti" nähdäksesi yksityiskohdat.</p>';
            
            const validSSL = results.filter(r => r.ssl && r.ssl.valid).length;
            const openPorts = results.filter(r => r.ports && r.ports.some(p => p.state === 'open')).length;
            const hasHeaders = results.filter(r => r.headers && r.headers['strict-transport-security']).length;
            
            html += '<div class="report-grid">';
            html += '<div class="report-card"><div class="report-number">' + results.length + '</div><div class="report-label">Skannatut kohteet</div></div>';
            html += '<div class="report-card risk-secure"><div class="report-number">' + validSSL + '</div><div class="report-label">SSL voimassa</div></div>';
            html += '<div class="report-card risk-high"><div class="report-number">' + openPorts + '</div><div class="report-label">Avoimia portteja</div></div>';
            html += '<div class="report-card risk-low"><div class="report-number">' + hasHeaders + '</div><div class="report-label">HSTS käytössä</div></div>';
            html += '</div>';
            
            document.getElementById('result').innerHTML = html;
        }

        async function showReport() {
            if (results.length === 0) {
                alert('Ei skannattuja kohteita. Suorita ensin skannaus.');
                return;
            }
            
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Luodaan raporttia...</p>';
            
            try {
                const response = await fetch('/api/report');
                const data = await response.json();
                if (data.error) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ ' + data.error + '</p>';
                    return;
                }
                reportData = data;
                document.getElementById('result').innerHTML = renderReport(data);
            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + error.message + '</p>';
            }
        }

        function renderReport(data) {
            let html = '<h2>📊 White Weasel - Raportti</h2>';
            html += '<p><strong>Skannausajankohta:</strong> ' + new Date(data.timestamp).toLocaleString('fi-FI') + '</p>';
            html += '<p><strong>Skannattuja kohteita:</strong> ' + data.totalScanned + '</p>';

            html += '<h3>📈 Yhteenveto</h3>';
            html += '<div class="report-grid">';
            html += '<div class="report-card"><div class="report-number">' + data.summary.total + '</div><div class="report-label">Skannatut kohteet</div></div>';
            html += '<div class="report-card risk-critical"><div class="report-number">' + data.summary.critical + '</div><div class="report-label">Kriittiset riskit</div></div>';
            html += '<div class="report-card risk-high"><div class="report-number">' + data.summary.high + '</div><div class="report-label">Korkeat riskit</div></div>';
            html += '<div class="report-card risk-medium"><div class="report-number">' + data.summary.medium + '</div><div class="report-label">Keskitasoiset riskit</div></div>';
            html += '<div class="report-card risk-low"><div class="report-number">' + data.summary.low + '</div><div class="report-label">Matalat riskit</div></div>';
            html += '<div class="report-card risk-secure"><div class="report-number">' + data.summary.secure + '</div><div class="report-label">Turvalliset</div></div>';
            html += '</div>';

            // Teknologiat
            if (data.technologies && data.technologies.length > 0) {
                html += '<h3>🧩 Tunnistetut teknologiat</h3>';
                html += '<div>';
                data.technologies.forEach(t => {
                    html += '<span class="tech-tag">' + t + '</span>';
                });
                html += '</div>';
            }

            // SSH-bannerit (erillinen)
            if (data.sshBanners && data.sshBanners.length > 0) {
                html += '<h3>🔑 SSH-palvelimet (bannerit)</h3>';
                data.sshBanners.forEach(b => {
                    html += '<div class="ssh-banner">' + b.domain + ': ' + b.banner + '</div>';
                });
            }

            // HTTP-headers
            if (data.headers && data.headers.length > 0) {
                html += '<h3>🛡️ Turvallisuusheadersit</h3>';
                html += '<ul>';
                data.headers.forEach(h => {
                    const statusClass = h.value ? 'header-ok' : 'header-missing';
                    html += '<li class="' + statusClass + '"><strong>' + h.name + '</strong>: ' + (h.value || 'PUUTTUU') + '</li>';
                });
                html += '</ul>';
            }

            // Havaitut ongelmat
            if (data.findings && data.findings.length > 0) {
                html += '<h3>⚠️ Havaitut ongelmat</h3>';
                html += '<div class="domain-list">';
                data.findings.forEach(f => {
                    const riskClass = 'risk-' + f.riskLevel;
                    html += '<div class="domain-item ' + riskClass + '">';
                    html += '<span><strong>' + f.domain + '</strong></span>';
                    html += '<span>' + f.issues.join(', ') + '</span>';
                    html += '</div>';
                });
                html += '</div>';
            }

            // Huomioitavaa
            if (data.observations && data.observations.length > 0) {
                html += '<h3>💡 Huomioitavaa</h3><ul>';
                data.observations.forEach(o => {
                    html += '<li>' + o + '</li>';
                });
                html += '</ul>';
            }

            // Suositukset
            if (data.recommendations && data.recommendations.length > 0) {
                html += '<h3>🎯 Suositukset</h3><ul>';
                data.recommendations.forEach(r => {
                    html += '<li><strong>' + r.priority + ':</strong> ' + r.text + '</li>';
                });
                html += '</ul>';
            }

            html += '<div class="report-download">';
            html += '<button onclick="downloadReport()" class="success">📥 Lataa raportti (JSON)</button>';
            html += '</div>';

            html += '<p><small>Raportti luotu: ' + new Date().toLocaleString('fi-FI') + '</small></p>';
            return html;
        }

        function downloadReport() {
            if (!reportData) {
                alert('Luo ensin raportti "Näytä raportti" -napilla.');
                return;
            }
            
            const dataStr = JSON.stringify(reportData, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'white-weasel-report-' + new Date().toISOString().slice(0,10) + '.json';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }

        window.onload = function() {
            document.getElementById('result').innerHTML = '<p>Valmis skannaamaan ${targetCount} kohdetta (mukana IP 185.192.15.123). Paina "Skannaa"-nappia aloittaaksesi.</p>';
        };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. SKANNAUSFUNKTIOT (laajennettu SSH-bannerilla)
// ============================================

// Tarkistetaan portti ja yritetään tunnistaa SSH-banneri (erityisesti portti 22)
async function checkPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(timeout);
        let banner = null;
        
        socket.on('connect', () => {
            // Jos portti on 22, yritetään lukea SSH-banneri
            if (port === 22) {
                socket.write('\n');
                socket.once('data', (data) => {
                    banner = data.toString().trim();
                    socket.destroy();
                    resolve({ port, state: 'open', banner });
                });
                // Jos banneri ei tule, annetaan aikaa
                setTimeout(() => {
                    if (!banner) {
                        socket.destroy();
                        resolve({ port, state: 'open', banner: null });
                    }
                }, 1000);
            } else {
                socket.destroy();
                resolve({ port, state: 'open' });
            }
        });
        
        socket.on('timeout', () => { 
            socket.destroy(); 
            resolve({ port, state: 'filtered' }); 
        });
        
        socket.on('error', () => { 
            socket.destroy(); 
            resolve({ port, state: 'closed' }); 
        });
        
        socket.connect(port, host);
    });
}

// Tarkistetaan SSL
async function checkSSL(domain) {
    return new Promise((resolve) => {
        const options = { 
            host: domain, 
            port: 443, 
            method: 'HEAD', 
            rejectUnauthorized: false, 
            timeout: 8000 
        };
        const req = https.request(options, (res) => {
            const cert = res.socket.getPeerCertificate();
            if (!cert || Object.keys(cert).length === 0) {
                return resolve({ valid: false });
            }
            const now = new Date();
            const validTo = new Date(cert.valid_to);
            const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
            resolve({ 
                valid: true, 
                expired: validTo < now, 
                daysRemaining: daysRemaining 
            });
        });
        req.on('error', () => resolve({ valid: false }));
        req.on('timeout', () => { 
            req.destroy(); 
            resolve({ valid: false }); 
        });
        req.end();
    });
}

// Haetaan HTTP-headers (toimii sekä domainille että IP:lle)
async function fetchHeaders(host) {
    try {
        const response = await axios.get(`https://${host}`, { 
            timeout: 10000, 
            maxRedirects: 5,
            headers: { 'User-Agent': 'WhiteWeaselRecon/3.3.1' }
        });
        return { headers: response.headers, status: response.status };
    } catch (error) {
        if (error.response) {
            return { headers: error.response.headers || {}, status: error.response.status };
        }
        return { error: error.message };
    }
}

// Tunnistetaan teknologiat
function identifyTechnologies(headers) {
    const techs = [];
    
    if (headers['server']) {
        const server = headers['server'];
        techs.push('Web: ' + server);
        
        const s = server.toLowerCase();
        if (s.includes('nginx')) techs.push('Nginx');
        else if (s.includes('apache')) techs.push('Apache');
        else if (s.includes('iis')) techs.push('IIS');
        else if (s.includes('cloudflare')) techs.push('Cloudflare');
    }
    
    if (headers['x-powered-by']) {
        techs.push('X-Powered-By: ' + headers['x-powered-by']);
    }
    
    if (headers['generator']) {
        techs.push('CMS: ' + headers['generator']);
    }
    
    return techs;
}

// Yksi skannaus (tukee sekä domainia että IP:tä)
async function performScan(host) {
    const result = { domain: host };
    try {
        // 1. HTTP-headers (vain jos HTTPS toimii)
        const headerData = await fetchHeaders(host);
        if (headerData.error) {
            // Ei hätää, yritetään SSL ja portit silti
        } else {
            result.headers = headerData.headers;
            result.technologies = identifyTechnologies(headerData.headers);
        }
        
        // 2. SSL (vain jos HTTPS toimii)
        result.ssl = await checkSSL(host);
        
        // 3. Portit (mukana SSH-banneri portissa 22)
        const ports = [80, 443, 22, 21, 25, 3306];
        const portResults = [];
        for (const port of ports) {
            const res = await checkPort(host, port, 2000);
            portResults.push(res);
        }
        result.ports = portResults;
        
        // 4. Etsitään SSH-banneri (jos portti 22 auki)
        const sshPort = portResults.find(p => p.port === 22 && p.state === 'open');
        if (sshPort && sshPort.banner) {
            result.sshBanner = sshPort.banner;
        }
        
    } catch (e) {
        result.error = e.message;
    }
    return result;
}

// ============================================
// 3. MASSASKANNAUS
// ============================================
let batchState = {
    status: 'idle',
    currentIndex: 0,
    total: TARGET_DOMAINS.length,
    currentDomain: '',
    results: [],
    lastScan: null
};

async function runBatchScan() {
    if (batchState.status === 'scanning') return;
    
    console.log('🚀 Käynnistetään massaskannaus (' + TARGET_DOMAINS.length + ' kohdetta)...');
    batchState.status = 'scanning';
    batchState.results = [];
    batchState.currentIndex = 0;

    for (let i = 0; i < TARGET_DOMAINS.length; i++) {
        const host = TARGET_DOMAINS[i];
        batchState.currentIndex = i + 1;
        batchState.currentDomain = host;
        console.log('🦡 [' + (i+1) + '/' + TARGET_DOMAINS.length + '] Skannataan: ' + host);

        const result = await performScan(host);
        batchState.results.push(result);
        await new Promise(resolve => setTimeout(resolve, 300));
    }

    batchState.status = 'idle';
    batchState.lastScan = new Date().toISOString();
    batchState.currentDomain = '';
    console.log('🏁 Massaskannaus valmis!');
}

// ============================================
// 4. RAPORTOINTI (laajennettu SSH-bannereilla)
// ============================================
function analyzeRisks(results) {
    const findings = [];
    let critical = 0, high = 0, medium = 0, low = 0, secure = 0;
    let technologies = [];
    let headersList = [];
    let sshBanners = [];

    results.forEach(r => {
        let riskLevel = 'secure';
        const issues = [];

        // SSL
        if (r.ssl && !r.ssl.valid) {
            issues.push('SSL-sertifikaatti virheellinen');
            riskLevel = 'high';
        } else if (r.ssl && r.ssl.daysRemaining < 30) {
            issues.push('SSL-sertifikaatti vanhenee ' + r.ssl.daysRemaining + ' päivän kuluttua');
            if (riskLevel === 'secure') riskLevel = 'medium';
        }

        // Avoimet portit (mukana SSH-banneri)
        if (r.ports) {
            const riskyPorts = r.ports.filter(p => p.state === 'open' && ![80, 443].includes(p.port));
            if (riskyPorts.length > 0) {
                const portInfo = riskyPorts.map(p => {
                    let info = p.port;
                    if (p.banner) {
                        info += ' (SSH: ' + p.banner + ')';
                        // Tallenna SSH-banneri erikseen
                        sshBanners.push({ domain: r.domain, banner: p.banner });
                    }
                    return info;
                });
                issues.push('Avoimet portit: ' + portInfo.join(', '));
                riskLevel = 'high';
            }
        }

        // HTTP-headers
        if (r.headers) {
            const securityHeaders = {
                'strict-transport-security': 'HSTS',
                'x-frame-options': 'X-Frame-Options',
                'x-content-type-options': 'X-Content-Type-Options',
                'content-security-policy': 'CSP'
            };
            
            Object.keys(securityHeaders).forEach(key => {
                const value = r.headers[key] || null;
                headersList.push({ name: securityHeaders[key], value: value });
                if (!value) {
                    issues.push('Puuttuva turvallisuusheader: ' + securityHeaders[key]);
                }
            });
        }

        // Teknologiat
        if (r.technologies) {
            r.technologies.forEach(t => {
                if (!technologies.includes(t)) technologies.push(t);
            });
        }

        findings.push({ domain: r.domain, riskLevel, issues });
        
        if (riskLevel === 'critical') critical++;
        else if (riskLevel === 'high') high++;
        else if (riskLevel === 'medium') medium++;
        else if (riskLevel === 'low') low++;
        else secure++;
    });

    return { 
        findings, 
        summary: { total: results.length, critical, high, medium, low, secure },
        technologies: technologies,
        headers: headersList,
        sshBanners: sshBanners
    };
}

function generateReport(results) {
    const analysis = analyzeRisks(results);
    
    const observations = [];
    const secureCount = analysis.summary.secure;
    if (secureCount === results.length) {
        observations.push('Kaikki skannatut kohteet ovat turvallisia! Hyvä työ!');
    } else if (secureCount > results.length * 0.5) {
        observations.push('Yli puolet kohteista on turvallisia. Hyvä perustaso.');
    } else {
        observations.push('Vain ' + secureCount + '/' + results.length + ' kohteesta on turvallisia. On parantamisen varaa.');
    }
    if (analysis.summary.high > 0) {
        observations.push(analysis.summary.high + ' kohteella on korkean riskin ongelmia (SSL-virheet, avoimet portit).');
    }

    // SSH-bannerit (CVE-2024-6387 -varoitus)
    if (analysis.sshBanners.length > 0) {
        analysis.sshBanners.forEach(b => {
            if (b.banner && (b.banner.includes('OpenSSH_8.') || b.banner.includes('OpenSSH_9.'))) {
                observations.push('⚠️ SSH-palvelin (CVE-2024-6387) haavoittuva: ' + b.domain + ' (' + b.banner + ')');
            }
        });
    }

    const recommendations = [];
    if (analysis.summary.high > 0) {
        recommendations.push({ priority: 'Kriittinen', text: 'Korjaa korkean riskin ongelmat: päivitä SSL-sertifikaatit ja sulje tarpeettomat portit.' });
    }
    if (analysis.summary.medium > 0) {
        recommendations.push({ priority: 'Keskitaso', text: 'Tarkista SSL-sertifikaattien vanhenemispäivämäärät.' });
    }
    // Headers-suositukset
    const missingHeaders = analysis.headers.filter(h => !h.value);
    if (missingHeaders.length > 0) {
        const names = missingHeaders.map(h => h.name).join(', ');
        recommendations.push({ priority: 'Keskitaso', text: 'Lisää puuttuvat turvallisuusheadersit: ' + names });
    }
    // SSH-suositus
    if (analysis.sshBanners.length > 0) {
        recommendations.push({ priority: 'Kriittinen', text: 'Päivitä OpenSSH versioon 9.8p1 tai uudempaan (CVE-2024-6387). Sulje SSH-portti (22) julkisesta internetistä.' });
    }
    if (recommendations.length === 0) {
        recommendations.push({ priority: 'Hyvä', text: 'Kaikki hyvin! Jatka hyvää työtä.' });
    }

    return {
        timestamp: new Date().toISOString(),
        totalScanned: results.length,
        summary: analysis.summary,
        technologies: analysis.technologies,
        headers: analysis.headers,
        sshBanners: analysis.sshBanners,
        findings: analysis.findings,
        observations: observations,
        recommendations: recommendations
    };
}

// ============================================
// 5. API-REITIT
// ============================================

app.post('/api/scan-batch', async (req, res) => {
    if (batchState.status === 'scanning') {
        return res.status(409).json({ error: 'Skannaus jo käynnissä!' });
    }
    runBatchScan().catch(console.error);
    res.json({ message: 'Massaskannaus käynnistetty! Seuraa edistymistä.' });
});

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

app.get('/api/batch-results', (req, res) => {
    if (batchState.results.length === 0) {
        return res.status(404).json({ error: 'Ei skannattuja kohteita.' });
    }
    res.json({
        results: batchState.results,
        total: batchState.results.length,
        timestamp: new Date().toISOString()
    });
});

app.get('/api/report', (req, res) => {
    if (batchState.results.length === 0) {
        return res.status(404).json({ error: 'Ei skannattuja kohteita. Suorita ensin massaskannaus.' });
    }
    const report = generateReport(batchState.results);
    res.json(report);
});

// ============================================
// 6. KÄYNNISTYS
// ============================================
app.listen(PORT, () => {
    console.log('🦡 White Weasel v' + VERSION);
    console.log('✅ Palvelin käynnissä portissa ' + PORT);
    console.log('📋 ' + TARGET_DOMAINS.length + ' kohdetta listassa');
    console.log('📝 Skannaus käynnistyy vain napista');
    console.log('📊 Raportti sisältää headerit, teknologiat ja SSH-bannerit');
    console.log('🔍 IP 185.192.15.123 on lisätty kohteisiin');
});
