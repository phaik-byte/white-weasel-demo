const express = require('express');
const axios = require('axios');
const https = require('https');
const net = require('net');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// KOHDELISTA (kovakoodattu)
// ============================================
const TARGET_DOMAINS = [
    // Ravintolat ja kahvilat
    'ravintola.fi',
    'kahvila.fi',
    'ravintolakoti.fi',
    'lounasravintola.fi',
    'konditoria.fi',
    'leipomo.fi',
    'pizzeria.fi',
    'grilli.fi',
    
    // Kauneus ja hyvinvointi
    'parturi.fi',
    'kampaamo.fi',
    'hieroja.fi',
    'fysioterapia.fi',
    'kosmetologi.fi',
    'kuntosali.fi',
    
    // Rakentaminen ja remontti
    'rakennus.fi',
    'remontti.fi',
    'maalarit.fi',
    'lvi.fi',
    'sahkotyo.fi',
    'lattianhoito.fi',
    
    // Kiinteistöt ja asuminen
    'kiinteisto.fi',
    'asunto.fi',
    'vuokraus.fi',
    'sisustus.fi',
    
    // Kuljetus ja logistiikka
    'kuljetus.fi',
    'logistiikka.fi',
    'muutto.fi',
    'taksi.fi',
    
    // Tietotekniikka ja digi
    'it-palvelut.fi',
    'verkkosivut.fi',
    'digimarkkinointi.fi',
    'ohjelmointi.fi',
    'tietoturva.fi',
    
    // Koulutus ja konsultointi
    'koulutus.fi',
    'konsultointi.fi',
    'valmennus.fi',
    'kielikoulu.fi',
    
    // Terveys ja hyvinvointi
    'optikko.fi',
    'apteekki.fi',
    'ravitsemus.fi',
    
    // Kauppa ja verkkokauppa
    'verkkokauppa.fi',
    'puutarha.fi',
    'kukkakauppa.fi',
    
    // Auto ja liikenne
    'autokorjaamo.fi',
    'renkaat.fi',
    'varaosat.fi'
];

console.log('📋 ' + TARGET_DOMAINS.length + ' kohdetta listassa');

// ============================================
// 1. KÄYTTÖLIITTYMÄ
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
            .domain-item { padding: 5px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
            .domain-item.done { color: #27ae60; }
            .domain-item.error { color: #e74c3c; }
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
            .hidden { display: none; }
            .status-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
            .badge-open { background: #e74c3c; color: white; }
            .badge-closed { background: #27ae60; color: white; }
            .badge-filtered { background: #f39c12; color: white; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        
        <div>
            <button onclick="scanBatch()" class="danger">🔄 Skannaa ${targetCount} kohdetta</button>
            <button onclick="showReport()" class="primary" id="reportBtn" disabled>📊 Näytä raportti</button>
            <button onclick="downloadReport()" class="success" id="downloadBtn" disabled>📥 Lataa raportti (JSON)</button>
        </div>
        
        <div id="status">
            <span id="statusText">⏳ Valmis...</span>
        </div>
        
        <div id="result">
            <p>Valmis skannaamaan ${targetCount} kohdetta. Paina "Skannaa"-nappia aloittaaksesi.</p>
        </div>

        <script>
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
                    // Hae tulokset
                    const res = await fetch('/api/batch-results');
                    const resultsData = await res.json();
                    if (resultsData.results && resultsData.results.length > 0) {
                        results = resultsData.results;
                        document.getElementById('reportBtn').disabled = false;
                        document.getElementById('downloadBtn').disabled = false;
                        // Näytä perustulokset
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
            
            // Yhteenveto
            const validSSL = results.filter(r => r.ssl && r.ssl.valid).length;
            const openPorts = results.filter(r => r.ports && r.ports.some(p => p.state === 'open')).length;
            
            html += '<div class="report-grid">';
            html += '<div class="report-card"><div class="report-number">' + results.length + '</div><div class="report-label">Skannatut kohteet</div></div>';
            html += '<div class="report-card risk-secure"><div class="report-number">' + validSSL + '</div><div class="report-label">SSL voimassa</div></div>';
            html += '<div class="report-card risk-high"><div class="report-number">' + openPorts + '</div><div class="report-label">Avoimia portteja</div></div>';
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

            // Yhteenveto
            html += '<h3>📈 Yhteenveto</h3>';
            html += '<div class="report-grid">';
            html += '<div class="report-card"><div class="report-number">' + data.summary.total + '</div><div class="report-label">Skannatut kohteet</div></div>';
            html += '<div class="report-card risk-critical"><div class="report-number">' + data.summary.critical + '</div><div class="report-label">Kriittiset riskit</div></div>';
            html += '<div class="report-card risk-high"><div class="report-number">' + data.summary.high + '</div><div class="report-label">Korkeat riskit</div></div>';
            html += '<div class="report-card risk-medium"><div class="report-number">' + data.summary.medium + '</div><div class="report-label">Keskitasoiset riskit</div></div>';
            html += '<div class="report-card risk-low"><div class="report-number">' + data.summary.low + '</div><div class="report-label">Matalat riskit</div></div>';
            html += '<div class="report-card risk-secure"><div class="report-number">' + data.summary.secure + '</div><div class="report-label">Turvalliset</div></div>';
            html += '</div>';

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
            document.getElementById('result').innerHTML = '<p>Valmis skannaamaan ${targetCount} kohdetta. Paina "Skannaa"-nappia aloittaaksesi.</p>';
        };
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. SKANNAUSFUNKTIOT
// ============================================

async function checkPort(host, port, timeout = 3000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(timeout);
        socket.on('connect', () => { socket.destroy(); resolve({ port, state: 'open' }); });
        socket.on('timeout', () => { socket.destroy(); resolve({ port, state: 'filtered' }); });
        socket.on('error', () => { socket.destroy(); resolve({ port, state: 'closed' }); });
        socket.connect(port, host);
    });
}

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

async function performScan(domain) {
    const result = { domain };
    try {
        result.ssl = await checkSSL(domain);
        
        const ports = [80, 443, 22, 21, 25, 3306];
        const portResults = [];
        for (const port of ports) {
            const res = await checkPort(domain, port, 2000);
            portResults.push(res);
        }
        result.ports = portResults;
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
        const domain = TARGET_DOMAINS[i];
        batchState.currentIndex = i + 1;
        batchState.currentDomain = domain;
        console.log('🦡 [' + (i+1) + '/' + TARGET_DOMAINS.length + '] Skannataan: ' + domain);

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
// 4. RAPORTOINTI
// ============================================
function analyzeRisks(results) {
    const findings = [];
    let critical = 0, high = 0, medium = 0, low = 0, secure = 0;

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

        // Avoimet portit (muut kuin 80, 443)
        if (r.ports) {
            const riskyPorts = r.ports.filter(p => p.state === 'open' && ![80, 443].includes(p.port));
            if (riskyPorts.length > 0) {
                issues.push('Avoimet portit: ' + riskyPorts.map(p => p.port).join(', '));
                riskLevel = 'high';
            }
        }

        findings.push({ domain: r.domain, riskLevel, issues });
        
        if (riskLevel === 'critical') critical++;
        else if (riskLevel === 'high') high++;
        else if (riskLevel === 'medium') medium++;
        else if (riskLevel === 'low') low++;
        else secure++;
    });

    return { findings, summary: { total: results.length, critical, high, medium, low, secure } };
}

function generateReport(results) {
    const analysis = analyzeRisks(results);
    
    // Huomioitavaa
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

    // Suositukset
    const recommendations = [];
    if (analysis.summary.high > 0) {
        recommendations.push({ priority: 'Kriittinen', text: 'Korjaa korkean riskin ongelmat: päivitä SSL-sertifikaatit ja sulje tarpeettomat portit.' });
    }
    if (analysis.summary.medium > 0) {
        recommendations.push({ priority: 'Keskitaso', text: 'Tarkista SSL-sertifikaattien vanhenemispäivämäärät ja varmista, että ne uusitaan ajoissa.' });
    }
    if (recommendations.length === 0) {
        recommendations.push({ priority: 'Hyvä', text: 'Kaikki hyvin! Jatka hyvää työtä.' });
    }

    return {
        timestamp: new Date().toISOString(),
        totalScanned: results.length,
        summary: analysis.summary,
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
    console.log('🦡 White Weasel Recon v3.2 — Raportoinnilla');
    console.log('✅ Palvelin käynnissä portissa ' + PORT);
    console.log('📋 ' + TARGET_DOMAINS.length + ' kohdetta listassa');
    console.log('📝 Skannaus käynnistyy vain napista');
});
