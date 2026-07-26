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
    'suomi.fi', 'valtioneuvosto.fi', 'eduskunta.fi',
    'helsinki.fi', 'tampere.fi', 'turku.fi',
    'oulu.fi', 'jyvaskyla.fi', 'lahti.fi',
    'kuopio.fi', 'pori.fi', 'lappeenranta.fi'
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
            body { font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            h1 { color: #2c3e50; }
            button { padding: 12px 24px; font-size: 16px; margin: 5px; cursor: pointer; background: #3498db; color: white; border: none; border-radius: 5px; }
            button:hover { background: #2980b9; }
            button.danger { background: #e74c3c; }
            button.danger:hover { background: #c0392b; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            #status { margin-top: 10px; padding: 10px; background: #e8f4f8; border-radius: 5px; }
            .loading { color: #3498db; }
            .error { color: #e74c3c; }
            .success { color: #27ae60; }
            .domain-item { padding: 5px; border-bottom: 1px solid #eee; }
        </style>
    </head>
    <body>
        <h1>🦡 White Weasel Recon</h1>
        <button onclick="scanBatch()" class="danger">🔄 Skannaa ${targetCount} kohdetta</button>
        <div id="status"><span id="statusText">⏳ Valmis...</span></div>
        <div id="result"><p>Valmis skannaamaan ${targetCount} kohdetta.</p></div>

        <script>
        let isRunning = false;

        async function scanBatch() {
            if (isRunning) { alert('Skannaus on jo käynnissä!'); return; }
            if (!confirm('Skannataan ${targetCount} kohdetta. Tämä voi kestää 5-10 minuuttia. Jatketaanko?')) return;
            
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään massaskannaus...</p>';
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
                    const results = await res.json();
                    if (results.results && results.results.length > 0) {
                        let html = '<h2>📊 Tulokset</h2>';
                        results.results.forEach((r, i) => {
                            const status = r.error ? '❌' : (r.ssl && r.ssl.valid ? '✅' : '⚠️');
                            html += '<div class="domain-item">' + (i+1) + '. ' + status + ' ' + r.domain;
                            if (r.error) html += ' <span class="error">' + r.error + '</span>';
                            if (r.ssl && r.ssl.valid) html += ' (SSL: ' + r.ssl.daysRemaining + ' päivää)';
                            html += '</div>';
                        });
                        document.getElementById('result').innerHTML = html;
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
        </script>
    </body>
    </html>
    `);
});

// ============================================
// 2. SKANNAUSFUNKTIOT
// ============================================

// Tarkistetaan portti
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

// Yksi skannaus
async function performScan(domain) {
    const result = { domain };
    try {
        // SSL
        result.ssl = await checkSSL(domain);
        
        // Portit (vain tärkeimmät)
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
// 4. API-REITIT
// ============================================

// Käynnistä massaskannaus
app.post('/api/scan-batch', async (req, res) => {
    if (batchState.status === 'scanning') {
        return res.status(409).json({ error: 'Skannaus jo käynnissä!' });
    }
    // Käynnistä skannaus taustalla
    runBatchScan().catch(console.error);
    res.json({ message: 'Massaskannaus käynnistetty! Seuraa edistymistä.' });
});

// Skannauksen tila
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

// Skannauksen tulokset
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

// ============================================
// 5. KÄYNNISTYS
// ============================================
app.listen(PORT, () => {
    console.log('🦡 White Weasel Recon v3.1');
    console.log('✅ Palvelin käynnissä portissa ' + PORT);
    console.log('📋 ' + TARGET_DOMAINS.length + ' kohdetta listassa');
    console.log('📝 Skannaus käynnistyy vain napista');
});
