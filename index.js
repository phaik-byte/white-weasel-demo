const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const whois = require('whois-json');
const fs = require('fs').promises;
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// HIBP API-avain
const HIBP_API_KEY = process.env.HIBP_API_KEY || 'testaa-ilman-avainta';

// Ota automatisointi käyttöön ympäristömuuttujalla (oletuksena päällä)
const AUTO_SCAN_ENABLED = process.env.AUTO_SCAN_ENABLED !== 'false';
const SCAN_INTERVAL = parseInt(process.env.SCAN_INTERVAL) || 60000; // 60 sekuntia oletuksena

app.use(express.static('public'));

// ============================================
// 1. KÄYTTÖLIITTYMÄ (sama kuin aiemmin)
// ============================================
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>White Weasel Recon</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
            .logo { font-size: 2em; font-weight: bold; }
            .weasel { color: #2c3e50; }
            .white { color: #ecf0f1; background: #2c3e50; padding: 2px 8px; border-radius: 5px; }
            input, button { padding: 12px; font-size: 16px; margin: 5px; }
            input { width: 60%; border: 2px solid #bdc3c7; border-radius: 5px; }
            button { background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #2980b9; }
            #result { margin-top: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            #autostatus { margin-top: 10px; padding: 10px; background: #e8f4f8; border-radius: 5px; border-left: 4px solid #3498db; }
            .loading { color: #3498db; font-style: italic; }
            .error { color: #e74c3c; font-weight: bold; }
            .success { color: #27ae60; }
            pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
            .footer { margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }
        </style>
    </head>
    <body>
        <h1><span class="white">White</span><span class="weasel">Weasel</span> 🦡</h1>
        <p>Syötä verkkotunnus (esim. <strong>suomi.fi</strong>)</p>
        <input type="text" id="domain" placeholder="esim. suomi.fi" value="suomi.fi">
        <button onclick="scan()">🔍 Skannaa</button>
        <button onclick="scanAll()">🔄 Skannaa kaikki automaattikohteet</button>
        <div id="autostatus">
            <span id="statusText">⏳ Ladataan automaattiskannauksen tilaa...</span>
        </div>
        <div id="result">
            <p class="loading">Odota skannausta...</p>
        </div>
        <div class="footer">White Weasel Recon v0.2 — Automaattinen tiedustelu</div>

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
            document.getElementById('result').innerHTML = '<p class="loading">⏳ Käynnistetään automaattinen skannaus kaikista kohteista...</p>';
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
                    statusText.innerHTML = '🟢 Joutilaana. Viimeisin skannaus: ' + (data.lastScan ? new Date(data.lastScan).toLocaleString('fi-FI') : 'Ei vielä');
                } else if (data.status === 'scanning') {
                    statusText.innerHTML = '🟡 Skannaus käynnissä... Kohde ' + data.currentIndex + '/' + data.total + ': ' + data.currentDomain;
                } else {
                    statusText.innerHTML = '⚪ Tila: ' + data.status;
                }
            } catch (e) {
                // Ei haittaa
            }
        }

        function formatResult(domain, data) {
            let html = '<h2>📊 Skannaustulokset</h2>';
            html += '<p><strong>🔍 Verkkotunnus:</strong> ' + domain + '</p>';
            if (data.whois) {
                html += '<h3>📋 WHOIS</h3><pre>' + JSON.stringify(data.whois, null, 2) + '</pre>';
            }
            if (data.dns) {
                html += '<h3>🌐 DNS-tietueet</h3><pre>' + JSON.stringify(data.dns, null, 2) + '</pre>';
            }
            if (data.hibp) {
                html += '<h3>🔐 Tietovuodot (HIBP)</h3>';
                if (data.hibp.breaches && data.hibp.breaches.length > 0) {
                    html += '<p class="error">⚠️ Löytyi ' + data.hibp.breaches.length + ' tietomurtoa!</p><ul>';
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
// 2. SKANNAUSLOGIIKKA (ydin)
// ============================================
async function performScan(domain) {
    const result = { domain, whois: null, dns: null, hibp: null };
    
    try {
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
// 3. AUTOMAATTINEN SKANNAUS (uusi ominaisuus!)
// ============================================
// Tämä on kohdelista – voit muokata tätä!
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
    'polisi.fi'
];

let scanState = {
    status: 'idle', // 'idle' | 'scanning'
    currentIndex: 0,
    total: TARGET_DOMAINS.length,
    currentDomain: '',
    lastScan: null,
    results: []
};

// Tallennetaan tulokset tiedostoon (pysyvä muisti)
const RESULTS_FILE = path.join(__dirname, 'scan_results.json');

async function loadResults() {
    try {
        const data = await fs.readFile(RESULTS_FILE, 'utf8');
        scanState.results = JSON.parse(data);
        console.log(`📂 Ladattu ${scanState.results.length} aiempaa tulosta`);
    } catch (e) {
        scanState.results = [];
        console.log('📂 Ei aiempaa dataa, aloitetaan tyhjästä');
    }
}

async function saveResults() {
    try {
        await fs.writeFile(RESULTS_FILE, JSON.stringify(scanState.results, null, 2));
        console.log(`💾 Tallennettu ${scanState.results.length} tulosta`);
    } catch (e) {
        console.error('❌ Tulosten tallennus epäonnistui:', e.message);
    }
}

async function runAutoScan() {
    if (scanState.status === 'scanning') {
        console.log('⏳ Skannaus jo käynnissä, ohitetaan');
        return;
    }

    console.log('🚀 Käynnistetään automaattinen skannaus!');
    scanState.status = 'scanning';
    scanState.results = [];

    for (let i = 0; i < TARGET_DOMAINS.length; i++) {
        const domain = TARGET_DOMAINS[i];
        scanState.currentIndex = i + 1;
        scanState.currentDomain = domain;
        console.log(`🦡 [${i+1}/${TARGET_DOMAINS.length}] Skannataan: ${domain}`);

        const result = await performScan(domain);
        scanState.results.push(result);

        // Odotetaan 2 sekuntia ennen seuraavaa, ettei kuormiteta liikaa
        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    scanState.status = 'idle';
    scanState.lastScan = new Date().toISOString();
    scanState.currentDomain = '';
    await saveResults();
    console.log('🏁 Automaattinen skannaus valmis!');
}

// ============================================
// 4. API-REITIT
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

// Käynnistä automaattinen skannaus
app.post('/api/scan-all', async (req, res) => {
    if (scanState.status === 'scanning') {
        return res.status(409).json({ message: 'Skannaus on jo käynnissä!' });
    }
    // Käynnistä skannaus taustalla (älä odota valmistumista)
    runAutoScan().catch(console.error);
    res.json({ message: 'Skannaus käynnistetty! Seuraa tilaa /api/status' });
});

// Hae skannauksen tila
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

// Hae kaikki tallennetut tulokset
app.get('/api/results', (req, res) => {
    res.json(scanState.results);
});

// ============================================
// 5. KÄYNNISTYS
// ============================================
app.listen(PORT, async () => {
    console.log(`🦡 White Weasel Recon v0.2 käynnissä portissa ${PORT}`);
    console.log(`📋 Kohdelistassa ${TARGET_DOMAINS.length} verkkotunnusta`);
    
    // Ladataan aiemmat tulokset
    await loadResults();

    // Automaattinen skannaus käynnistetään, jos AUTO_SCAN_ENABLED != 'false'
    if (AUTO_SCAN_ENABLED !== 'false') {
        console.log('⏳ Ensimmäinen automaattinen skannaus käynnistyy 10 sekunnin kuluttua...');
        setTimeout(() => {
            runAutoScan().catch(console.error);
        }, 10000);

        // Ajoitetaan skannaus säännöllisesti
        setInterval(() => {
            runAutoScan().catch(console.error);
        }, SCAN_INTERVAL);
        console.log(`⏰ Automaattinen skannaus ajastettu ${SCAN_INTERVAL/1000} sekunnin välein`);
    } else {
        console.log('⏸️ Automaattinen skannaus pois päältä (AUTO_SCAN_ENABLED=false)');
    }
});
