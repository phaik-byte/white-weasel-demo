const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const whois = require('whois-json');
const app = express();
const PORT = process.env.PORT || 3000;

// HIBP API-avain (laitetaan ympäristömuuttujaan myöhemmin)
const HIBP_API_KEY = process.env.HIBP_API_KEY || 'testaa-ilman-avainta';

app.use(express.static('public'));

// Pääreitti - näyttää HTML-sivun
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
        <div id="result">
            <p class="loading">Odota skannausta...</p>
        </div>
        <div class="footer">White Weasel Recon v0.1 — Eettinen tiedustelu</div>

        <script>
        async function scan() {
            const domain = document.getElementById('domain').value.trim();
            if (!domain) {
                document.getElementById('result').innerHTML = '<p class="error">Syötä verkkotunnus!</p>';
                return;
            }

            document.getElementById('result').innerHTML = '<p class="loading">⏳ Skannataan verkkotunnusta <strong>' + domain + '</strong>...</p>';

            try {
                const response = await fetch('/api/scan?domain=' + encodeURIComponent(domain));
                const data = await response.json();

                if (!response.ok) {
                    document.getElementById('result').innerHTML = '<p class="error">❌ Virhe: ' + (data.error || 'Tuntematon ongelma') + '</p>';
                    return;
                }

                let html = '<h2>📊 Skannaustulokset</h2>';
                html += '<p><strong>🔍 Verkkotunnus:</strong> ' + domain + '</p>';

                // WHOIS
                if (data.whois) {
                    html += '<h3>📋 WHOIS</h3>';
                    html += '<pre>' + JSON.stringify(data.whois, null, 2) + '</pre>';
                } else {
                    html += '<p><em>WHOIS-tietoja ei löytynyt</em></p>';
                }

                // DNS
                if (data.dns) {
                    html += '<h3>🌐 DNS-tietueet</h3>';
                    html += '<pre>' + JSON.stringify(data.dns, null, 2) + '</pre>';
                }

                // HIBP
                if (data.hibp) {
                    html += '<h3>🔐 Tietovuodot (Have I Been Pwned)</h3>';
                    if (data.hibp.breaches && data.hibp.breaches.length > 0) {
                        html += '<p class="error">⚠️ Löytyi ' + data.hibp.breaches.length + ' tietomurtoa!</p>';
                        html += '<ul>';
                        data.hibp.breaches.forEach(b => {
                            html += '<li><strong>' + b.Name + '</strong> (' + b.BreachDate + ') – ' + b.Description.substring(0, 100) + '...</li>';
                        });
                        html += '</ul>';
                    } else {
                        html += '<p class="success">✅ Ei löytynyt tietomurtoja tästä domainista.</p>';
                    }
                }

                html += '<p><small>Skannausajankohta: ' + new Date().toLocaleString('fi-FI') + '</small></p>';
                document.getElementById('result').innerHTML = html;

            } catch (error) {
                document.getElementById('result').innerHTML = '<p class="error">❌ Yhteysvirhe: ' + error.message + '</p>';
            }
        }

        // Automaattinen skannaus kun sivu latautuu
        window.onload = function() {
            scan();
        };
        </script>
    </body>
    </html>
    `);
});

// API-reitti, joka tekee varsinaisen skannauksen
app.get('/api/scan', async (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain puuttuu' });
    }

    try {
        const result = {
            domain: domain,
            whois: null,
            dns: null,
            hibp: null
        };

        // 1. WHOIS (käyttää whois-json-kirjastoa)
        try {
            const whoisData = await whois(domain);
            result.whois = whoisData;
        } catch (e) {
            result.whois = { error: 'WHOIS-haku epäonnistui: ' + e.message };
        }

        // 2. DNS-tietueet
        try {
            const dnsRecords = {
                A: await dns.resolve4(domain).catch(() => []),
                MX: await dns.resolveMx(domain).catch(() => []),
                NS: await dns.resolveNs(domain).catch(() => []),
                TXT: await dns.resolveTxt(domain).catch(() => [])
            };
            result.dns = dnsRecords;
        } catch (e) {
            result.dns = { error: 'DNS-haku epäonnistui: ' + e.message };
        }

        // 3. HIBP (Have I Been Pwned) – Vain jos API-avain on asetettu
        if (HIBP_API_KEY && HIBP_API_KEY !== 'testaa-ilman-avainta') {
            try {
                const hibpResponse = await axios.get(
                    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(domain)}?truncateResponse=false`,
                    {
                        headers: {
                            'hibp-api-key': HIBP_API_KEY,
                            'User-Agent': 'WhiteWeaselRecon/1.0 (https://whiteweasel.fi)'
                        }
                    }
                );
                result.hibp = {
                    breaches: hibpResponse.data || [],
                    status: 'ok'
                };
            } catch (e) {
                if (e.response && e.response.status === 404) {
                    // 404 tarkoittaa, että ei löytynyt tietomurtoja – ei virhe
                    result.hibp = { breaches: [], status: 'ok' };
                } else {
                    result.hibp = { 
                        error: 'HIBP-kutsu epäonnistui: ' + (e.response?.data?.message || e.message),
                        status: 'error'
                    };
                }
            }
        } else {
            result.hibp = { 
                message: 'HIBP ei käytössä (aseta HIBP_API_KEY ympäristömuuttujana)',
                status: 'disabled'
            };
        }

        res.json(result);

    } catch (error) {
        res.status(500).json({ error: 'Skannaus epäonnistui: ' + error.message });
    }
});

app.listen(PORT, () => {
    console.log('🦡 White Weasel Recon käynnissä portissa ' + PORT);
});
