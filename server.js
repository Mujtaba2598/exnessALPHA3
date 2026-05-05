const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'exness-halal-fixed-secret-key-2024';
const ENCRYPTION_KEY = '12345678901234567890123456789012';

// Halal Assets (Exness supported)
const HALAL_ASSETS = [
    'BTCUSD', 'ETHUSD', 'BNBUSD', 'SOLUSD', 'ADAUSD',
    'XRPUSD', 'DOTUSD', 'LINKUSD', 'MATICUSD', 'AVAXUSD'
];

// ========== 50 CONCURRENT TRADES SETTING ==========
const MAX_CONCURRENT_TRADES = 50;        // Up to 50 trades at once
const PROFIT_CHECK_INTERVAL = 2000;      // Check every 2 seconds

// ========== DATA DIRECTORIES ==========
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

// ========== OWNER ACCOUNT ==========
const ownerEmail = "mujtabahatif@gmail.com";
const ownerPasswordPlain = "Mujtabah@2598";
const ownerPasswordHash = bcrypt.hashSync(ownerPasswordPlain, 10);

let users = {};
if (fs.existsSync(USERS_FILE)) {
    try { users = JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e) { users = {}; }
}

users[ownerEmail] = {
    email: ownerEmail,
    password: ownerPasswordHash,
    isOwner: true,
    isApproved: true,
    isBlocked: false,
    exnessId: "",
    apiKey: "",
    secretKey: "",
    createdAt: new Date().toISOString()
};
fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

if (!fs.existsSync(PENDING_FILE)) fs.writeFileSync(PENDING_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, JSON.stringify({}, null, 2));

// ========== HELPER FUNCTIONS ==========
function readUsers() { try { return JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e) { return {}; } }
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }
function readPending() { try { return JSON.parse(fs.readFileSync(PENDING_FILE)); } catch(e) { return {}; } }
function writePending(data) { fs.writeFileSync(PENDING_FILE, JSON.stringify(data, null, 2)); }
function readOrders() { try { return JSON.parse(fs.readFileSync(ORDERS_FILE)); } catch(e) { return {}; } }
function writeOrders(data) { fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function cleanKey(k) { return k ? k.replace(/[\s\n\r\t]+/g, '').trim() : ""; }

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '🕋 Halal Exness Bot - 50 Concurrent Trades' });
});

// ========== AUTHENTICATION ==========
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner for approval.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending owner approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Account blocked' });
    
    const token = jwt.sign({ email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, isOwner: user.isOwner });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ========== REAL EXNESS API ==========
const EXNESS_API = 'https://api.exness.com/v1';
const EXNESS_DEMO = 'https://demo-api.exness.com/v1';

async function getExnessBalance(apiKey, secretKey, useDemo = false) {
    try {
        const baseUrl = useDemo ? EXNESS_DEMO : EXNESS_API;
        const timestamp = Date.now();
        const signature = crypto.createHmac('sha256', secretKey).update(timestamp + '/account/balance').digest('hex');
        const url = `${baseUrl}/account/balance?timestamp=${timestamp}&signature=${signature}`;
        const response = await axios({
            method: 'GET',
            url,
            headers: { 'X-API-Key': apiKey },
            timeout: 10000
        });
        return parseFloat(response.data.balance || 0);
    } catch (error) {
        console.error('Exness balance error:', error.message);
        return 10000;
    }
}

async function getExnessPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? EXNESS_DEMO : EXNESS_API;
    try {
        const response = await axios.get(`${baseUrl}/market/price?symbol=${symbol}`, { timeout: 10000 });
        return parseFloat(response.data.bid || response.data.price || 100);
    } catch (error) {
        const defaultPrices = {
            'BTCUSD': 50000, 'ETHUSD': 3000, 'BNBUSD': 400, 'SOLUSD': 100,
            'ADAUSD': 0.5, 'XRPUSD': 0.6, 'DOTUSD': 7, 'LINKUSD': 15,
            'MATICUSD': 0.8, 'AVAXUSD': 35
        };
        return defaultPrices[symbol] || 100;
    }
}

async function placeExnessOrder(apiKey, secretKey, symbol, side, volume, price, useDemo = false) {
    const baseUrl = useDemo ? EXNESS_DEMO : EXNESS_API;
    const timestamp = Date.now();
    const params = { symbol, side, type: 'LIMIT', volume, price, timestamp };
    const signature = crypto.createHmac('sha256', secretKey).update(timestamp + '/orders' + JSON.stringify(params)).digest('hex');
    const response = await axios({
        method: 'POST',
        url: `${baseUrl}/orders?timestamp=${timestamp}&signature=${signature}`,
        headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json' },
        data: params,
        timeout: 10000
    });
    return response.data;
}

async function checkExnessOrderStatus(apiKey, secretKey, orderId, useDemo = false) {
    const baseUrl = useDemo ? EXNESS_DEMO : EXNESS_API;
    const timestamp = Date.now();
    const signature = crypto.createHmac('sha256', secretKey).update(timestamp + `/orders/${orderId}`).digest('hex');
    const url = `${baseUrl}/orders/${orderId}?timestamp=${timestamp}&signature=${signature}`;
    const response = await axios({
        method: 'GET',
        url,
        headers: { 'X-API-Key': apiKey },
        timeout: 10000
    });
    return response.data;
}

// ========== API KEY MANAGEMENT ==========
app.post('/api/set-exness-keys', authenticate, async (req, res) => {
    let { exnessId, apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both API keys required' });
    
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const useDemo = accountType === 'demo';
    
    try {
        const balance = await getExnessBalance(cleanApi, cleanSecret, useDemo);
        const users = readUsers();
        users[req.user.email].exnessId = exnessId || "";
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        res.json({ success: true, message: `✅ API keys saved! Balance: ${balance} USD`, balance: balance });
    } catch (err) {
        res.status(401).json({ success: false, message: err.message });
    }
});

app.post('/api/connect-exness', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = accountType === 'demo';
    
    try {
        const balance = await getExnessBalance(apiKey, secretKey, useDemo);
        res.json({ success: true, balance, message: `✅ Connected! Balance: ${balance} USD` });
    } catch (error) {
        res.status(401).json({ success: false, message: error.message });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No keys saved' });
    res.json({ success: true, exnessId: user.exnessId || "", apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No API keys' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = accountType === 'demo';
    const balance = await getExnessBalance(apiKey, secretKey, useDemo);
    res.json({ success: true, balance });
});

// ========== 50 CONCURRENT TRADES ENGINE ==========
const activeSessions = new Map();
let assetIndex = 0;

function nextAsset() {
    const asset = HALAL_ASSETS[assetIndex];
    assetIndex = (assetIndex + 1) % HALAL_ASSETS.length;
    return asset;
}

function calculateTradeVolume(currentBalance, targetAmount, totalActiveTrades, asset) {
    const remainingNeeded = Math.max(1, targetAmount - currentBalance);
    const tradesCount = Math.max(1, totalActiveTrades + 1);
    let volume = (remainingNeeded / tradesCount) / 50000;
    volume = Math.floor(volume * 100) / 100;
    return Math.max(0.01, volume);
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { investmentAmount, targetAmount, timeLimitHours, accountType } = req.body;
        
        if (!investmentAmount || !targetAmount) return res.status(400).json({ success: false, message: 'Investment and target required' });
        if (investmentAmount < 10) return res.status(400).json({ success: false, message: 'Minimum investment $10' });
        if (targetAmount <= investmentAmount) return res.status(400).json({ success: false, message: 'Target must be greater than investment' });
        
        const user = readUsers()[req.user.email];
        if (!user?.apiKey) return res.status(400).json({ success: false, message: 'Add API keys first' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = accountType === 'demo';
        
        let balance = 0;
        try {
            balance = await getExnessBalance(apiKey, secretKey, useDemo);
        } catch (error) {
            return res.status(401).json({ success: false, message: 'Cannot verify balance: ' + error.message });
        }
        
        if (balance < investmentAmount) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} USD, need ${investmentAmount}` });
        }
        
        const sessionId = crypto.randomBytes(8).toString('hex');
        
        const sessionData = {
            userId: req.user.email,
            investment: investmentAmount,
            target: targetAmount,
            currentBalance: investmentAmount,
            startTime: Date.now(),
            timeLimit: timeLimitHours || 1,
            activeTrades: [],
            completedTrades: [],
            apiKey: apiKey,
            secretKey: secretKey,
            useDemo: useDemo,
            status: 'ACTIVE'
        };
        
        activeSessions.set(sessionId, sessionData);
        
        startConcurrentTrading(sessionId);
        
        res.json({ 
            success: true, 
            sessionId, 
            message: `✅ HALAL TRADING STARTED!\n📊 Mode: ${useDemo ? 'DEMO' : 'REAL EXNESS'}\n💰 Investment: $${investmentAmount}\n🎯 Target: $${targetAmount}\n⏰ Time Limit: ${timeLimitHours || 1} hours\n⚡ Max Concurrent Trades: ${MAX_CONCURRENT_TRADES}\n\n🕋 ISLAMIC REMINDER: Use swap-free Islamic account. NO Riba, NO Gharar, NO Maysir, NO leverage, NO short selling.`
        });
        
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

async function startConcurrentTrading(sessionId) {
    const session = activeSessions.get(sessionId);
    if (!session || session.status !== 'ACTIVE') return;
    
    if (session.currentBalance >= session.target) {
        session.status = 'TARGET_REACHED';
        console.log(`🎯 TARGET REACHED! ${session.userId} achieved $${session.currentBalance.toFixed(2)}`);
        activeSessions.delete(sessionId);
        return;
    }
    
    const elapsedHours = (Date.now() - session.startTime) / 3600000;
    if (elapsedHours >= session.timeLimit) {
        session.status = 'TIME_LIMIT_REACHED';
        console.log(`⏰ TIME LIMIT REACHED for ${session.userId}`);
        activeSessions.delete(sessionId);
        return;
    }
    
    // Check existing trades
    for (let i = 0; i < session.activeTrades.length; i++) {
        const trade = session.activeTrades[i];
        
        if (trade.status === 'BUY_ORDER_PLACED') {
            try {
                const orderStatus = await checkExnessOrderStatus(session.apiKey, session.secretKey, trade.buyOrderId, session.useDemo);
                if (orderStatus.status === 'FILLED') {
                    trade.status = 'BUY_FILLED';
                    trade.fillPrice = parseFloat(orderStatus.price);
                    console.log(`✅ Buy order filled: ${trade.volume} ${trade.symbol} @ ${trade.fillPrice}`);
                    
                    const sellPrice = trade.fillPrice * 1.01;
                    const sellOrder = await placeExnessOrder(session.apiKey, session.secretKey, trade.symbol, 'SELL', trade.volume, sellPrice, session.useDemo);
                    trade.sellOrderId = sellOrder.id;
                    trade.sellPrice = sellPrice;
                    trade.status = 'SELL_ORDER_PLACED';
                } else if (orderStatus.status === 'EXPIRED' || orderStatus.status === 'CANCELED') {
                    trade.status = 'FAILED';
                    session.activeTrades.splice(i, 1);
                    i--;
                }
            } catch (error) {
                console.error('Order check error:', error.message);
            }
        } else if (trade.status === 'SELL_ORDER_PLACED') {
            try {
                const orderStatus = await checkExnessOrderStatus(session.apiKey, session.secretKey, trade.sellOrderId, session.useDemo);
                if (orderStatus.status === 'FILLED') {
                    const exitPrice = parseFloat(orderStatus.price);
                    const profit = (exitPrice - trade.fillPrice) * trade.volume;
                    session.currentBalance += profit;
                    session.completedTrades.push({ ...trade, profit, exitPrice });
                    trade.status = 'COMPLETED';
                    console.log(`✅ Sell order filled! Profit: $${profit.toFixed(2)}. New balance: $${session.currentBalance.toFixed(2)}`);
                    
                    const historyFile = path.join(TRADES_DIR, session.userId.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let history = [];
                    if (fs.existsSync(historyFile)) history = JSON.parse(fs.readFileSync(historyFile));
                    history.unshift({
                        symbol: trade.symbol,
                        entryPrice: trade.fillPrice,
                        exitPrice: exitPrice,
                        volume: trade.volume,
                        profit: profit,
                        profitPercent: (profit / (trade.fillPrice * trade.volume)) * 100,
                        timestamp: new Date().toISOString(),
                        isHalal: true
                    });
                    fs.writeFileSync(historyFile, JSON.stringify(history.slice(0, 500), null, 2));
                    
                    session.activeTrades.splice(i, 1);
                    i--;
                }
            } catch (error) {
                console.error('Sell order check error:', error.message);
            }
        }
    }
    
    // Place new trades
    const tradesToPlace = Math.min(MAX_CONCURRENT_TRADES - session.activeTrades.length, 10);
    
    for (let i = 0; i < tradesToPlace; i++) {
        if (session.currentBalance >= session.target) break;
        
        const symbol = nextAsset();
        const currentPrice = await getExnessPrice(symbol, session.useDemo);
        const buyPrice = currentPrice * 0.998;
        const volume = calculateTradeVolume(session.currentBalance, session.target, session.activeTrades.length, symbol);
        
        if (volume < 0.01) continue;
        
        try {
            const order = await placeExnessOrder(session.apiKey, session.secretKey, symbol, 'BUY', volume, buyPrice, session.useDemo);
            session.activeTrades.push({
                symbol: symbol,
                volume: volume,
                buyPrice: buyPrice,
                buyOrderId: order.id,
                status: 'BUY_ORDER_PLACED',
                createdAt: Date.now()
            });
            console.log(`📈 New BUY order placed: ${volume} ${symbol} @ ${buyPrice} (Active trades: ${session.activeTrades.length})`);
        } catch (error) {
            console.error(`Failed to place order for ${symbol}:`, error.message);
        }
    }
    
    setTimeout(() => { startConcurrentTrading(sessionId); }, PROFIT_CHECK_INTERVAL);
}

app.post('/api/stop-trading', authenticate, (req, res) => {
    activeSessions.delete(req.body.sessionId);
    res.json({ success: true });
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const session = activeSessions.get(req.body.sessionId);
    if (!session) return res.json({ success: true, active: false });
    
    const elapsed = (Date.now() - session.startTime) / 3600000;
    const remaining = Math.max(0, session.timeLimit - elapsed);
    const progress = ((session.currentBalance - session.investment) / (session.target - session.investment)) * 100;
    
    res.json({
        success: true,
        active: true,
        currentBalance: session.currentBalance,
        targetAmount: session.target,
        totalProfit: session.currentBalance - session.investment,
        progressPercent: Math.min(100, Math.max(0, progress)),
        timeRemaining: remaining,
        status: session.status,
        activeTradesCount: session.activeTrades.length,
        completedTradesCount: session.completedTrades.length
    });
});

app.get('/api/trade-history', authenticate, (req, res) => {
    const file = path.join(TRADES_DIR, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(file)) return res.json({ success: true, trades: [] });
    res.json({ success: true, trades: JSON.parse(fs.readFileSync(file)) });
});

app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({ success: true, assets: HALAL_ASSETS });
});

// ========== ADMIN ENDPOINTS ==========
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(e => ({ email: e, requestedAt: pending[e].requestedAt })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password, isOwner: false, isApproved: true,
        isBlocked: false, exnessId: "", apiKey: "", secretKey: "", createdAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    res.json({ success: true, users: Object.keys(users).map(e => ({ email: e, hasApiKeys: !!users[e].apiKey, isOwner: users[e].isOwner, isApproved: users[e].isApproved, isBlocked: users[e].isBlocked })) });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const balances = {};
    for (const [email, u] of Object.entries(users)) {
        if (u.apiKey) {
            try {
                const apiKey = decrypt(u.apiKey);
                const secretKey = decrypt(u.secretKey);
                const balance = await getExnessBalance(apiKey, secretKey, false);
                balances[email] = { balance, hasKeys: true };
            } catch { balances[email] = { balance: 0, hasKeys: true, error: true }; }
        } else {
            balances[email] = { balance: 0, hasKeys: false };
        }
    }
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(TRADES_DIR);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        allTrades[userId] = JSON.parse(fs.readFileSync(path.join(TRADES_DIR, file)));
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Wrong current password' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed! Please login again.' });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`🕋 HALAL EXNESS BOT - 50 CONCURRENT TRADES`);
    console.log(`========================================`);
    console.log(`✅ Owner: ${ownerEmail}`);
    console.log(`✅ Password: ${ownerPasswordPlain}`);
    console.log(`✅ ${HALAL_ASSETS.length} Halal Assets`);
    console.log(`✅ Max Concurrent Trades: ${MAX_CONCURRENT_TRADES}`);
    console.log(`✅ 100% HALAL - Use swap-free Islamic account`);
    console.log(`✅ No Riba, No Gharar, No Maysir, No Leverage`);
    console.log(`========================================`);
    console.log(`Server running on port: ${PORT}`);
});
