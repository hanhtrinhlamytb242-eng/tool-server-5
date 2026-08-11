const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));

// ============================================================
// CẤU HÌNH
// ============================================================
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_KEY = 'ADMIN_2026_Ka1t0_S3cr3t_X9zW8yV7uT6rQ5pO4nM3';

// ============================================================
// HÀM XỬ LÝ DỮ LIỆU
// ============================================================
function initData() {
    if (!fs.existsSync(DATA_FILE)) {
        const defaultData = { keys: {}, logs: {}, sessions: {} };
        fs.writeFileSync(DATA_FILE, JSON.stringify(defaultData, null, 2));
    }
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function saveData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ===== MIDDLEWARE =====
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, x-admin-key, x-api-key');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    req.clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${req.clientIp}`);
    next();
});

// ===== XÁC THỰC ADMIN =====
function verifyAdmin(req, res, next) {
    const adminKey = req.body.adminKey || req.query.adminKey || req.headers['x-admin-key'];
    if (adminKey !== ADMIN_KEY) {
        return res.status(403).json({ success: false, message: '🔒 Không có quyền!' });
    }
    next();
}

// ============================================================
// API CÔNG KHAI
// ============================================================
app.get('/', (req, res) => {
    res.json({ name: 'Tool Management Server', version: '4.0.0', status: 'running' });
});

app.get('/api/health', (req, res) => {
    const data = initData();
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        totalKeys: Object.keys(data.keys).length,
        activeKeys: Object.values(data.keys).filter(k => k.active).length,
        totalSessions: Object.keys(data.sessions).length,
        totalLogs: data.logs.length
    });
});

// ============================================================
// API XÁC THỰC KEY (CHO TOOL VỎ BỌC)
// ============================================================
app.post('/verify-key', (req, res) => {
    const { key, hwid } = req.body;
    const data = initData();
    const clientIp = req.clientIp;
    
    if (!data.keys[key]) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_NOT_FOUND', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key không tồn tại!' });
    }
    
    const keyData = data.keys[key];
    if (!keyData.active) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_DISABLED', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key đã bị khóa!' });
    }
    
    if (keyData.hwid && keyData.hwid !== hwid) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'HWID_MISMATCH', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: '🔒 Key đã được sử dụng trên thiết bị khác!' });
    }
    
    if (new Date(keyData.expiry) < new Date()) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_EXPIRED', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key đã hết hạn!' });
    }
    
    if (keyData.used >= keyData.maxUses) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_EXHAUSTED', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key đã hết lượt!' });
    }
    
    if (!keyData.hwid) {
        keyData.hwid = hwid;
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    data.sessions[token] = { key, hwid, connectedAt: new Date().toISOString(), ip: clientIp };
    data.logs[key] = data.logs[key] || [];
    data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_SUCCESS', status: 'SUCCESS', ip: clientIp });
    saveData(data);
    
    res.json({
        success: true,
        message: `✅ Xác thực thành công! Còn ${keyData.maxUses - keyData.used} lượt`,
        data: { token, expiresIn: 86400, type: keyData.type, remaining: keyData.maxUses - keyData.used, total: keyData.maxUses }
    });
});

// ============================================================
// API QUẢN LÝ MÃ HÓA TOOL
// ============================================================

// Lưu key mã hóa (chỉ admin)
app.post('/api/save-encrypt-key', verifyAdmin, (req, res) => {
    const { key, iv, salt, encrypted } = req.body;
    
    if (!key || !iv || !encrypted) {
        return res.json({ success: false, message: 'Thiếu dữ liệu!' });
    }
    
    global.encryptKey = key;
    global.encryptIv = iv;
    global.encryptSalt = salt;
    global.encryptedCode = encrypted;
    global.encryptTimestamp = Date.now();
    
    console.log(`[ENCRYPT] Đã lưu key mã hóa mới!`);
    res.json({ success: true, message: 'Đã lưu key mã hóa!' });
});

// Lấy key giải mã (có xác thực HWID)
app.post('/api/get-decrypt-key', (req, res) => {
    const { hwid } = req.body;
    
    if (!hwid) {
        return res.json({ success: false, message: 'Thiếu HWID xác thực!' });
    }
    
    if (!global.encryptKey) {
        return res.json({ success: false, message: 'Chưa có key mã hóa!' });
    }
    
    // Kiểm tra HWID có trong danh sách key không
    const data = initData();
    let authorized = false;
    for (let key in data.keys) {
        if (data.keys[key].hwid === hwid) {
            authorized = true;
            break;
        }
    }
    
    if (!authorized) {
        return res.json({ success: false, message: '🔒 Thiết bị chưa được cấp phép!' });
    }
    
    res.json({
        success: true,
        key: global.encryptKey,
        iv: global.encryptIv,
        encrypted: global.encryptedCode,
        salt: global.encryptSalt
    });
});

// Kiểm tra hash file
app.post('/api/verify-hash', (req, res) => {
    const { hash } = req.body;
    
    if (!global.fileHash) {
        global.fileHash = hash;
        return res.json({ valid: true });
    }
    
    res.json({ valid: global.fileHash === hash });
});

// ============================================================
// API HACK 30M GOLD (XỬ LÝ TRÊN SERVER)
// ============================================================
app.post('/api/hack-gold', async (req, res) => {
    try {
        const { key, platform, uniqId, hostId, gichapo, times } = req.body;
        
        // Kiểm tra key hợp lệ
        const data = initData();
        if (!data.keys[key] || !data.keys[key].active) {
            return res.json({ success: false, message: 'Key không hợp lệ hoặc đã hết hạn!' });
        }
        
        const keyData = data.keys[key];
        if (keyData.used >= keyData.maxUses) {
            return res.json({ success: false, message: 'Key đã hết lượt sử dụng!' });
        }
        
        // ===== LOGIC HACK GỐC =====
        const K_AES2 = Buffer.from("gksekfidjrqjfwk1", "utf8");
        const I_AES2 = Buffer.from("towerdefense_amo", "utf8");
        
        function encryptAES2(data) {
            const cipher = crypto.createCipheriv("aes-128-cbc", K_AES2, I_AES2);
            let enc = cipher.update(JSON.stringify(data), "utf8", "base64");
            enc += cipher.final("base64");
            return enc;
        }
        
        function decryptAES2(b64) {
            try {
                if (typeof b64 === 'string' && b64.startsWith('{')) return b64;
                const d = crypto.createDecipheriv("aes-128-cbc", K_AES2, I_AES2);
                let dec = d.update(b64, "base64", "utf8") + d.final("utf8");
                return dec.replace(/[\x00-\x1F\x7F-\x9F]/g, "");
            } catch (e) { return null; }
        }
        
        function postRequest(url, postData, headers = {}, timeoutMs = 30000) {
            return new Promise((resolve, reject) => {
                const u = new URL(url);
                const opt = {
                    hostname: u.hostname,
                    port: u.port || 80,
                    path: u.pathname,
                    method: 'POST',
                    timeout: timeoutMs,
                    headers: {
                        'User-Agent': 'app',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(postData),
                        'Connection': 'keep-alive',
                        ...headers
                    }
                };
                const req = http.request(opt, res => {
                    let body = '';
                    res.on('data', chunk => body += chunk);
                    res.on('end', () => resolve(body));
                });
                req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
                req.on('error', e => reject(e));
                req.write(postData);
                req.end();
            });
        }
        
        function findGichapo(obj) {
            if (!obj || typeof obj !== 'object') return null;
            if (obj.gichapo && typeof obj.gichapo === 'string' && obj.gichapo.length >= 1) return obj.gichapo;
            for (let k in obj) { let f = findGichapo(obj[k]); if (f) return f; }
            return null;
        }
        
        async function hackGold30M(platform, uniqId, hostId, gichapo) {
            const payload = {
                SGS: true,
                LANG: 3,
                PICK: 8,
                PICK_NAME: "GOLD",
                PICK_AMOUNT: "30,000,000",
                UNIQ_ID: uniqId,
                PLATFORM: platform,
                MOBILE_CONNECT: "",
                GICHAPO: gichapo
            };
            
            const enc = encryptAES2(payload);
            const url = `http://211.253.26.47:8093/TOWERDEFENCE_COMMON/EVENT_MENU/eventmenu_shopping.php`;
            const body = `DATA=${encodeURIComponent(enc)}`;
            
            const res = await postRequest(url, body);
            try {
                const dec = decryptAES2(res);
                return JSON.parse(dec || res);
            } catch (e) {
                return { RAW: res, ERROR: e.message };
            }
        }
        
        // Lấy thông tin user trước
        const isViet = (platform === 'AMO' || platform === 'SS');
        const gicDefault = isViet ? "선택된서버:베트남서버 ping:67ms" : "선택된서버:한국서버 ping:205ms";
        const getUrl = `http://211.253.26.47:8093/TOWERDEFENCE_${platform}/get_user_data_all_AES2.php`;
        const getPayload = {
            UNIQ_ID: uniqId, HOST_ID: hostId,
            MOBILE_CONNECT: "", ANDROID_AD: "",
            GICHAPO: gicDefault, LOCAL_KEY: null
        };
        if (platform === 'ATV' || platform === 'LG') getPayload.MODEL_NAME = "BeyondTV";
        
        const res = await postRequest(getUrl, `DATA=${encodeURIComponent(encryptAES2(getPayload))}`);
        const dec = decryptAES2(res);
        if (!dec) throw new Error('Không giải mã được dữ liệu GET');
        const userData = JSON.parse(dec);
        const gichapo_found = findGichapo(userData);
        const val = userData.VALUE || {};
        const normal = val.normal?.value || {};
        const rubydiagold = val.rubydiagold?.value || {};
        const userName = normal.USER_NAME || '???';
        let gold = rubydiagold.GOLD || 0;
        
        // Hack
        let successCount = 0, totalGoldReceived = 0;
        const finalGichapo = gichapo || gichapo_found;
        for (let i = 0; i < times; i++) {
            const result = await hackGold30M(platform, uniqId, hostId, finalGichapo);
            if (result && result.RESULT === "OK") {
                successCount++;
                totalGoldReceived += 30000000;
            }
        }
        
        // Trừ lượt key
        keyData.used += times;
        saveData(data);
        
        res.json({
            success: true,
            userName: userName,
            goldBefore: gold,
            successCount: successCount,
            totalGoldReceived: totalGoldReceived,
            remainingUses: keyData.maxUses - keyData.used,
            message: `✅ Hack ${successCount}/${times} lần thành công! Nhận ${totalGoldReceived.toLocaleString()} vàng`
        });
        
    } catch (error) {
        res.json({ success: false, message: '❌ Lỗi: ' + error.message });
    }
});

// ============================================================
// API ADMIN
// ============================================================
app.post('/api/admin/create-key', verifyAdmin, (req, res) => {
    const { type, expiry, maxUses, note } = req.body;
    const data = initData();
    const newKey = `KEY_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    
    data.keys[newKey] = {
        type: type || 'vip',
        expiry: expiry || '2028-12-31',
        maxUses: maxUses || 999,
        used: 0,
        active: true,
        hwid: null,
        createdAt: new Date().toISOString(),
        note: note || 'Key mới'
    };
    
    data.logs[newKey] = data.logs[newKey] || [];
    data.logs[newKey].push({ timestamp: new Date().toISOString(), action: 'KEY_CREATED', status: 'SUCCESS', ip: req.clientIp });
    saveData(data);
    
    res.json({ success: true, message: 'Tạo key thành công!', key: newKey, data: data.keys[newKey] });
});

app.get('/api/admin/list-keys', verifyAdmin, (req, res) => {
    const data = initData();
    const keyList = Object.keys(data.keys).map(k => ({
        key: k,
        ...data.keys[k],
        remaining: data.keys[k].maxUses - data.keys[k].used,
        status: data.keys[k].active ? '🟢 Hoạt động' : '🔴 Đã khóa',
        hwid: data.keys[k].hwid || 'Chưa kích hoạt'
    }));
    res.json({ success: true, total: keyList.length, keys: keyList });
});

app.post('/api/admin/disable-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    const data = initData();
    if (!data.keys[key]) return res.json({ success: false, message: 'Key không tồn tại!' });
    data.keys[key].active = false;
    data.logs[key] = data.logs[key] || [];
    data.logs[key].push({ timestamp: new Date().toISOString(), action: 'KEY_DISABLED', status: 'SUCCESS', ip: req.clientIp });
    saveData(data);
    res.json({ success: true, message: `Đã khóa key: ${key}` });
});

app.post('/api/admin/delete-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    const data = initData();
    if (!data.keys[key]) return res.json({ success: false, message: 'Key không tồn tại!' });
    delete data.keys[key];
    delete data.logs[key];
    saveData(data);
    res.json({ success: true, message: `Đã xóa key: ${key}` });
});

app.get('/api/admin/logs', verifyAdmin, (req, res) => {
    const { key, limit = 50 } = req.query;
    const data = initData();
    let logs = [];
    if (key && data.logs[key]) {
        logs = data.logs[key];
    } else {
        Object.keys(data.logs).forEach(k => {
            data.logs[k].forEach(log => {
                logs.push({ ...log, key: k });
            });
        });
    }
    logs = logs.slice(-parseInt(limit)).reverse();
    res.json({ success: true, total: logs.length, logs });
});

app.get('/api/admin/sessions', verifyAdmin, (req, res) => {
    const data = initData();
    const sessions = Object.keys(data.sessions).map(token => ({
        token: token.substring(0, 16) + '...',
        ...data.sessions[token]
    }));
    res.json({ success: true, total: sessions.length, sessions });
});

app.post('/api/admin/disconnect', verifyAdmin, (req, res) => {
    const { token, key } = req.body;
    const data = initData();
    let disconnected = [];
    if (token && data.sessions[token]) {
        delete data.sessions[token];
        disconnected.push(token.substring(0, 16) + '...');
    } else if (key) {
        const tokens = Object.keys(data.sessions).filter(t => data.sessions[t].key === key);
        tokens.forEach(t => { delete data.sessions[t]; disconnected.push(t.substring(0, 16) + '...'); });
    } else {
        const tokens = Object.keys(data.sessions);
        tokens.forEach(t => { delete data.sessions[t]; disconnected.push(t.substring(0, 16) + '...'); });
    }
    res.json({ success: true, message: `Đã ngắt ${disconnected.length} session(s)`, disconnected });
});

// ============================================================
// KHỞI ĐỘNG SERVER
// ============================================================
app.listen(PORT, () => {
    initData();
    console.log(`✅ Server đang chạy tại port ${PORT}`);
    console.log(`🔑 Admin Key: ${ADMIN_KEY}`);
    console.log(`📁 Dữ liệu: ${DATA_FILE}`);
    console.log(`📌 API hack 30M Gold đã sẵn sàng!`);
});
