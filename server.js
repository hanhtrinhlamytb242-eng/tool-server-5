const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));

// ============================================================
// CẤU HÌNH
// ============================================================
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_KEY = 'ADMIN_2026_Ka1t0_S3cr3t_X9zW8yV7uT6rQ5pO4nM3';

// ===== RSA KEY =====
const RSA_PRIVATE_FILE = path.join(__dirname, 'rsa_private.pem');
const RSA_PUBLIC_FILE = path.join(__dirname, 'rsa_public.pem');

function generateRSAKeys() {
    if (!fs.existsSync(RSA_PRIVATE_FILE) || !fs.existsSync(RSA_PUBLIC_FILE)) {
        const { generateKeyPairSync } = require('crypto');
        const { privateKey, publicKey } = generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        fs.writeFileSync(RSA_PRIVATE_FILE, privateKey);
        fs.writeFileSync(RSA_PUBLIC_FILE, publicKey);
        console.log('✅ Đã tạo cặp RSA key mới!');
    }
    return {
        privateKey: fs.readFileSync(RSA_PRIVATE_FILE, 'utf8'),
        publicKey: fs.readFileSync(RSA_PUBLIC_FILE, 'utf8')
    };
}

const RSA = generateRSAKeys();

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

app.get('/api/public-key', (req, res) => {
    res.json({ success: true, publicKey: RSA.publicKey });
});

// ============================================================
// API CŨ (HỖ TRỢ TOOL KHÔNG RSA) - THÊM MỚI
// ============================================================
app.post('/verify-key', (req, res) => {
    const { key, hwid } = req.body;
    const data = initData();
    const clientIp = req.clientIp;
    
    console.log(`[VERIFY] Key: ${key}, HWID: ${hwid}`);
    
    // Kiểm tra key tồn tại
    if (!data.keys[key]) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_NOT_FOUND', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key không tồn tại!' });
    }
    
    const keyData = data.keys[key];
    
    // Kiểm tra key active
    if (!keyData.active) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_DISABLED', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key đã bị khóa!' });
    }
    
    // Kiểm tra HWID (mỗi key chỉ dùng 1 máy)
    if (keyData.hwid && keyData.hwid !== hwid) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'HWID_MISMATCH', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: '🔒 Key đã được sử dụng trên thiết bị khác!' });
    }
    
    // Kiểm tra hết hạn
    if (new Date(keyData.expiry) < new Date()) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_EXPIRED', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key đã hết hạn!' });
    }
    
    // Kiểm tra số lượt dùng
    if (keyData.used >= keyData.maxUses) {
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_FAILED', status: 'KEY_EXHAUSTED', ip: clientIp });
        saveData(data);
        return res.json({ success: false, message: 'Key đã hết lượt!' });
    }
    
    // Lưu HWID lần đầu
    if (!keyData.hwid) {
        keyData.hwid = hwid;
    }
    
    // Tăng số lượt dùng
    keyData.used++;
    
    // Tạo session token
    const token = crypto.randomBytes(32).toString('hex');
    data.sessions[token] = { key, hwid, connectedAt: new Date().toISOString(), ip: clientIp };
    
    // Ghi log
    data.logs[key] = data.logs[key] || [];
    data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_SUCCESS', status: 'SUCCESS', ip: clientIp });
    saveData(data);
    
    res.json({
        success: true,
        message: `✅ Xác thực thành công! Còn ${keyData.maxUses - keyData.used} lượt`,
        data: {
            token,
            expiresIn: 86400,
            type: keyData.type,
            remaining: keyData.maxUses - keyData.used,
            total: keyData.maxUses
        }
    });
});

app.post('/use-key', (req, res) => {
    const { key, hwid } = req.body;
    const data = initData();
    const clientIp = req.clientIp;
    
    console.log(`[USE] Key: ${key}, HWID: ${hwid}`);
    
    if (!data.keys[key]) {
        return res.json({ success: false, message: 'Key không tồn tại!' });
    }
    
    const keyData = data.keys[key];
    
    if (keyData.hwid && keyData.hwid !== hwid) {
        return res.json({ success: false, message: '🔒 Sai thiết bị!' });
    }
    
    if (keyData.used >= keyData.maxUses) {
        return res.json({ success: false, message: 'Key đã hết lượt!', remaining: 0, total: keyData.maxUses });
    }
    
    keyData.used++;
    
    data.logs[key] = data.logs[key] || [];
    data.logs[key].push({ timestamp: new Date().toISOString(), action: 'USE_KEY', status: 'SUCCESS', ip: clientIp });
    saveData(data);
    
    res.json({
        success: true,
        message: `Còn ${keyData.maxUses - keyData.used}/${keyData.maxUses} lượt`,
        remaining: keyData.maxUses - keyData.used,
        total: keyData.maxUses
    });
});

// ============================================================
// API RSA MỚI
// ============================================================
app.post('/api/secure-verify', (req, res) => {
    try {
        const encrypted = Buffer.from(req.body.encrypted, 'base64');
        const decrypted = crypto.privateDecrypt({
            key: RSA.privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, encrypted);
        const { key, hwid, timestamp } = JSON.parse(decrypted.toString('utf8'));
        const data = initData();
        const clientIp = req.clientIp;

        if (Date.now() - timestamp > 30000) {
            return res.json({ success: false, message: '⏰ Request đã hết hạn!' });
        }

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

        keyData.used++;
        const token = crypto.randomBytes(32).toString('hex');
        data.sessions[token] = { key, hwid, connectedAt: new Date().toISOString(), ip: clientIp };
        
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'VERIFY_SUCCESS', status: 'SUCCESS', ip: clientIp });
        saveData(data);

        const responseData = {
            success: true,
            message: `✅ Xác thực thành công! Còn ${keyData.maxUses - keyData.used} lượt`,
            data: { token, expiresIn: 86400, type: keyData.type, remaining: keyData.maxUses - keyData.used, total: keyData.maxUses }
        };
        const encryptedResponse = crypto.publicEncrypt({
            key: RSA.publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(JSON.stringify(responseData)));
        
        res.json({ encrypted: encryptedResponse.toString('base64') });

    } catch (error) {
        res.json({ success: false, message: '❌ Lỗi giải mã: ' + error.message });
    }
});

app.post('/api/secure-use', (req, res) => {
    try {
        const encrypted = Buffer.from(req.body.encrypted, 'base64');
        const decrypted = crypto.privateDecrypt({
            key: RSA.privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, encrypted);
        const { key, hwid, timestamp } = JSON.parse(decrypted.toString('utf8'));

        if (Date.now() - timestamp > 30000) {
            return res.json({ success: false, message: '⏰ Request đã hết hạn!' });
        }

        const data = initData();
        if (!data.keys[key]) {
            return res.json({ success: false, message: 'Key không tồn tại!' });
        }

        const keyData = data.keys[key];
        if (keyData.hwid && keyData.hwid !== hwid) {
            return res.json({ success: false, message: '🔒 Sai thiết bị!' });
        }

        if (keyData.used >= keyData.maxUses) {
            return res.json({ success: false, message: 'Key đã hết lượt!', remaining: 0, total: keyData.maxUses });
        }

        keyData.used++;
        data.logs[key] = data.logs[key] || [];
        data.logs[key].push({ timestamp: new Date().toISOString(), action: 'USE_KEY', status: 'SUCCESS', ip: req.clientIp });
        saveData(data);

        const responseData = {
            success: true,
            message: `Còn ${keyData.maxUses - keyData.used}/${keyData.maxUses} lượt`,
            remaining: keyData.maxUses - keyData.used,
            total: keyData.maxUses
        };
        const encryptedResponse = crypto.publicEncrypt({
            key: RSA.publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(JSON.stringify(responseData)));
        
        res.json({ encrypted: encryptedResponse.toString('base64') });

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

app.post('/api/admin/enable-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    const data = initData();
    if (!data.keys[key]) return res.json({ success: false, message: 'Key không tồn tại!' });
    data.keys[key].active = true;
    data.logs[key] = data.logs[key] || [];
    data.logs[key].push({ timestamp: new Date().toISOString(), action: 'KEY_ENABLED', status: 'SUCCESS', ip: req.clientIp });
    saveData(data);
    res.json({ success: true, message: `Đã kích hoạt lại key: ${key}` });
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
    console.log(`🔐 RSA Key đã tạo!`);
    console.log(`📌 API cũ /verify-key và /use-key đã được thêm!`);
});
