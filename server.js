const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ===== FILE LƯU DỮ LIỆU =====
const DATA_FILE = path.join(__dirname, 'data.json');

// ===== KHỞI TẠO DỮ LIỆU =====
function initData() {
    if (!fs.existsSync(DATA_FILE)) {
        const defaultData = {
            keys: {},
            logs: [],
            sessions: {}
        };
        fs.writeFileSync(DATA_FILE, JSON.stringify(defaultData, null, 2));
    }
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function saveData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ===== CORS - CHO PHÉP TRUY CẬP TỪ MỌI NƠI =====
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, x-api-key');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// ===== LOG MIDDLEWARE =====
app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${clientIp}`);
    req.clientIp = clientIp;
    next();
});

// ===== ADMIN KEY MỚI (BẢO MẬT) =====
const ADMIN_KEY = 'ADMIN_2026_Ka1t0_S3cr3t_X9zW8yV7uT6rQ5pO4nM3';

// ===== MIDDLEWARE XÁC THỰC ADMIN =====
function verifyAdmin(req, res, next) {
    const adminKey = req.body.adminKey || req.query.adminKey || req.headers['x-admin-key'];
    if (adminKey !== ADMIN_KEY) {
        return res.status(403).json({
            success: false,
            message: '🔒 Không có quyền truy cập!'
        });
    }
    next();
}

// ===== API GỐC =====
app.get('/', (req, res) => {
    res.json({
        name: 'Tool Management Server',
        version: '3.0.0',
        status: 'running'
    });
});

// ===== API HEALTH =====
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

// ===== API XÁC THỰC KEY (TOOL GỌI) =====
app.post('/verify-key', (req, res) => {
    const { key, hwid } = req.body;
    const data = initData();
    const clientIp = req.clientIp;
    
    if (!data.keys[key]) {
        data.logs.push({
            timestamp: new Date().toISOString(),
            key: key,
            action: 'VERIFY_FAILED',
            status: 'KEY_NOT_FOUND',
            ip: clientIp,
            message: 'Key không tồn tại'
        });
        saveData(data);
        return res.json({
            success: false,
            message: 'Key không tồn tại! Vui lòng nhập lại.'
        });
    }
    
    const keyData = data.keys[key];
    
    if (!keyData.active) {
        data.logs.push({
            timestamp: new Date().toISOString(),
            key: key,
            action: 'VERIFY_FAILED',
            status: 'KEY_DISABLED',
            ip: clientIp,
            message: 'Key đã bị vô hiệu hóa'
        });
        saveData(data);
        return res.json({
            success: false,
            message: 'Key đã bị vô hiệu hóa!'
        });
    }
    
    if (new Date(keyData.expiry) < new Date()) {
        data.logs.push({
            timestamp: new Date().toISOString(),
            key: key,
            action: 'VERIFY_FAILED',
            status: 'KEY_EXPIRED',
            ip: clientIp,
            message: 'Key đã hết hạn'
        });
        saveData(data);
        return res.json({
            success: false,
            message: 'Key đã hết hạn!'
        });
    }
    
    if (keyData.used >= keyData.maxUses) {
        data.logs.push({
            timestamp: new Date().toISOString(),
            key: key,
            action: 'VERIFY_FAILED',
            status: 'KEY_EXHAUSTED',
            ip: clientIp,
            message: 'Key đã hết lượt sử dụng'
        });
        saveData(data);
        return res.json({
            success: false,
            message: 'Key đã hết lượt sử dụng!'
        });
    }
    
    keyData.used++;
    
    const token = crypto.randomBytes(32).toString('hex');
    data.sessions[token] = {
        key: key,
        hwid: hwid || 'unknown',
        connectedAt: new Date().toISOString(),
        lastActive: new Date().toISOString(),
        ip: clientIp
    };
    
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: key,
        action: 'VERIFY_SUCCESS',
        status: 'SUCCESS',
        ip: clientIp,
        sessionToken: token,
        message: `Xác thực thành công, còn ${keyData.maxUses - keyData.used} lượt`
    });
    
    saveData(data);
    
    res.json({
        success: true,
        message: `Xác thực thành công! Còn ${keyData.maxUses - keyData.used} lượt`,
        data: {
            token: token,
            expiresIn: 86400,
            type: keyData.type,
            total: keyData.maxUses,
            remaining: keyData.maxUses - keyData.used
        }
    });
});

// ===== API TRỪ LƯỢT DÙNG =====
app.post('/use-key', (req, res) => {
    const { key, hwid } = req.body;
    const data = initData();
    const clientIp = req.clientIp;
    
    if (!data.keys[key]) {
        return res.json({ success: false, message: 'Key không tồn tại!' });
    }
    
    const keyData = data.keys[key];
    
    if (keyData.used >= keyData.maxUses) {
        return res.json({
            success: false,
            message: 'Key đã hết lượt!',
            remaining: 0,
            total: keyData.maxUses
        });
    }
    
    keyData.used++;
    
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: key,
        action: 'USE_KEY',
        status: 'SUCCESS',
        ip: clientIp,
        message: `Đã sử dụng 1 lượt, còn ${keyData.maxUses - keyData.used} lượt`
    });
    
    saveData(data);
    
    res.json({
        success: true,
        message: `Còn ${keyData.maxUses - keyData.used}/${keyData.maxUses} lượt`,
        remaining: keyData.maxUses - keyData.used,
        total: keyData.maxUses
    });
});

// ============================================================
// API ADMIN - CÓ XÁC THỰC ADMIN KEY
// ============================================================

// ===== TẠO KEY =====
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
        createdAt: new Date().toISOString(),
        note: note || 'Key mới'
    };
    
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: newKey,
        action: 'KEY_CREATED',
        status: 'SUCCESS',
        ip: req.clientIp,
        message: `Đã tạo key mới: ${newKey}`
    });
    
    saveData(data);
    
    res.json({
        success: true,
        message: 'Tạo key thành công!',
        key: newKey,
        data: data.keys[newKey]
    });
});

// ===== XEM DANH SÁCH KEY =====
app.get('/api/admin/list-keys', verifyAdmin, (req, res) => {
    const data = initData();
    const keyList = Object.keys(data.keys).map(k => ({
        key: k,
        ...data.keys[k],
        remaining: data.keys[k].maxUses - data.keys[k].used,
        status: data.keys[k].active ? '🟢 Hoạt động' : '🔴 Đã khóa'
    }));
    
    res.json({
        success: true,
        total: keyList.length,
        keys: keyList
    });
});

// ===== XÓA KEY =====
app.post('/api/admin/delete-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    const data = initData();
    
    if (!data.keys[key]) {
        return res.json({
            success: false,
            message: 'Key không tồn tại!'
        });
    }
    
    delete data.keys[key];
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: key,
        action: 'KEY_DELETED',
        status: 'SUCCESS',
        ip: req.clientIp,
        message: `Đã xóa key: ${key}`
    });
    saveData(data);
    
    res.json({
        success: true,
        message: `Đã xóa key: ${key}`
    });
});

// ===== VÔ HIỆU HÓA KEY =====
app.post('/api/admin/disable-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    const data = initData();
    
    if (!data.keys[key]) {
        return res.json({
            success: false,
            message: 'Key không tồn tại!'
        });
    }
    
    data.keys[key].active = false;
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: key,
        action: 'KEY_DISABLED',
        status: 'SUCCESS',
        ip: req.clientIp,
        message: `Đã vô hiệu hóa key: ${key}`
    });
    saveData(data);
    
    res.json({
        success: true,
        message: `Đã vô hiệu hóa key: ${key}`
    });
});

// ===== KÍCH HOẠT KEY =====
app.post('/api/admin/enable-key', verifyAdmin, (req, res) => {
    const { key } = req.body;
    const data = initData();
    
    if (!data.keys[key]) {
        return res.json({
            success: false,
            message: 'Key không tồn tại!'
        });
    }
    
    data.keys[key].active = true;
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: key,
        action: 'KEY_ENABLED',
        status: 'SUCCESS',
        ip: req.clientIp,
        message: `Đã kích hoạt lại key: ${key}`
    });
    saveData(data);
    
    res.json({
        success: true,
        message: `Đã kích hoạt lại key: ${key}`
    });
});

// ===== XEM LOG =====
app.get('/api/admin/logs', verifyAdmin, (req, res) => {
    const { limit = 50 } = req.query;
    const data = initData();
    const logs = data.logs.slice(-parseInt(limit)).reverse();
    
    res.json({
        success: true,
        total: data.logs.length,
        logs: logs
    });
});

// ===== XEM SESSIONS =====
app.get('/api/admin/sessions', verifyAdmin, (req, res) => {
    const data = initData();
    const sessions = Object.keys(data.sessions).map(token => ({
        token: token.substring(0, 16) + '...',
        ...data.sessions[token]
    }));
    
    res.json({
        success: true,
        total: sessions.length,
        sessions: sessions
    });
});

// ===== NGẮT KẾT NỐI =====
app.post('/api/admin/disconnect', verifyAdmin, (req, res) => {
    const { token, key } = req.body;
    const data = initData();
    let disconnected = [];
    
    if (token && data.sessions[token]) {
        delete data.sessions[token];
        disconnected.push(token.substring(0, 16) + '...');
    } else if (key) {
        const tokens = Object.keys(data.sessions).filter(t => data.sessions[t].key === key);
        tokens.forEach(t => {
            delete data.sessions[t];
            disconnected.push(t.substring(0, 16) + '...');
        });
    } else {
        const tokens = Object.keys(data.sessions);
        tokens.forEach(t => {
            delete data.sessions[t];
            disconnected.push(t.substring(0, 16) + '...');
        });
    }
    
    data.logs.push({
        timestamp: new Date().toISOString(),
        key: key || 'ALL',
        action: 'DISCONNECT',
        status: 'SUCCESS',
        ip: req.clientIp,
        message: `Đã ngắt kết nối ${disconnected.length} session(s)`
    });
    saveData(data);
    
    res.json({
        success: true,
        message: `Đã ngắt kết nối ${disconnected.length} session(s)`,
        disconnected: disconnected
    });
});

// ===== KHỞI ĐỘNG =====
app.listen(PORT, () => {
    initData();
    console.log(`✅ Server đang chạy tại port ${PORT}`);
    console.log(`🔑 Admin Key: ${ADMIN_KEY}`);
    console.log(`📁 Dữ liệu: ${DATA_FILE}`);
});
