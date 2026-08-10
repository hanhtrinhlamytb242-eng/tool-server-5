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

// ===== LOG MIDDLEWARE =====
app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${clientIp}`);
    req.clientIp = clientIp;
    next();
});

// ===== API GỐC =====
app.get('/', (req, res) => {
    res.json({
        name: 'Tool Management Server',
        version: '3.0.0',
        status: 'running',
        endpoints: {
            health: '/api/health',
            'verify-key': '/verify-key (POST)',
            'use-key': '/use-key (POST)',
            createKey: '/api/admin/create-key (POST)',
            listKeys: '/api/admin/list-keys (GET)',
            disableKey: '/api/admin/disable-key (POST)',
            logs: '/api/admin/logs (GET)'
        }
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
    
    console.log(`[AUTH] Key: ${key}, HWID: ${hwid}`);
    
    // Kiểm tra key tồn tại
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
    
    // Kiểm tra key active
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
    
    // Kiểm tra hết hạn
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
    
    // Kiểm tra số lượt dùng
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
    
    // Tạo session token
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

// ===== API TRỪ LƯỢT DÙNG (TOOL GỌI) =====
app.post('/use-key', (req, res) => {
    const { key, hwid } = req.body;
    const data = initData();
    const clientIp = req.clientIp;
    
    console.log(`[USE] Key: ${key}, HWID: ${hwid}`);
    
    if (!data.keys[key]) {
        return res.json({ success: false, message: 'Key không tồn tại!' });
    }
    
    const keyData = data.keys[key];
    
    // Kiểm tra còn lượt không
    if (keyData.used >= keyData.maxUses) {
        return res.json({
            success: false,
            message: 'Key đã hết lượt!',
            remaining: 0,
            total: keyData.maxUses
        });
    }
    
    // Tăng số lượt dùng
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

// ===== API ADMIN - TẠO KEY =====
app.post('/api/admin/create-key', (req, res) => {
    const { adminKey, type, expiry, maxUses, note } = req.body;
    
    if (adminKey !== 'ADMIN_2026_SECRET') {
        return res.status(403).json({
            success: false,
            message: 'Không có quyền!'
        });
    }
    
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

// ===== API ADMIN - XEM DANH SÁCH KEY =====
app.get('/api/admin/list-keys', (req, res) => {
    const { adminKey } = req.query;
    
    if (adminKey !== 'ADMIN_2026_SECRET') {
        return res.status(403).json({
            success: false,
            message: 'Không có quyền!'
        });
    }
    
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

// ===== API ADMIN - VÔ HIỆU HÓA KEY =====
app.post('/api/admin/disable-key', (req, res) => {
    const { adminKey, key } = req.body;
    
    if (adminKey !== 'ADMIN_2026_SECRET') {
        return res.status(403).json({
            success: false,
            message: 'Không có quyền!'
        });
    }
    
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

// ===== API ADMIN - XEM LOG =====
app.get('/api/admin/logs', (req, res) => {
    const { adminKey, limit = 50 } = req.query;
    
    if (adminKey !== 'ADMIN_2026_SECRET') {
        return res.status(403).json({
            success: false,
            message: 'Không có quyền!'
        });
    }
    
    const data = initData();
    const logs = data.logs.slice(-parseInt(limit)).reverse();
    
    res.json({
        success: true,
        total: data.logs.length,
        logs: logs
    });
});

// ===== KHỞI ĐỘNG SERVER =====
app.listen(PORT, () => {
    initData();
    console.log(`✅ Server đang chạy tại port ${PORT}`);
    console.log(`📁 Dữ liệu lưu tại: ${DATA_FILE}`);
    console.log(`🔑 Admin Key: ADMIN_2026_SECRET`);
    console.log(`📋 Key mẫu: TEST_2026`);
});
