const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req, res) => {
    res.json({
        name: 'Tool Management Server',
        version: '3.0.0',
        status: 'running',
        endpoints: {
            health: '/api/health',
            verify: '/api/verify (POST)',
            createKey: '/api/admin/create-key (POST)'
        }
    });
});

app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        message: 'Server is running'
    });
});

app.post('/api/verify', (req, res) => {
    const { key } = req.body;
    if (!key) {
        return res.json({ success: false, message: 'Key không được để trống!' });
    }
    
    if (key === 'TEST_2026') {
        return res.json({
            success: true,
            message: 'Key hợp lệ!',
            data: { remaining: 999, total: 1000 }
        });
    }
    
    res.json({ success: false, message: 'Key không tồn tại!' });
});

app.post('/api/admin/create-key', (req, res) => {
    const { adminKey } = req.body;
    if (adminKey !== 'ADMIN_2026_SECRET') {
        return res.status(403).json({ success: false, message: 'Không có quyền!' });
    }
    res.json({
        success: true,
        key: `KEY_${Date.now()}`,
        message: 'Key đã được tạo!'
    });
});

app.listen(PORT, () => {
    console.log(`✅ Server đang chạy tại port ${PORT}`);
    console.log(`🔑 Admin Key: ADMIN_2026_SECRET`);
});
