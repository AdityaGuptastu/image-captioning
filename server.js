const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ai_vision_studio'
};

let db;

// Initialize database connection
async function initializeDatabase() {
    try {
        db = await mysql.createConnection(dbConfig);
        console.log('Connected to MySQL database');
        
        // Create tables if they don't exist
        await createTables();
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

// Create database tables
async function createTables() {
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE,
            password VARCHAR(255) NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL,
            profile_image VARCHAR(255) DEFAULT NULL
        )
    `;

    const createAnalysesTable = `
        CREATE TABLE IF NOT EXISTS analyses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            image_url VARCHAR(500) NOT NULL,
            caption TEXT NOT NULL,
            features JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `;

    const createSessionsTable = `
        CREATE TABLE IF NOT EXISTS sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token VARCHAR(500) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `;

    try {
        await db.execute(createUsersTable);
        await db.execute(createAnalysesTable);
        await db.execute(createSessionsTable);
        
        // Create default admin user if not exists
        await createDefaultAdmin();
        
        console.log('Database tables created successfully');
    } catch (error) {
        console.error('Error creating tables:', error);
    }
}

// Create default admin user
async function createDefaultAdmin() {
    try {
        const [existing] = await db.execute('SELECT id FROM users WHERE is_admin = TRUE LIMIT 1');
        
        if (existing.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await db.execute(
                'INSERT INTO users (username, password, is_admin) VALUES (?, ?, TRUE)',
                ['admin', hashedPassword]
            );
            console.log('Default admin user created: username=admin, password=admin123');
        }
    } catch (error) {
        console.error('Error creating default admin:', error);
    }
}

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [users] = await db.execute('SELECT * FROM users WHERE id = ?', [decoded.userId]);
        
        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }

        req.user = users[0];
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// Middleware to verify admin
const verifyAdmin = (req, res, next) => {
    if (!req.user.is_admin) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

// Routes

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username and password are required' });
        }

        // Check if user already exists
        const [existing] = await db.execute('SELECT id FROM users WHERE username = ? OR email = ?', [username, email || '']);
        
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        const [result] = await db.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email || null, hashedPassword]
        );

        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username and password are required' });
        }

        // Find user
        const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
        
        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const user = users[0];

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Update last login
        await db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username, isAdmin: user.is_admin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                isAdmin: user.is_admin,
                profileImage: user.profile_image
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/verify', verifyToken, (req, res) => {
    res.json({
        success: true,
        user: {
            id: req.user.id,
            username: req.user.username,
            email: req.user.email,
            isAdmin: req.user.is_admin,
            profileImage: req.user.profile_image
        }
    });
});

// Analysis Routes
app.post('/api/analyses', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const { caption, features } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Image file is required' });
        }

        const imageUrl = `/uploads/${req.file.filename}`;

        const [result] = await db.execute(
            'INSERT INTO analyses (user_id, image_url, caption, features) VALUES (?, ?, ?, ?)',
            [req.user.id, imageUrl, caption, features]
        );

        res.json({
            success: true,
            analysis: {
                id: result.insertId,
                imageUrl,
                caption,
                features: JSON.parse(features)
            }
        });
    } catch (error) {
        console.error('Analysis save error:', error);
        res.status(500).json({ success: false, message: 'Failed to save analysis' });
    }
});

app.get('/api/analyses/user/:userId', verifyToken, async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);
        
        // Users can only access their own analyses, admins can access any
        if (req.user.id !== userId && !req.user.is_admin) {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        const [analyses] = await db.execute(
            'SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );

        res.json({ success: true, analyses });
    } catch (error) {
        console.error('Get analyses error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch analyses' });
    }
});

app.delete('/api/analyses/:id', verifyToken, async (req, res) => {
    try {
        const analysisId = parseInt(req.params.id);

        // Check if analysis belongs to user or user is admin
        const [analyses] = await db.execute('SELECT * FROM analyses WHERE id = ?', [analysisId]);
        
        if (analyses.length === 0) {
            return res.status(404).json({ success: false, message: 'Analysis not found' });
        }

        const analysis = analyses[0];
        
        if (analysis.user_id !== req.user.id && !req.user.is_admin) {
            return res.status(403).json({ success: false, message: 'Access denied' });
        }

        // Delete image file
        try {
            await fs.unlink(path.join(__dirname, 'public', analysis.image_url));
        } catch (fileError) {
            console.log('File deletion error (file may not exist):', fileError.message);
        }

        // Delete from database
        await db.execute('DELETE FROM analyses WHERE id = ?', [analysisId]);

        res.json({ success: true, message: 'Analysis deleted successfully' });
    } catch (error) {
        console.error('Delete analysis error:', error);
        res.status(500).json({ success: false, message: 'Failed to delete analysis' });
    }
});

// Admin Routes
app.get('/api/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const [userCount] = await db.execute('SELECT COUNT(*) as count FROM users');
        const [analysisCount] = await db.execute('SELECT COUNT(*) as count FROM analyses');
        const [todayCount] = await db.execute('SELECT COUNT(*) as count FROM analyses WHERE DATE(created_at) = CURDATE()');

        res.json({
            success: true,
            stats: {
                totalUsers: userCount[0].count,
                totalAnalyses: analysisCount[0].count,
                todayAnalyses: todayCount[0].count
            }
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch stats' });
    }
});

app.get('/api/admin/analyses', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const [analyses] = await db.execute(`
            SELECT a.*, u.username 
            FROM analyses a 
            JOIN users u ON a.user_id = u.id 
            ORDER BY a.created_at DESC 
            LIMIT 50
        `);

        res.json({ success: true, analyses });
    } catch (error) {
        console.error('Admin analyses error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch analyses' });
    }
});

app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const [users] = await db.execute(`
            SELECT u.id, u.username, u.email, u.is_admin, u.created_at, u.last_login,
                   COUNT(a.id) as total_analyses
            FROM users u
            LEFT JOIN analyses a ON u.id = a.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        `);

        res.json({ success: true, users });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch users' });
    }
});

app.delete('/api/admin/analyses/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const analysisId = parseInt(req.params.id);

        const [analyses] = await db.execute('SELECT * FROM analyses WHERE id = ?', [analysisId]);
        
        if (analyses.length === 0) {
            return res.status(404).json({ success: false, message: 'Analysis not found' });
        }

        const analysis = analyses[0];

        // Delete image file
        try {
            await fs.unlink(path.join(__dirname, 'public', analysis.image_url));
        } catch (fileError) {
            console.log('File deletion error:', fileError.message);
        }

        // Delete from database
        await db.execute('DELETE FROM analyses WHERE id = ?', [analysisId]);

        res.json({ success: true, message: 'Analysis deleted successfully' });
    } catch (error) {
        console.error('Admin delete error:', error);
        res.status(500).json({ success: false, message: 'Failed to delete analysis' });
    }
});

app.delete('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        if (userId === req.user.id) {
            return res.status(400).json({ success: false, message: 'Cannot delete your own account' });
        }

        // Delete user (cascades to delete analyses)
        await db.execute('DELETE FROM users WHERE id = ?', [userId]);

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({ success: false, message: 'Failed to delete user' });
    }
});

// User Profile Routes
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const [analyses] = await db.execute(
            'SELECT COUNT(*) as total FROM analyses WHERE user_id = ?',
            [req.user.id]
        );

        res.json({
            success: true,
            profile: {
                id: req.user.id,
                username: req.user.username,
                email: req.user.email,
                profileImage: req.user.profile_image,
                totalAnalyses: analyses[0].total,
                memberSince: req.user.created_at,
                lastLogin: req.user.last_login
            }
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch profile' });
    }
});

app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { email } = req.body;

        await db.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            [email || null, req.user.id]
        );

        res.json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ success: false, message: 'Failed to update profile' });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'File too large' });
        }
    }
    
    console.error('Unhandled error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

// Create uploads directory if it doesn't exist
async function createUploadsDir() {
    try {
        await fs.access('uploads');
    } catch {
        await fs.mkdir('uploads');
        console.log('Created uploads directory');
    }
}

// Start server
async function startServer() {
    await initializeDatabase();
    await createUploadsDir();
    
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
        console.log(`User panel: http://localhost:${PORT}/user.html`);
    });
}

startServer().catch(console.error);