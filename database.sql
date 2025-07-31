-- AI Vision Studio Database Schema
-- Run this script to set up the database manually

-- Create database
CREATE DATABASE IF NOT EXISTS ai_vision_studio;
USE ai_vision_studio;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    profile_picture VARCHAR(255),
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_is_admin (is_admin),
    INDEX idx_created_at (created_at)
);

-- Analyses table
CREATE TABLE IF NOT EXISTS analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    image_url VARCHAR(500) NOT NULL,
    image_filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255),
    image_size INT, -- File size in bytes
    image_width INT,
    image_height INT,
    caption TEXT NOT NULL,
    features JSON,
    confidence_score DECIMAL(5,2), -- 0.00 to 100.00
    processing_time INT, -- Processing time in milliseconds
    ip_address VARCHAR(45), -- Support IPv6
    user_agent TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    view_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign key
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_is_public (is_public),
    INDEX idx_confidence_score (confidence_score),
    INDEX idx_user_created (user_id, created_at)
);

-- User sessions table (for better session management)
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    INDEX idx_user_id (user_id),
    INDEX idx_session_token (session_token),
    INDEX idx_expires_at (expires_at)
);

-- Analysis tags table (for categorization)
CREATE TABLE IF NOT EXISTS analysis_tags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    color VARCHAR(7), -- Hex color code
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_name (name)
);

-- Junction table for analysis-tag relationships
CREATE TABLE IF NOT EXISTS analysis_tag_relations (
    analysis_id INT NOT NULL,
    tag_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (analysis_id, tag_id),
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES analysis_tags(id) ON DELETE CASCADE
);

-- User preferences table
CREATE TABLE IF NOT EXISTS user_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE NOT NULL,
    theme VARCHAR(20) DEFAULT 'light', -- light, dark, auto
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    notifications_enabled BOOLEAN DEFAULT TRUE,
    email_notifications BOOLEAN DEFAULT TRUE,
    public_profile BOOLEAN DEFAULT FALSE,
    auto_save_analyses BOOLEAN DEFAULT TRUE,
    preferred_image_quality VARCHAR(20) DEFAULT 'high',
    max_history_items INT DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- System logs table
CREATE TABLE IF NOT EXISTS system_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    level ENUM('ERROR', 'WARN', 'INFO', 'DEBUG') NOT NULL,
    message TEXT NOT NULL,
    context JSON,
    user_id INT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_level (level),
    INDEX idx_created_at (created_at),
    INDEX idx_user_id (user_id)
);

-- API usage tracking table
CREATE TABLE IF NOT EXISTS api_usage_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INT NOT NULL,
    response_time INT, -- in milliseconds
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_size INT,
    response_size INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_user_id (user_id),
    INDEX idx_endpoint (endpoint),
    INDEX idx_created_at (created_at),
    INDEX idx_status_code (status_code)
);

-- Insert default admin user
INSERT IGNORE INTO users (username, password, is_admin) 
VALUES ('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', TRUE);
-- Default password is 'password' - change this immediately!

-- Insert default analysis tags
INSERT IGNORE INTO analysis_tags (name, description, color) VALUES
('Portrait', 'Images containing people or faces', '#FF6B6B'),
('Landscape', 'Natural landscape scenes', '#4ECDC4'),
('Architecture', 'Buildings and structures', '#45B7D1'),
('Nature', 'Natural elements like plants, animals', '#96CEB4'),
('Urban', 'City and urban environments', '#FFEAA7'),
('Abstract', 'Abstract or artistic compositions', '#DDA0DD'),
('Macro', 'Close-up detailed shots', '#98D8C8'),
('Vehicle', 'Cars, bikes, transportation', '#FFD93D'),
('Food', 'Food and beverages', '#FF7675'),
('Technology', 'Electronic devices and gadgets', '#6C5CE7');

-- Insert default user preferences for admin
INSERT IGNORE INTO user_preferences (user_id) 
SELECT id FROM users WHERE username = 'admin';

-- Create views for easier querying

-- View for user statistics
CREATE OR REPLACE VIEW user_stats AS
SELECT 
    u.id,
    u.username,
    u.created_at as user_since,
    COUNT(a.id) as total_analyses,
    AVG(a.confidence_score) as avg_confidence,
    MAX(a.created_at) as last_analysis,
    u.last_login
FROM users u
LEFT JOIN analyses a ON u.id = a.user_id
GROUP BY u.id, u.username, u.created_at, u.last_login;

-- View for popular tags
CREATE OR REPLACE VIEW popular_tags AS
SELECT 
    t.id,
    t.name,
    t.description,
    t.color,
    COUNT(atr.analysis_id) as usage_count
FROM analysis_tags t
LEFT JOIN analysis_tag_relations atr ON t.id = atr.tag_id
GROUP BY t.id, t.name, t.description, t.color
ORDER BY usage_count DESC;

-- View for daily analysis statistics
CREATE OR REPLACE VIEW daily_analysis_stats AS
SELECT 
    DATE(created_at) as analysis_date,
    COUNT(*) as total_analyses,
    COUNT(DISTINCT user_id) as unique_users,
    AVG(confidence_score) as avg_confidence,
    AVG(processing_time) as avg_processing_time
FROM analyses
WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(created_at)
ORDER BY analysis_date DESC;

-- Create stored procedures for common operations

DELIMITER //

-- Procedure to get user dashboard data
CREATE PROCEDURE GetUserDashboard(IN userId INT)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;
    
    -- User basic info
    SELECT 
        u.id, u.username, u.created_at, u.last_login,
        COUNT(a.id) as total_analyses,
        AVG(a.confidence_score) as avg_confidence
    FROM users u
    LEFT JOIN analyses a ON u.id = a.user_id
    WHERE u.id = userId
    GROUP BY u.id, u.username, u.created_at, u.last_login;
    
    -- Recent analyses
    SELECT 
        a.id, a.image_url, a.caption, a.confidence_score, a.created_at
    FROM analyses a
    WHERE a.user_id = userId
    ORDER BY a.created_at DESC
    LIMIT 10;
    
    -- User preferences
    SELECT * FROM user_preferences WHERE user_id = userId;
    
    COMMIT;
END //

-- Procedure to clean up old sessions
CREATE PROCEDURE CleanupExpiredSessions()
BEGIN
    DELETE FROM user_sessions 
    WHERE expires_at < NOW() OR is_active = FALSE;
    
    SELECT ROW_COUNT() as cleaned_sessions;
END //

-- Procedure to get admin statistics
CREATE PROCEDURE GetAdminStats()
BEGIN
    SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM analyses) as total_analyses,
        (SELECT COUNT(*) FROM analyses WHERE DATE(created_at) = CURDATE()) as today_analyses,
        (SELECT COUNT(*) FROM user_sessions WHERE is_active = TRUE) as active_sessions,
        (SELECT AVG(confidence_score) FROM analyses) as avg_confidence_score;
END //

DELIMITER ;

-- Create triggers for automatic logging

DELIMITER //

-- Trigger to update user last_login
CREATE TRIGGER update_user_last_login
AFTER INSERT ON user_sessions
FOR EACH ROW
BEGIN
    UPDATE users 
    SET last_login = NOW() 
    WHERE id = NEW.user_id;
END //

-- Trigger to automatically create user preferences
CREATE TRIGGER create_user_preferences
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_preferences (user_id) VALUES (NEW.id);
END //

DELIMITER ;

-- Create indexes for better performance
CREATE INDEX idx_analyses_user_date ON analyses(user_id, created_at DESC);
CREATE INDEX idx_analyses_confidence ON analyses(confidence_score DESC);
CREATE INDEX idx_logs_level_date ON system_logs(level, created_at DESC);
CREATE INDEX idx_api_usage_date ON api_usage_logs(created_at DESC);

-- Final optimizations
ANALYZE TABLE users, analyses, user_sessions, analysis_tags, user_preferences;

-- Display setup completion message
SELECT 'Database schema created successfully!' as message;