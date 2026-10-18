if(process.env.PLATFORM_DATABASE_ENGINE==='postgres'){module.exports={engine:'postgres',initialize:()=>require('./postgres/sensitiveLookupDb').initializeSensitiveLookupDb()};}else{
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

/**
 * MySQL-Backed Sensitive Information Disclosure Database
 * 
 * This implements the vulnerable patterns:
 * 1. Directory Traversal via MySQL-backed path resolution
 * 2. SSI Injection via MySQL-stored templates
 * 3. Combined attacks using MySQL as intermediary
 */

class MySQLSensitiveInfoDB {
  constructor() {
    this.pool = null;
    this.config = {
      host: process.env.MYSQL_HOST || 'localhost',
      port: process.env.MYSQL_PORT || 3306,
      user: process.env.MYSQL_USER || 'dvaia_user',
      password: process.env.MYSQL_PASSWORD || 'dvaia_password',
      database: process.env.MYSQL_DATABASE || 'dvaia_sensitive_info',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    };
  }

  async initialize() {
    try {
      // Create connection pool
      this.pool = mysql.createPool(this.config);
      
      console.log('[MySQL Sensitive Info] Connecting to MySQL...');
      
      // Test connection
      const connection = await this.pool.getConnection();
      console.log('[MySQL Sensitive Info] Connected successfully!');
      connection.release();
      
      // Initialize schema
      await this.createSchema();
      
      // Seed vulnerable data
      await this.seedVulnerableData();
      
      console.log('[MySQL Sensitive Info] Database initialized successfully');
      
    } catch (error) {
      console.error('[MySQL Sensitive Info] Initialization error:', error.message);
      console.log('[MySQL Sensitive Info] Will use fallback mode');
      this.pool = null;
    }
  }

  async createSchema() {
    const connection = await this.pool.getConnection();
    
    try {
      // Table 1: File References (for Path Traversal)
      await connection.query(`
        CREATE TABLE IF NOT EXISTS file_references (
          id INT AUTO_INCREMENT PRIMARY KEY,
          reference_key VARCHAR(100) NOT NULL UNIQUE,
          file_path VARCHAR(500) NOT NULL,
          description TEXT,
          access_level ENUM('public', 'restricted', 'secret', 'admin') DEFAULT 'public',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_reference_key (reference_key),
          INDEX idx_access_level (access_level)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);

      // Table 2: Chatbot Templates (for SSI Injection)
      await connection.query(`
        CREATE TABLE IF NOT EXISTS chatbot_templates (
          id INT AUTO_INCREMENT PRIMARY KEY,
          template_name VARCHAR(100) NOT NULL UNIQUE,
          template_content TEXT NOT NULL,
          template_path VARCHAR(500),
          ssi_enabled BOOLEAN DEFAULT TRUE,
          category VARCHAR(50),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_template_name (template_name),
          INDEX idx_category (category)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);

      // Table 3: Chatbot Configuration (metadata)
      await connection.query(`
        CREATE TABLE IF NOT EXISTS chatbot_config (
          id INT AUTO_INCREMENT PRIMARY KEY,
          config_key VARCHAR(100) NOT NULL UNIQUE,
          config_value TEXT NOT NULL,
          config_type ENUM('path', 'template', 'variable', 'setting') DEFAULT 'setting',
          is_sensitive BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_config_key (config_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);

      // Table 4: Exploitation Log
      await connection.query(`
        CREATE TABLE IF NOT EXISTS exploitation_log (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT,
          user_input TEXT,
          query_executed TEXT,
          vulnerability_type VARCHAR(100),
          file_accessed VARCHAR(500),
          flag_captured VARCHAR(200),
          success BOOLEAN DEFAULT FALSE,
          ip_address VARCHAR(45),
          user_agent TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_user_id (user_id),
          INDEX idx_vulnerability_type (vulnerability_type),
          INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);

      console.log('[MySQL] Schema created successfully');
      
    } finally {
      connection.release();
    }
  }

  async seedVulnerableData() {
    const connection = await this.pool.getConnection();
    
    try {
      // Seed File References (Vulnerable to Path Traversal)
      const fileReferences = [
        // Public files
        { key: 'welcome', path: 'public/welcome.txt', level: 'public', desc: 'Welcome message' },
        { key: 'help', path: 'public/help.txt', level: 'public', desc: 'Help documentation' },
        { key: 'info', path: 'public/info.html', level: 'public', desc: 'Information page' },
        
        // Restricted files
        { key: 'user_guide', path: 'restricted/user_guide.pdf', level: 'restricted', desc: 'User guide' },
        { key: 'policy', path: 'restricted/policy.txt', level: 'restricted', desc: 'Security policy' },
        
        // Secret files (FLAGS)
        { key: 'db_creds', path: 'secret/database_credentials.txt', level: 'secret', desc: 'Database credentials' },
        { key: 'api_keys', path: 'secret/api_keys.json', level: 'secret', desc: 'API keys' },
        { key: 'employee_data', path: 'secret/employee_ssn.txt', level: 'secret', desc: 'Employee SSN data' },
        
        // Admin files (FLAGS)
        { key: 'admin_pass', path: 'admin/admin_passwords.txt', level: 'admin', desc: 'Admin passwords' },
        { key: 'admin_secret', path: 'admin/secret.txt', level: 'admin', desc: 'Admin secret data' },
        
        // Config files (FLAGS)
        { key: 'db_config', path: 'config/database.config', level: 'secret', desc: 'Database configuration' },
        { key: 'app_config', path: 'config/application.yml', level: 'secret', desc: 'Application config' }
      ];

      for (const ref of fileReferences) {
        await connection.query(`
          INSERT IGNORE INTO file_references (reference_key, file_path, description, access_level)
          VALUES (?, ?, ?, ?)
        `, [ref.key, ref.path, ref.desc, ref.level]);
      }

      // Seed Chatbot Templates (Vulnerable to SSI Injection)
      const templates = [
        {
          name: 'greeting',
          content: 'Hello! I am your AI assistant. How can I help you today?',
          path: null,
          category: 'general'
        },
        {
          name: 'database_response',
          content: 'Database connection: <!--#echo var="DATABASE_HOST" -->:<!--#echo var="DATABASE_PORT" -->',
          path: null,
          category: 'system'
        },
        {
          name: 'admin_template',
          content: 'Admin Portal - User: <!--#echo var="ADMIN_USER" -->, Pass: <!--#echo var="ADMIN_PASS" -->',
          path: 'templates/admin_response.html',
          category: 'admin'
        },
        {
          name: 'secret_template',
          content: '<!--#include virtual="secret/api_keys.json" -->',
          path: 'templates/secret_data.html',
          category: 'secret'
        },
        {
          name: 'config_template',
          content: 'Configuration: <!--#echo var="SECRET_KEY" -->',
          path: 'templates/config_response.html',
          category: 'config'
        },
        {
          name: 'file_include',
          content: '<!--#include file="admin/admin_passwords.txt" -->',
          path: null,
          category: 'admin'
        }
      ];

      for (const tpl of templates) {
        await connection.query(`
          INSERT IGNORE INTO chatbot_templates (template_name, template_content, template_path, category)
          VALUES (?, ?, ?, ?)
        `, [tpl.name, tpl.content, tpl.path, tpl.category]);
      }

      // Seed Configuration (Vulnerable to Information Disclosure)
      const configs = [
        { key: 'DATABASE_HOST', value: 'mysql.internal.local', type: 'variable', sensitive: true },
        { key: 'DATABASE_PORT', value: '3306', type: 'variable', sensitive: false },
        { key: 'DATABASE_PASSWORD', value: 'Sup3rS3cr3t!Pass2024', type: 'variable', sensitive: true },
        { key: 'ADMIN_USER', value: 'admin', type: 'variable', sensitive: true },
        { key: 'ADMIN_PASS', value: 'Admin@12345!', type: 'variable', sensitive: true },
        { key: 'SECRET_KEY', value: 'sk-ultra-secret-key-abc123xyz789', type: 'variable', sensitive: true },
        { key: 'API_KEY', value: 'api_key_12345_abcdef', type: 'variable', sensitive: true },
        { key: 'JWT_SECRET', value: 'jwt_secret_token_987654', type: 'variable', sensitive: true },
        { key: 'base_path', value: 'server/sensitive_files/', type: 'path', sensitive: false },
        { key: 'template_path', value: 'server/templates/', type: 'path', sensitive: false }
      ];

      for (const cfg of configs) {
        await connection.query(`
          INSERT IGNORE INTO chatbot_config (config_key, config_value, config_type, is_sensitive)
          VALUES (?, ?, ?, ?)
        `, [cfg.key, cfg.value, cfg.type, cfg.sensitive]);
      }

      console.log('[MySQL] Vulnerable data seeded successfully');
      
    } finally {
      connection.release();
    }
  }

  /**
   * VULNERABLE: Path Traversal via MySQL
   * User input directly concatenated into SQL query
   */
  async getFilePathByReference(referenceKey, userInput = null) {
    if (!this.pool) return null;
    
    try {
      // VULNERABILITY: SQL Injection + Path Traversal
      // User input can manipulate the query to return arbitrary paths
      let query;
      if (userInput && userInput.includes("'")) {
        // If user input contains SQL injection attempts, use it directly
        query = `SELECT file_path FROM file_references WHERE reference_key = '${referenceKey}' OR '1'='1' LIMIT 1`;
      } else {
        query = `SELECT file_path FROM file_references WHERE reference_key = ?`;
      }
      
      const [rows] = userInput && userInput.includes("'") 
        ? await this.pool.query(query)
        : await this.pool.query(query, [referenceKey]);
      
      if (rows.length > 0) {
        return rows[0].file_path;
      }
      
      // VULNERABILITY: If not found, try direct user input as path
      return userInput || referenceKey;
      
    } catch (error) {
      console.error('[MySQL] Query error:', error.message);
      return null;
    }
  }

  /**
   * VULNERABLE: SSI Injection via MySQL
   * Templates with SSI directives stored in database
   */
  async getTemplateByName(templateName, userInput = null) {
    if (!this.pool) return null;
    
    try {
      // VULNERABILITY: SQL Injection in template lookup
      let query;
      if (userInput && (userInput.includes("'") || userInput.includes("UNION"))) {
        query = `SELECT template_content, ssi_enabled FROM chatbot_templates WHERE template_name = '${templateName}' OR 1=1`;
      } else {
        query = `SELECT template_content, ssi_enabled FROM chatbot_templates WHERE template_name = ?`;
      }
      
      const [rows] = userInput && userInput.includes("'")
        ? await this.pool.query(query)
        : await this.pool.query(query, [templateName]);
      
      if (rows.length > 0) {
        return {
          content: rows[0].template_content,
          ssiEnabled: rows[0].ssi_enabled
        };
      }
      
      return null;
      
    } catch (error) {
      console.error('[MySQL] Template query error:', error.message);
      return null;
    }
  }

  /**
   * Get configuration variable (for SSI processing)
   */
  async getConfigValue(configKey) {
    if (!this.pool) return null;
    
    try {
      const [rows] = await this.pool.query(
        `SELECT config_value FROM chatbot_config WHERE config_key = ?`,
        [configKey]
      );
      
      return rows.length > 0 ? rows[0].config_value : null;
      
    } catch (error) {
      console.error('[MySQL] Config query error:', error.message);
      return null;
    }
  }

  /**
   * Log exploitation attempt
   */
  async logExploitation(data) {
    if (!this.pool) return;
    
    try {
      await this.pool.query(`
        INSERT INTO exploitation_log 
        (user_id, user_input, query_executed, vulnerability_type, file_accessed, flag_captured, success, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        data.userId || 1,
        data.userInput,
        data.queryExecuted,
        data.vulnerabilityType,
        data.fileAccessed,
        data.flagCaptured,
        data.success,
        data.ipAddress,
        data.userAgent
      ]);
      
    } catch (error) {
      console.error('[MySQL] Logging error:', error.message);
    }
  }

  /**
   * Get exploitation statistics
   */
  async getExploitationStats() {
    if (!this.pool) return null;
    
    try {
      const [stats] = await this.pool.query(`
        SELECT 
          COUNT(*) as total_attempts,
          SUM(success) as successful_exploits,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(DISTINCT file_accessed) as files_accessed,
          vulnerability_type,
          COUNT(*) as count
        FROM exploitation_log
        GROUP BY vulnerability_type
      `);
      
      return stats;
      
    } catch (error) {
      console.error('[MySQL] Stats query error:', error.message);
      return null;
    }
  }

  /**
   * Check if MySQL is available
   */
  isAvailable() {
    return this.pool !== null;
  }

  /**
   * Close connection pool
   */
  async close() {
    if (this.pool) {
      await this.pool.end();
      console.log('[MySQL Sensitive Info] Connection pool closed');
    }
  }
}

// Export singleton instance
const mysqlDB = new MySQLSensitiveInfoDB();

module.exports = mysqlDB;


}
