'use strict';
const {FILE_FLAGS}=require('../config/legacySensitiveFlags');
const path=require('node:path');
const { SHARED_FILES } = require('../data/sensitiveSharedFixtures');
const { seedMissingLabFiles } = require('./labFixtureSeed');
// Create sensitive files directory structure for the challenge
// Explicit installation/test override; importing never creates or reads fixtures.
const configuredRoot = process.env.LEGACY_SENSITIVE_FILES_ROOT;
if (configuredRoot !== undefined && (!configuredRoot || !path.isAbsolute(configuredRoot)
    || path.resolve(configuredRoot) !== configuredRoot)) {
  throw new TypeError('LEGACY_SENSITIVE_FILES_ROOT must be an absolute normalized directory');
}
const sensitiveFilesDir = configuredRoot || path.join(__dirname, '../sensitive_files');
const publicDir = path.join(sensitiveFilesDir, 'public');
const secretDir = path.join(sensitiveFilesDir, 'secret');
const adminDir = path.join(sensitiveFilesDir, 'admin');
const configDir = path.join(sensitiveFilesDir, 'config');

function createSensitiveFiles() {
  const fixtures = {};
  const writeFixture = (filename, content) => { fixtures[path.relative(sensitiveFilesDir, filename).split(path.sep).join('/')] = content; };
  // Create public files (accessible)
  const publicFiles = {
    'welcome.txt': SHARED_FILES['public/welcome.txt'],
    'info.html': '<!DOCTYPE html><html><body><h1>Public Information</h1><p>This is publicly accessible content.</p></body></html>',
    'readme.md': '# Public Documentation\n\nThis directory contains public files that are safe to access.'
  };

  Object.entries(publicFiles).forEach(([filename, content]) => {
    writeFixture(path.join(publicDir, filename), content);
  });

  // Create secret files (should NOT be accessible)
  const secretFiles = {
    'database_credentials.txt': `DATABASE CREDENTIALS - CONFIDENTIAL
==========================================
Host: localhost
Port: 3306
Username: admin_user
Password: P@ssw0rd123!SecureDB
Database: production_db
Connection String: mysql://admin_user:P@ssw0rd123!SecureDB@localhost:3306/production_db

IMPORTANT: Do NOT share these credentials!
FLAG: ${FILE_FLAGS[0]}`,
    
    'api_keys.json': JSON.stringify({
      openai_api_key: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
      aws_access_key: "AKIA123456789EXAMPLE",
      aws_secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      stripe_secret_key: "sk_live_51Abc123Def456Ghi789Jkl012Mno345Pqr678Stu901Vwx234Yz",
      jwt_secret: "super-secret-jwt-key-do-not-share",
      encryption_key: "AES256-KEY-b8f5e3a1c9d7e2f4a6b8c0d2e4f6a8b0",
      flag: FILE_FLAGS[1]
    }, null, 2),
    
    'employee_ssn.txt': `EMPLOYEE SOCIAL SECURITY NUMBERS - HIGHLY CONFIDENTIAL
========================================================
John Doe - SSN: 123-45-6789 - Salary: $95,000
Jane Smith - SSN: 234-56-7890 - Salary: $120,000
Bob Johnson - SSN: 345-67-8901 - Salary: $85,000
Alice Williams - SSN: 456-78-9012 - Salary: $110,000

WARNING: Unauthorized access is a federal crime!
FLAG: ${FILE_FLAGS[2]}`
  };

  Object.entries(secretFiles).forEach(([filename, content]) => {
    writeFixture(path.join(secretDir, filename), content);
  });

  // Create admin files (should NOT be accessible)
  const adminFiles = {
    'admin_passwords.txt': `ADMINISTRATOR CREDENTIALS
==========================
Super Admin: admin / Admin@2024!SuperSecure
Database Admin: dbadmin / Db@dmin#Pass2024
System Admin: sysadmin / Sys@dmin$2024Secure
Security Admin: secadmin / Sec@dmin&2024Safe

Two-Factor Backup Codes: 1234-5678-9012, 3456-7890-1234

FLAG: ${FILE_FLAGS[3]}`,
    
    'backup_keys.pem': SHARED_FILES['admin/backup_keys.pem']
  };

  Object.entries(adminFiles).forEach(([filename, content]) => {
    writeFixture(path.join(adminDir, filename), content);
  });

  // Create config files (should NOT be accessible)
  const configFiles = {
    'database.config': `# Database Configuration File
# WARNING: This file contains sensitive information

[production]
db_host=prod-db-server.company.com
db_port=5432
db_name=production_database
db_user=prod_admin
db_password=Pr0d@dmin#SecurePass2024!
connection_pool_size=50

[development]
db_host=localhost
db_port=5432
db_name=dev_database
db_user=dev_admin
db_password=Dev@dmin123!

[security]
encryption_algorithm=AES-256-GCM
session_secret=ultra-secret-session-key-987654321
jwt_expiration=3600
max_login_attempts=5

FLAG: ${FILE_FLAGS[5]}`,
    
    'application.properties': `# Application Properties
spring.datasource.url=jdbc:mysql://localhost:3306/appdb
spring.datasource.username=appuser
spring.datasource.password=@ppUs3r#Pass2024!
server.port=8443
server.ssl.key-store=classpath:keystore.jks
server.ssl.key-store-password=k3yst0r3P@ss
server.ssl.key-password=k3yP@ss2024
oauth.client.secret=oauth-secret-key-abc123def456
oauth.client.id=app-client-12345

FLAG: ${FILE_FLAGS[6]}`
  };

  Object.entries(configFiles).forEach(([filename, content]) => {
    writeFixture(path.join(configDir, filename), content);
  });

  // A real protected template makes traversal plus SSI independently reproducible.
  // Missing-only seeding preserves instructor-edited templates on upgrade.
  writeFixture(path.join(secretDir, 'ssi_report.shtml'),
    'Owned teaching report\n<!--#include file="../secret/database_credentials.txt" -->\n');

  seedMissingLabFiles(sensitiveFilesDir, fixtures);
  console.log('✓ Ensured missing sensitive challenge files');
}


module.exports={createSensitiveFiles,sensitiveFilesDir,publicDir,secretDir,adminDir,configDir};

if(require.main===module){
 if(process.argv.length!==3||process.argv[2]!=='--initialize-missing')throw new Error('Use --initialize-missing to explicitly create missing challenge fixtures');
 createSensitiveFiles();
}
