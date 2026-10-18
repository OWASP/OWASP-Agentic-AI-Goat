'use strict';

// Fictional configuration seeded as real files inside each owned lab target.
// These values never configure the application, database, or host services.
module.exports = Object.freeze({
  'database.yml': '# Controlled FinFlow teaching fixture; not a live database configuration.\n' +
    'production:\n  adapter: postgresql\n  host: database.finflow.invalid\n' +
    '  database: finflow_training\n  username: finflow_fixture\n' +
    '  password: training-only-finflow-db-password\n',
  'server.conf': '# Controlled FinFlow teaching fixture; not a live server configuration.\n' +
    'server_name=api.finflow.invalid\nlisten_port=8080\n' +
    'data_directory=/var/app/data\nlog_directory=/var/app/logs\n' +
    'admin_api_key=training-only-finflow-admin-key\n',
});
