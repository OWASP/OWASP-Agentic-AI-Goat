const { authDb } = require('./authDb');
const { createAdminTables, insertAdminDefaultData } = require('./adminSchema');

// Initialize admin functionality
function initializeAdminDatabase() {
  console.log('🔧 Initializing admin database schema...');

  try {
    // Create admin tables in the auth database
    createAdminTables(authDb);
    console.log('✅ Admin tables created successfully');

    // Insert default admin data
    insertAdminDefaultData(authDb);
    console.log('✅ Default admin data inserted successfully');

    console.log('🎉 Admin database initialization complete!');
    console.log('📋 Default admin accounts:');
    console.log('   - admin@dvaia.local (admin123!@#) - Super Admin');
    console.log('   - administrator@dvaia.local (admin2024$) - Regular Admin');

  } catch (error) {
    console.error('❌ Error initializing admin database:', error);
  }
}

// Run initialization
initializeAdminDatabase();

module.exports = { initializeAdminDatabase };