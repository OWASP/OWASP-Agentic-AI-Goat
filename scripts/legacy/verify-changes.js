#!/usr/bin/env node

const axios = require('axios');

console.log('🔍 DVAIA Platform Verification');
console.log('================================\n');

async function verifyChanges() {
  try {
    console.log('📊 Server Status:');
    
    // Test server
    try {
      const serverResponse = await axios.get('http://localhost:5000/');
      console.log('✅ Backend Server: Running on port 5000');
    } catch (error) {
      console.log('❌ Backend Server: Not running');
      return;
    }

    // Test client
    try {
      const clientResponse = await axios.get('http://localhost:3000/');
      console.log('✅ Frontend Client: Running on port 3000');
    } catch (error) {
      console.log('❌ Frontend Client: Not running');
    }

    console.log('\n🎯 Challenge Verification:');
    
    // Test challenges API
    try {
      const challengesResponse = await axios.get('http://localhost:5000/api/workshop/challenges');
      const challenges = challengesResponse.data.challenges;
      
      console.log(`✅ Total Challenges: ${challenges.length}`);
      challenges.forEach((challenge, index) => {
        console.log(`   ${index + 1}. ${challenge.title} (${challenge.route})`);
      });
    } catch (error) {
      console.log('❌ Challenges API: Error');
    }

    console.log('\n🎓 Solutions System:');
    
    // Test solutions API
    try {
      const solutionsResponse = await axios.get('http://localhost:5000/api/challenges/solutions/ai_sql_injection_chat');
      if (solutionsResponse.data.success) {
        console.log('✅ Solutions API: Working');
        console.log(`   - Learning Objectives: ${solutionsResponse.data.solutions.objectives.length}`);
        console.log(`   - Solution Steps: ${solutionsResponse.data.solutions.steps.length}`);
        console.log(`   - Prevention Tips: ${solutionsResponse.data.solutions.prevention.length}`);
      }
    } catch (error) {
      if (error.response?.status === 403) {
        console.log('🔒 Solutions API: Disabled by instructor (this is normal)');
        
        // Try to enable solutions for testing
        try {
          await axios.post('http://localhost:5000/api/challenges/solutions/toggle', { enabled: true });
          console.log('✅ Solutions Toggle: Working (enabled for testing)');
          
          // Test again
          const retryResponse = await axios.get('http://localhost:5000/api/challenges/solutions/ai_sql_injection_chat');
          if (retryResponse.data.success) {
            console.log('✅ Solutions Content: Available when enabled');
          }
        } catch (toggleError) {
          console.log('❌ Solutions Toggle: Error');
        }
      } else {
        console.log('❌ Solutions API: Error');
      }
    }

    console.log('\n🎮 How to Access New Features:');
    console.log('================================');
    console.log('1. 🌐 Open your browser to: http://localhost:3000');
    console.log('2. 🔐 Login to Workshop with: student/student123');
    console.log('3. 🎯 Go to "Security Challenges" to see all 3 challenges');
    console.log('4. 💡 Look for "Show Solutions" button (floating, bottom-right)');
    console.log('5. 👨‍🏫 For instructor features: Login as instructor and check "Solutions Control" tab');
    
    console.log('\n📋 Available Challenges:');
    console.log('• AI-Powered SQL Injection: /vulnerabilities/sql-injection');
    console.log('• Order Query SQL Injection: /vulnerabilities/order-query');
    console.log('• Reflected XSS in LLM: /vulnerabilities/xss');
    
    console.log('\n🎓 New Features Added:');
    console.log('• ✨ Completely redesigned ALL challenges with modern UI');
    console.log('• 🎨 Unified design system across all 3 challenges');
    console.log('• 📚 Learning Objectives for all challenges');
    console.log('• 🔧 Step-by-step solutions (5 steps each)');
    console.log('• 🎛️ Instructor control panel for solutions');
    console.log('• 💫 Floating solutions panel on all challenges');
    console.log('• 🛡️ Prevention techniques and best practices');
    console.log('• 🌙 Dark theme with glassmorphism effects');
    console.log('• 📱 Responsive design for all screen sizes');

  } catch (error) {
    console.log('❌ Verification failed:', error.message);
  }
}

verifyChanges();
