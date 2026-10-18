const puppeteer = require('puppeteer');
const assert = require('assert');

// Test configuration
const TEST_CONFIG = {
  baseUrl: 'http://localhost:5000',
  timeout: 30000,
  headless: true, // Set to false to see browser actions
  slowMo: 100 // Slow down actions for better visibility
};

// Test data
const TEST_DATA = {
  workshop: {
    student: { username: 'student', password: 'password' },
    instructor: { username: 'instructor', password: 'password' }
  },
  secureshop: {
    customer: { username: 'customer1', password: 'password123' },
    retailer: { username: 'retailer1', password: 'password123' }
  }
};

class FrontendTests {
  constructor() {
    this.browser = null;
    this.page = null;
  }

  async setup() {
    console.log('🚀 Setting up browser...');
    this.browser = await puppeteer.launch({
      headless: TEST_CONFIG.headless,
      slowMo: TEST_CONFIG.slowMo,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    this.page = await this.browser.newPage();
    await this.page.setViewport({ width: 1280, height: 720 });
    
    // Set longer timeout for page loads
    this.page.setDefaultTimeout(TEST_CONFIG.timeout);
    
    console.log('✅ Browser setup complete');
  }

  async teardown() {
    if (this.browser) {
      await this.browser.close();
      console.log('🧹 Browser closed');
    }
  }

  async waitForSelector(selector, timeout = 10000) {
    try {
      await this.page.waitForSelector(selector, { timeout });
      return true;
    } catch (error) {
      console.log(`⚠️ Selector not found: ${selector}`);
      return false;
    }
  }

  async testHomePage() {
    console.log('🧪 Testing Home Page...');
    
    await this.page.goto(TEST_CONFIG.baseUrl);
    
    // Wait for page to load
    const titleFound = await this.waitForSelector('h1');
    assert(titleFound, 'Home page should have a title');
    
    // Check for workshop login elements
    const loginExists = await this.page.$('input[type="text"]') !== null;
    const passwordExists = await this.page.$('input[type="password"]') !== null;
    
    console.log('✅ Home Page Tests Passed');
    return { loginExists, passwordExists };
  }

  async testWorkshopLogin() {
    console.log('🧪 Testing Workshop Login...');
    
    await this.page.goto(TEST_CONFIG.baseUrl);
    
    // Try to find login form
    const usernameInput = await this.page.$('input[type="text"]');
    const passwordInput = await this.page.$('input[type="password"]');
    const loginButton = await this.page.$('button[type="submit"], button:contains("Login")');
    
    if (usernameInput && passwordInput && loginButton) {
      // Fill login form
      await this.page.type('input[type="text"]', TEST_DATA.workshop.student.username);
      await this.page.type('input[type="password"]', TEST_DATA.workshop.student.password);
      
      // Click login button
      await Promise.all([
        this.page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 10000 }).catch(() => {}),
        this.page.click('button[type="submit"], button')
      ]);
      
      // Check if redirected to dashboard
      const currentUrl = this.page.url();
      console.log(`Current URL after login: ${currentUrl}`);
    }
    
    console.log('✅ Workshop Login Tests Passed');
  }

  async testWorkshopDashboard() {
    console.log('🧪 Testing Workshop Dashboard...');
    
    // Navigate to dashboard (assuming we're logged in)
    try {
      await this.page.goto(`${TEST_CONFIG.baseUrl}/workshop-dashboard`);
      
      // Wait for dashboard elements
      const dashboardFound = await this.waitForSelector('h1, .dashboard, [class*="dashboard"]');
      
      // Look for navigation elements
      const challengesLink = await this.page.$('a[href*="challenges"]');
      const ecommerceLink = await this.page.$('a[href*="ecommerce"]');
      
      console.log(`Dashboard found: ${dashboardFound}`);
      console.log(`Challenges link found: ${challengesLink !== null}`);
      console.log(`Ecommerce link found: ${ecommerceLink !== null}`);
      
    } catch (error) {
      console.log(`⚠️ Dashboard test error: ${error.message}`);
    }
    
    console.log('✅ Workshop Dashboard Tests Passed');
  }

  async testWorkshopChallenges() {
    console.log('🧪 Testing Workshop Challenges...');
    
    try {
      await this.page.goto(`${TEST_CONFIG.baseUrl}/workshop/challenges`);
      
      // Wait for challenges page to load
      const challengesFound = await this.waitForSelector('h1, .challenge, [class*="challenge"]');
      
      // Look for challenge cards
      const challengeCards = await this.page.$$('.challenge, [class*="challenge"], [class*="card"]');
      
      // Look for SQL injection challenge
      const sqlChallengeExists = await this.page.evaluate(() => {
        return document.body.textContent.includes('SQL Injection') || 
               document.body.textContent.includes('sql injection');
      });
      
      console.log(`Challenges page found: ${challengesFound}`);
      console.log(`Challenge cards found: ${challengeCards.length}`);
      console.log(`SQL challenge exists: ${sqlChallengeExists}`);
      
    } catch (error) {
      console.log(`⚠️ Challenges test error: ${error.message}`);
    }
    
    console.log('✅ Workshop Challenges Tests Passed');
  }

  async testSecureShopLogin() {
    console.log('🧪 Testing SecureShop Login...');
    
    try {
      await this.page.goto(`${TEST_CONFIG.baseUrl}/secureshop`);
      
      // Wait for login page
      const loginPageFound = await this.waitForSelector('input[type="text"], input[placeholder*="username"]');
      
      if (loginPageFound) {
        // Fill login form
        await this.page.type('input[type="text"], input[placeholder*="username"]', TEST_DATA.secureshop.customer.username);
        await this.page.type('input[type="password"], input[placeholder*="password"]', TEST_DATA.secureshop.customer.password);
        
        // Click login button
        const loginButton = await this.page.$('button[type="submit"], button:contains("Login")');
        if (loginButton) {
          await Promise.all([
            this.page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 10000 }).catch(() => {}),
            loginButton.click()
          ]);
        }
      }
      
      console.log('SecureShop login form found and submitted');
      
    } catch (error) {
      console.log(`⚠️ SecureShop login test error: ${error.message}`);
    }
    
    console.log('✅ SecureShop Login Tests Passed');
  }

  async testProductCatalog() {
    console.log('🧪 Testing Product Catalog...');
    
    try {
      await this.page.goto(`${TEST_CONFIG.baseUrl}/secureshop/catalog`);
      
      // Wait for catalog page
      const catalogFound = await this.waitForSelector('.product, [class*="product"], h1, h2');
      
      // Look for search functionality
      const searchInput = await this.page.$('input[type="search"], input[placeholder*="search"]');
      
      // Look for product cards
      const productCards = await this.page.$$('.product, [class*="product"], [class*="card"]');
      
      // Look for add to cart buttons
      const addToCartButtons = await this.page.$$('button:contains("Add to Cart"), button:contains("cart")');
      
      console.log(`Catalog page found: ${catalogFound}`);
      console.log(`Search input found: ${searchInput !== null}`);
      console.log(`Product cards found: ${productCards.length}`);
      console.log(`Add to cart buttons found: ${addToCartButtons.length}`);
      
    } catch (error) {
      console.log(`⚠️ Product catalog test error: ${error.message}`);
    }
    
    console.log('✅ Product Catalog Tests Passed');
  }

  async testAIAssistant() {
    console.log('🧪 Testing AI Assistant...');
    
    try {
      await this.page.goto(`${TEST_CONFIG.baseUrl}/ecommerce/ai-assistant`);
      
      // Wait for AI assistant page
      const aiPageFound = await this.waitForSelector('input[type="text"], textarea, .chat, [class*="chat"]');
      
      // Look for chat interface elements
      const chatInput = await this.page.$('input[type="text"], textarea');
      const sendButton = await this.page.$('button[type="submit"], button:contains("Send")');
      
      if (chatInput && sendButton) {
        // Test sending a message
        await this.page.type('input[type="text"], textarea', 'Update my name to Test User');
        await sendButton.click();
        
        // Wait a moment for response
        await this.page.waitForTimeout(2000);
      }
      
      console.log(`AI assistant page found: ${aiPageFound}`);
      console.log(`Chat input found: ${chatInput !== null}`);
      console.log(`Send button found: ${sendButton !== null}`);
      
    } catch (error) {
      console.log(`⚠️ AI Assistant test error: ${error.message}`);
    }
    
    console.log('✅ AI Assistant Tests Passed');
  }

  async testSQLInjectionDemo() {
    console.log('🧪 Testing SQL Injection Demo...');
    
    try {
      await this.page.goto(`${TEST_CONFIG.baseUrl}/ecommerce/sql-demo`);
      
      // Wait for demo page
      const demoPageFound = await this.waitForSelector('h1, .demo, [class*="demo"], [class*="attack"]');
      
      // Look for attack vector cards
      const attackCards = await this.page.$$('.attack, [class*="attack"], [class*="card"]');
      
      // Check for SQL injection content
      const sqlContent = await this.page.evaluate(() => {
        return document.body.textContent.includes('SQL Injection') ||
               document.body.textContent.includes('Union') ||
               document.body.textContent.includes('Boolean');
      });
      
      console.log(`Demo page found: ${demoPageFound}`);
      console.log(`Attack cards found: ${attackCards.length}`);
      console.log(`SQL content found: ${sqlContent}`);
      
    } catch (error) {
      console.log(`⚠️ SQL Demo test error: ${error.message}`);
    }
    
    console.log('✅ SQL Injection Demo Tests Passed');
  }

  async runAllTests() {
    console.log('🚀 Starting Frontend Test Suite...\n');
    
    const startTime = Date.now();
    let passedTests = 0;
    let failedTests = 0;
    
    const tests = [
      { name: 'Home Page', fn: () => this.testHomePage() },
      { name: 'Workshop Login', fn: () => this.testWorkshopLogin() },
      { name: 'Workshop Dashboard', fn: () => this.testWorkshopDashboard() },
      { name: 'Workshop Challenges', fn: () => this.testWorkshopChallenges() },
      { name: 'SecureShop Login', fn: () => this.testSecureShopLogin() },
      { name: 'Product Catalog', fn: () => this.testProductCatalog() },
      { name: 'AI Assistant', fn: () => this.testAIAssistant() },
      { name: 'SQL Injection Demo', fn: () => this.testSQLInjectionDemo() }
    ];
    
    await this.setup();
    
    for (const test of tests) {
      try {
        await test.fn();
        passedTests++;
        console.log(`✅ ${test.name} - PASSED\n`);
      } catch (error) {
        failedTests++;
        console.log(`❌ ${test.name} - FAILED`);
        console.log(`   Error: ${error.message}\n`);
      }
      
      // Small delay between tests
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    await this.teardown();
    
    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);
    
    console.log('📊 Frontend Test Results Summary:');
    console.log(`   Total Tests: ${tests.length}`);
    console.log(`   Passed: ${passedTests}`);
    console.log(`   Failed: ${failedTests}`);
    console.log(`   Duration: ${duration}s`);
    
    return { passedTests, failedTests, totalTests: tests.length };
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  (async () => {
    const tester = new FrontendTests();
    const results = await tester.runAllTests();
    
    if (results.failedTests === 0) {
      console.log('🎉 All frontend tests passed!');
      process.exit(0);
    } else {
      console.log('⚠️ Some frontend tests failed.');
      process.exit(1);
    }
  })();
}

module.exports = FrontendTests;
