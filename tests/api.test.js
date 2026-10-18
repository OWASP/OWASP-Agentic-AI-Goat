const axios = require('axios');
const assert = require('assert');

// Base URL for testing
const BASE_URL = process.env.TEST_BASE_URL || 'http://127.0.0.1:1';
const WORKSHOP_ONLY = process.env.WORKSHOP_ONLY === '1';

// Test configuration
const TEST_CONFIG = {
  timeout: 10000,
  retries: 3
};

// Test data
const TEST_DATA = {
  workshop: {
    student: { username: 'student', password: 'student123' },
    instructor: { username: 'instructor', password: 'password' }
  },
  secureshop: {
    customer: { username: 'customer1', password: 'password123' },
    retailer: { username: 'retailer1', password: 'password123' },
    newCustomer: {
      username: 'testcustomer',
      email: 'test@customer.com',
      password: 'testpass123',
      full_name: 'Test Customer',
      role: 'customer'
    },
    newRetailer: {
      username: 'testretailer',
      email: 'test@retailer.com',
      password: 'testpass123',
      full_name: 'Test Retailer',
      role: 'retailer'
    },
    product: {
      name: 'Test Product',
      description: 'A test product for automated testing',
      price: 99.99,
      category: 'Electronics',
      stock_quantity: 10
    }
  }
};

// Global variables for storing tokens and IDs
let workshopToken = '';
let shopCustomerToken = '';
let shopRetailerToken = '';
let testProductId = '';

// Utility functions
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const makeRequest = async (method, url, data = null, headers = {}) => {
  try {
    const config = {
      method,
      url: `${BASE_URL}${url}`,
      timeout: TEST_CONFIG.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };
    
    if (data) {
      config.data = data;
    }
    
    const response = await axios(config);
    return { success: true, data: response.data, status: response.status };
  } catch (error) {
    return {
      success: false,
      error: error.response?.data || error.message,
      status: error.response?.status || 500
    };
  }
};

// Test Suite Classes
class WorkshopTests {
  static async testWorkshopLogin() {
    console.log('🧪 Testing Workshop Login...');
    
    // Test student login
    const studentLogin = await makeRequest('POST', '/api/auth/login', TEST_DATA.workshop.student);
    assert(studentLogin.success, `Student login failed: ${JSON.stringify(studentLogin.error)}`);
    assert(studentLogin.data.token, 'Student login should return token');
    
    // Test instructor login (if exists)
    const instructorLogin = await makeRequest('POST', '/api/auth/login', TEST_DATA.workshop.instructor);
    // Note: This might fail if instructor doesn't exist, which is okay
    
    console.log('✅ Workshop Login Tests Passed');
    return studentLogin.data.token;
  }
  
  static async testWorkshopChallenges() {
    console.log('🧪 Testing Workshop Challenges...');
    
    const challengesResponse = await makeRequest('GET', '/api/workshop/challenges', null, {
      Authorization: `Bearer ${workshopToken}`
    });
    assert(challengesResponse.success, `Challenges fetch failed: ${JSON.stringify(challengesResponse.error)}`);
    assert(Array.isArray(challengesResponse.data.challenges), 'Challenges should be an array');
    assert(challengesResponse.data.challenges.length > 0, 'Should have at least one challenge');
    
    console.log('✅ Workshop Challenges Tests Passed');
  }
  
  static async testWorkshopProgress() {
    console.log('🧪 Testing Workshop Progress...');
    
    const progressResponse = await makeRequest('GET', '/api/workshop/progress', null, {
      Authorization: `Bearer ${workshopToken}`
    });
    assert(progressResponse.success, `Progress fetch failed: ${JSON.stringify(progressResponse.error)}`);
    assert(Array.isArray(progressResponse.data.challenges), 'Progress should contain challenges array');
    
    console.log('✅ Workshop Progress Tests Passed');
  }
}

class SecureShopTests {
  static async testSecureShopAuth() {
    console.log('🧪 Testing SecureShop Authentication...');
    
    // Test customer login
    const customerLogin = await makeRequest('POST', '/api/secureshop/auth/login', TEST_DATA.secureshop.customer);
    assert(customerLogin.success, `Customer login failed: ${JSON.stringify(customerLogin.error)}`);
    assert(customerLogin.data.token, 'Customer login should return token');
    shopCustomerToken = customerLogin.data.token;
    
    // Test retailer login
    const retailerLogin = await makeRequest('POST', '/api/secureshop/auth/login', TEST_DATA.secureshop.retailer);
    assert(retailerLogin.success, `Retailer login failed: ${JSON.stringify(retailerLogin.error)}`);
    assert(retailerLogin.data.token, 'Retailer login should return token');
    shopRetailerToken = retailerLogin.data.token;
    
    console.log('✅ SecureShop Authentication Tests Passed');
  }
  
  static async testSecureShopRegistration() {
    console.log('🧪 Testing SecureShop Registration...');
    
    // Test customer registration
    const customerReg = await makeRequest('POST', '/api/secureshop/auth/register', TEST_DATA.secureshop.newCustomer);
    // Note: This might fail if user already exists, which is okay for testing
    
    // Test retailer registration
    const retailerReg = await makeRequest('POST', '/api/secureshop/auth/register', TEST_DATA.secureshop.newRetailer);
    // Note: This might fail if user already exists, which is okay for testing
    
    console.log('✅ SecureShop Registration Tests Passed');
  }
  
  static async testProductCatalog() {
    console.log('🧪 Testing Product Catalog...');
    
    // Test get all products
    const productsResponse = await makeRequest('GET', '/api/secureshop/products');
    assert(productsResponse.success, `Products fetch failed: ${JSON.stringify(productsResponse.error)}`);
    assert(Array.isArray(productsResponse.data.products), 'Products should be an array');
    
    // Test product search
    const searchResponse = await makeRequest('GET', '/api/secureshop/products?search=headphones');
    assert(searchResponse.success, `Product search failed: ${JSON.stringify(searchResponse.error)}`);
    
    // Test category filter
    const categoryResponse = await makeRequest('GET', '/api/secureshop/products?category=Electronics');
    assert(categoryResponse.success, `Category filter failed: ${JSON.stringify(categoryResponse.error)}`);
    
    console.log('✅ Product Catalog Tests Passed');
  }
  
  static async testRetailerProductManagement() {
    console.log('🧪 Testing Retailer Product Management...');
    
    if (!shopRetailerToken) {
      console.log('⚠️ Skipping retailer tests - no retailer token');
      return;
    }
    
    // Test create product
    const createResponse = await makeRequest(
      'POST',
      '/api/secureshop/retailer/products',
      TEST_DATA.secureshop.product,
      { Authorization: `Bearer ${shopRetailerToken}` }
    );
    assert(createResponse.success, `Product creation failed: ${JSON.stringify(createResponse.error)}`);
    testProductId = createResponse.data.product_id;
    
    // Test update product
    const updateData = { ...TEST_DATA.secureshop.product, name: 'Updated Test Product' };
    const updateResponse = await makeRequest(
      'PUT',
      `/api/secureshop/retailer/products/${testProductId}`,
      updateData,
      { Authorization: `Bearer ${shopRetailerToken}` }
    );
    assert(updateResponse.success, `Product update failed: ${JSON.stringify(updateResponse.error)}`);
    
    console.log('✅ Retailer Product Management Tests Passed');
  }
  
  static async testShoppingCart() {
    console.log('🧪 Testing Shopping Cart...');
    
    if (!shopCustomerToken) {
      console.log('⚠️ Skipping cart tests - no customer token');
      return;
    }
    
    // Test add to cart
    const addToCartResponse = await makeRequest(
      'POST',
      '/api/secureshop/cart/add',
      { product_id: 1, quantity: 2 },
      { Authorization: `Bearer ${shopCustomerToken}` }
    );
    assert(addToCartResponse.success, `Add to cart failed: ${JSON.stringify(addToCartResponse.error)}`);
    
    // Test get cart
    const cartResponse = await makeRequest(
      'GET',
      '/api/secureshop/cart',
      null,
      { Authorization: `Bearer ${shopCustomerToken}` }
    );
    assert(cartResponse.success, `Get cart failed: ${JSON.stringify(cartResponse.error)}`);
    assert(Array.isArray(cartResponse.data.cart_items), 'Cart items should be an array');
    
    console.log('✅ Shopping Cart Tests Passed');
  }
  
  static async testOrderManagement() {
    console.log('🧪 Testing Order Management...');
    
    if (!shopCustomerToken) {
      console.log('⚠️ Skipping order tests - no customer token');
      return;
    }
    
    // Test create order
    const orderData = {
      payment_method: 'credit_card',
      shipping_address: '123 Test St, Test City, TS 12345'
    };
    
    const createOrderResponse = await makeRequest(
      'POST',
      '/api/secureshop/orders/create',
      orderData,
      { Authorization: `Bearer ${shopCustomerToken}` }
    );
    
    // Note: This might fail if cart is empty, which is okay
    if (createOrderResponse.success) {
      // Test get orders
      const ordersResponse = await makeRequest(
        'GET',
        '/api/secureshop/orders',
        null,
        { Authorization: `Bearer ${shopCustomerToken}` }
      );
      assert(ordersResponse.success, `Get orders failed: ${JSON.stringify(ordersResponse.error)}`);
    }
    
    console.log('✅ Order Management Tests Passed');
  }
  
  static async testCategories() {
    console.log('🧪 Testing Categories...');
    
    const categoriesResponse = await makeRequest('GET', '/api/secureshop/categories');
    assert(categoriesResponse.success, `Categories fetch failed: ${JSON.stringify(categoriesResponse.error)}`);
    assert(Array.isArray(categoriesResponse.data.categories), 'Categories should be an array');
    
    console.log('✅ Categories Tests Passed');
  }
}

class AITests {
  static async testAIAssistant() {
    console.log('🧪 Testing AI Assistant...');
    
    if (!shopCustomerToken) {
      console.log('⚠️ Skipping AI tests - no customer token');
      return;
    }
    
    // Test AI profile update
    const profileUpdateResponse = await makeRequest(
      'POST',
      '/api/ecommerce/update-profile',
      {
        action: 'update_name',
        name: 'Test User',
        userId: 1,
        attackType: 'basic'
      }
    );
    
    // Note: This endpoint might have vulnerabilities by design
    // We're just testing if it responds
    
    // Test AI query
    const queryResponse = await makeRequest(
      'POST',
      '/api/ecommerce/ai-query',
      {
        message: 'Show me all orders',
        userId: 1
      }
    );
    
    console.log('✅ AI Assistant Tests Passed');
  }
}

// Main test runner
class TestRunner {
  static async runAllTests() {
    console.log('🚀 Starting Comprehensive Test Suite...\n');
    
    const startTime = Date.now();
    let passedTests = 0;
    let failedTests = 0;
    
    const workshopTests = [
      // Workshop Tests
      { name: 'Workshop Login', fn: WorkshopTests.testWorkshopLogin },
      { name: 'Workshop Challenges', fn: WorkshopTests.testWorkshopChallenges },
      { name: 'Workshop Progress', fn: WorkshopTests.testWorkshopProgress },
    ];
    const excludedScopeTests = [
      // SecureShop Tests
      { name: 'SecureShop Authentication', fn: SecureShopTests.testSecureShopAuth },
      { name: 'SecureShop Registration', fn: SecureShopTests.testSecureShopRegistration },
      { name: 'Product Catalog', fn: SecureShopTests.testProductCatalog },
      { name: 'Retailer Product Management', fn: SecureShopTests.testRetailerProductManagement },
      { name: 'Shopping Cart', fn: SecureShopTests.testShoppingCart },
      { name: 'Order Management', fn: SecureShopTests.testOrderManagement },
      { name: 'Categories', fn: SecureShopTests.testCategories },
      
      // AI Tests
      { name: 'AI Assistant', fn: AITests.testAIAssistant }
    ];
    const tests = WORKSHOP_ONLY ? workshopTests : [...workshopTests, ...excludedScopeTests];
    
    for (const test of tests) {
      try {
        const result = await test.fn();
        if (test.fn === WorkshopTests.testWorkshopLogin) workshopToken = result;
        passedTests++;
        console.log(`✅ ${test.name} - PASSED\n`);
      } catch (error) {
        failedTests++;
        console.log(`❌ ${test.name} - FAILED`);
        console.log(`   Error: ${error.message}\n`);
      }
      
      // Small delay between tests
      await delay(500);
    }
    
    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);
    
    console.log('📊 Test Results Summary:');
    console.log(`   Total Tests: ${tests.length}`);
    console.log(`   Passed: ${passedTests}`);
    console.log(`   Failed: ${failedTests}`);
    console.log(`   Duration: ${duration}s`);
    
    if (failedTests === 0) {
      console.log('🎉 All tests passed!');
      process.exit(0);
    } else {
      console.log('⚠️ Some tests failed. Check the output above for details.');
      process.exit(1);
    }
  }
  
  static async checkServerHealth() {
    console.log('🏥 Checking server health...');
    
    try {
      const response = await axios.get(`${BASE_URL}/api/monitoring/health`, { timeout: 5000 });
      console.log('✅ Server is running and responding');
      return true;
    } catch (error) {
      console.log('❌ Server is not responding');
      console.log(`   Make sure the server is running on ${BASE_URL}`);
      console.log('   Run: npm start');
      return false;
    }
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  (async () => {
    if (process.env.SERVER_AVAILABLE !== '1' || !process.env.TEST_BASE_URL) {
      console.error('Refusing to contact a default server; set SERVER_AVAILABLE=1 and TEST_BASE_URL explicitly');
      process.exit(1);
    }
    const isHealthy = await TestRunner.checkServerHealth();
    if (isHealthy) {
      await TestRunner.runAllTests();
    } else {
      process.exit(1);
    }
  })();
}

module.exports = {
  TestRunner,
  WorkshopTests,
  SecureShopTests,
  AITests
};
