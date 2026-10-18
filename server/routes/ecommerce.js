const express = require('express');
const router = express.Router();
const store = require('../database/legacyChallengeStore');
const logger = require('../utils/logger');
const { describeLegacySqlResult, legacySqlEducationalNote } = require('../services/legacySqlPresentation');
const platformOwner=req=>req.legacyPlatformMutation?.ownerId||null;
const {legacyPlatformMutationMiddleware}=require('../services/legacyPlatformMutationLifecycle');

// Vulnerable product search with SQL injection
router.get('/products', (req, res) => {
  const { search, category } = req.query;
  
  let sql = 'SELECT * FROM products WHERE 1=1';
  const params = [];
  
  // Vulnerable: Direct string concatenation for search
  if (search) {
    sql += ` AND (name LIKE '%${search}%' OR description LIKE '%${search}%')`;
  }
  
  // Slightly less vulnerable: parameterized for category
  if (category) {
    sql += store.engine === 'postgres' ? ' AND category = $1' : ' AND category = ?';
    params.push(category);
  }
  
  sql += ' ORDER BY name';
  
  store.searchCommerceProducts(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ 
        error: 'Database error', 
        details: err.message // Vulnerable: exposing error details
      });
    }
    
    res.json({
      success: true,
      products: rows,
      query: search, // Vulnerable: reflecting user input
      sql: sql // Vulnerable: exposing SQL query
    });
  });
});

// Get single product with reviews (vulnerable to XSS)
router.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  
  // Vulnerable: No input validation
  const productSql = `SELECT * FROM products WHERE id = ${productId}`;
  
  store.readProduct(productSql, (err, product) => {
    if (err) {
      logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
    }
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // Get reviews for this product
    const reviewsSql = `SELECT r.*, u.username FROM reviews r 
                       JOIN users u ON r.user_id = u.id 
                       WHERE r.product_id = ${productId} 
                       ORDER BY r.created_at DESC`;
    
    store.readReviews(reviewsSql, (err, reviews) => {
      if (err) {
        logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
      }
      
      res.json({
        success: true,
        product: product,
        reviews: reviews
      });
    });
  });
});

// Add product review (vulnerable to stored XSS)
router.post('/product/:id/review', legacyPlatformMutationMiddleware, (req, res) => {
  const productId = req.params.id;
  const { rating, comment } = req.body;
  const userId = req.session.userId || 1; // Vulnerable: weak session handling
  
  // Vulnerable: No input sanitization
  const owner=platformOwner(req);
  const sql = `INSERT INTO reviews (product_id, user_id, rating, comment${owner?', platform_owner_id':''})
               VALUES (${productId}, ${userId}, ${rating}, '${comment}'${owner?`, ${owner}`:''})`;
  
  store.addReview(sql, function(err) {
    if (err) {
      logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
    }
    
    res.json({
      success: true,
      message: 'Review added successfully',
      reviewId: this.lastID
    });
  });
});

// Shopping cart endpoints
router.get('/cart', (req, res) => {
  const userId = req.session.userId || 1;
  
  const sql = `SELECT c.*, p.name, p.price, p.image_url 
               FROM cart c 
               JOIN products p ON c.product_id = p.id 
               WHERE c.user_id = ${userId}`;
  
  store.readCart(sql, (err, items) => {
    if (err) {
      logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
    }
    
    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    res.json({
      success: true,
      items: items,
      total: total.toFixed(2)
    });
  });
});

router.get('/cart/count', (req, res) => {
  const userId = req.session.userId || 1;
  
  store.countCart(
    userId,
    (err, result) => {
      if (err) {
        logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
      }
      
      res.json({
        success: true,
        count: result.count || 0
      });
    }
  );
});

router.post('/cart/add', legacyPlatformMutationMiddleware, (req, res) => {
  const { product_id, quantity = 1 } = req.body;
  const userId = req.session.userId || 1;
  
  // Vulnerable: No input validation
  const owner=platformOwner(req);
  const sql = `${store.engine === 'postgres' ? 'INSERT' : 'INSERT OR REPLACE'} INTO cart (user_id, product_id, quantity${owner?', platform_owner_id':''})
               VALUES (${userId}, ${product_id}, ${quantity}${owner?`, ${owner}`:''})`;
  
  store.addCart(sql, function(err) {
    if (err) {
      logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
    }
    
    res.json({
      success: true,
      message: 'Product added to cart'
    });
  });
});

// Vulnerable checkout process (CSRF)
router.post('/checkout', legacyPlatformMutationMiddleware, (req, res) => {
  const { payment_method, shipping_address } = req.body;
  const userId = req.session.userId || 1;
  
  // Vulnerable: No CSRF token validation
  // Vulnerable: No input sanitization
  const owner=platformOwner(req);
  const orderSql = `INSERT INTO orders (user_id, total_amount, payment_method, shipping_address, status${owner?', platform_owner_id':''})
                    VALUES (${userId}, 0, '${payment_method}', '${shipping_address}', 'pending'${owner?`, ${owner}`:''})`;
  
  store.createOrder(orderSql, function(err) {
    if (err) {
      logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
    }
    
    const orderId = this.lastID;
    
    // Move cart items to order_items
    const moveItemsSql = `INSERT INTO order_items (order_id, product_id, quantity, price)
                          SELECT ${orderId}, c.product_id, c.quantity, p.price
                          FROM cart c
                          JOIN products p ON c.product_id = p.id
                          WHERE c.user_id = ${userId}`;
    
    store.moveOrderItems(moveItemsSql, (err) => {
      if (err) {
        logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
      }
      
      // Clear cart
      store.clearCart(`DELETE FROM cart WHERE user_id = ${userId}`, (err) => {
        if (err) {
          logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
        }
        
        res.json({
          success: true,
          message: 'Order placed successfully',
          orderId: orderId
        });
      });
    });
  });
});

// Get user orders (vulnerable to IDOR)
router.get('/orders', (req, res) => {
  const userId = req.query.user_id || req.session.userId || 1; // Vulnerable: user can specify user_id
  
  const sql = `SELECT o.*, 
               ${store.engine === 'postgres' ? "STRING_AGG(p.name || ' x' || oi.quantity, ',')" : "GROUP_CONCAT(p.name || ' x' || oi.quantity)"} as items
               FROM orders o
               LEFT JOIN order_items oi ON o.id = oi.order_id
               LEFT JOIN products p ON oi.product_id = p.id
               WHERE o.user_id = ${userId}
               GROUP BY o.id
               ORDER BY o.created_at DESC`;
  
  store.readOrders(sql, (err, orders) => {
    if (err) {
      logger.error('route_error', { route: req.method + ' ' + req.path, message: err.message });
      return res.status(500).json({ error: err.message });
    }
    
    res.json({
      success: true,
      orders: orders
    });
  });
});

// AI Assistant endpoints for vulnerable profile updates
router.post('/update-profile', (req, res) => {
  const { action, name, address, userId, attackType = 'basic' } = req.body;
  
  let sql, vulnerability;
  
  if (action === 'update_name') {
    switch (attackType) {
      case 'union':
        // Union-based SQL injection
        sql = `UPDATE users SET username = '${name}' WHERE id = ${userId} UNION SELECT * FROM users--`;
        vulnerability = 'Union-based SQL Injection';
        break;
      case 'boolean_blind':
        // Boolean-based blind SQL injection
        sql = `UPDATE users SET username = '${name}' WHERE id = ${userId} AND (SELECT COUNT(*) FROM users WHERE role='admin') > 0--`;
        vulnerability = 'Boolean-based Blind SQL Injection';
        break;
      case 'time_blind':
        // Time-based blind SQL injection
        sql = `UPDATE users SET username = '${name}' WHERE id = ${userId} AND (SELECT CASE WHEN COUNT(*)>0 THEN (SELECT COUNT(*) FROM users WHERE SUBSTR(password,1,1)='a') ELSE 0 END FROM users WHERE role='admin')--`;
        vulnerability = 'Time-based Blind SQL Injection';
        break;
      case 'second_order':
        // Second-order SQL injection (stored and executed later)
        sql = `UPDATE users SET username = '${name}', bio = 'Updated via AI: ${name}' WHERE id = ${userId}`;
        vulnerability = 'Second-order SQL Injection';
        break;
      case 'error_based':
        // Error-based SQL injection
        sql = `UPDATE users SET username = '${name}' WHERE id = ${userId} AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) x GROUP BY CONCAT(username,0x3a,password) HAVING COUNT(*)>1)--`;
        vulnerability = 'Error-based SQL Injection';
        break;
      default:
        // Basic SQL injection
        sql = `UPDATE users SET username = '${name}' WHERE id = ${userId}`;
        vulnerability = 'Basic SQL Injection - Direct string interpolation';
    }
    
    store.updateDemoProfile(sql, function(err) {
      if (err) {
        return res.status(500).json({ 
          error: 'Database error',
          details: err.message,
          sqlQuery: sql,
          vulnerability: vulnerability,
          attackType: attackType
        });
      }
      
      res.json({
        success: true,
        message: `Name updated to ${name}`,
        sqlQuery: sql,
        vulnerability: vulnerability,
        attackType: attackType,
        result: {
          affectedRows: this.changes,
          userId: userId,
          newName: name
        }
      });
    });
  } else if (action === 'update_address') {
    // Address update with different injection types
    switch (attackType) {
      case 'stacked':
        // Stacked queries
        sql = `UPDATE users SET address = '${address}' WHERE id = ${userId}; INSERT INTO audit_log (action, user_id) VALUES ('address_change', ${userId})--`;
        vulnerability = 'Stacked Query SQL Injection';
        break;
      default:
        sql = `UPDATE users SET address = '${address}' WHERE id = ${userId}`;
        vulnerability = 'Basic SQL Injection in Address Field';
    }
    
    store.updateDemoProfile(sql, function(err) {
      if (err) {
        return res.status(500).json({ 
          error: 'Database error',
          details: err.message,
          sqlQuery: sql,
          vulnerability: vulnerability
        });
      }
      
      res.json({
        success: true,
        message: `Address updated to ${address}`,
        sqlQuery: sql,
        vulnerability: vulnerability,
        result: {
          affectedRows: this.changes,
          userId: userId,
          newAddress: address
        }
      });
    });
  } else {
    res.status(400).json({ error: 'Invalid action' });
  }
});

// AI Query endpoint - executes user-generated SQL with multiple injection types
router.post('/ai-query', (req, res) => {
  const { query, sqlQuery, userId, attackType = 'basic' } = req.body;
  
  let finalSQL = sqlQuery;
  let vulnerability = 'Basic SQL Injection';
  
  // Enhance SQL based on attack type
  switch (attackType) {
    case 'union':
      // Union-based injection to extract sensitive data
      finalSQL = sqlQuery + ` UNION SELECT id, username, password, email, role, workshop_admin, created_at, 'UNION_ATTACK' FROM users--`;
      vulnerability = 'Union-based SQL Injection';
      break;
      
    case 'boolean_blind':
      // Boolean-based blind injection
      finalSQL = sqlQuery + ` AND (SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin')>0 THEN 1 ELSE (SELECT 1/0) END)=1--`;
      vulnerability = 'Boolean-based Blind SQL Injection';
      break;
      
    case 'time_blind':
      // Time-based blind injection (simulated)
      finalSQL = sqlQuery + ` AND (SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin')>0 THEN (SELECT COUNT(*) FROM users) ELSE 1 END)>0--`;
      vulnerability = 'Time-based Blind SQL Injection';
      break;
      
    case 'error_based':
      // Error-based injection
      finalSQL = sqlQuery + ` AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) x GROUP BY CONCAT(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM users LIMIT 1),0x7e) HAVING COUNT(*)>1)--`;
      vulnerability = 'Error-based SQL Injection';
      break;
      
    case 'stacked':
      // Stacked queries
      finalSQL = sqlQuery + `; INSERT INTO audit_log (action, details, user_id) VALUES ('AI_QUERY', '${query}', ${userId})--`;
      vulnerability = 'Stacked Query SQL Injection';
      break;
      
    case 'nosql':
      // NoSQL injection simulation (for educational purposes)
      finalSQL = `SELECT * FROM users WHERE username = '${query}' OR '1'='1'`;
      vulnerability = 'NoSQL Injection Simulation';
      break;
      
    default:
      vulnerability = 'Basic SQL Injection - template-generated query execution';
  }
  
  // Vulnerable: Executing user-influenced SQL directly
  store.executeAiSql(finalSQL, (err, results) => {
    if (err) {
      return res.status(500).json({
        error: 'SQL execution failed',
        details: err.message,
        sqlQuery: finalSQL,
        originalQuery: sqlQuery,
        vulnerability: vulnerability,
        attackType: attackType,
        educationalNote: 'This error demonstrates how SQL injection can cause database errors and potentially expose sensitive information.'
      });
    }
    
    const aiResponse = describeLegacySqlResult(attackType, results);

    res.json({
      success: true,
      aiResponse: aiResponse,
      sqlQuery: finalSQL,
      originalQuery: sqlQuery,
      results: results,
      vulnerability: vulnerability,
      attackType: attackType,
      educationalNote: legacySqlEducationalNote(attackType, store.engine)
    });
  });
});

// NoSQL injection simulation endpoint
router.post('/nosql-query', (req, res) => {
  const { query, userId } = req.body;
  
  // Simulate NoSQL injection patterns
  const nosqlPatterns = {
    'show my orders': `db.orders.find({user_id: ${userId}})`,
    'admin orders': `db.orders.find({$where: "this.user_id == ${userId} || '1'=='1'"})`,
    'all users': `db.users.find({$or: [{id: ${userId}}, {$where: "'1'=='1'"}]})`,
    'bypass auth': `db.users.find({username: {$regex: ".*"}, password: {$ne: null}})`
  };
  
  const matchedPattern = Object.keys(nosqlPatterns).find(pattern => 
    query.toLowerCase().includes(pattern.toLowerCase())
  );
  
  const nosqlQuery = matchedPattern ? nosqlPatterns[matchedPattern] : 
    `db.collection.find({user_input: "${query}"})`;
  
  // Simulate NoSQL results (convert to SQL for demo)
  let sqlEquivalent;
  if (query.toLowerCase().includes('admin')) {
    sqlEquivalent = `SELECT * FROM orders WHERE user_id = ${userId} OR '1'='1'`;
  } else if (query.toLowerCase().includes('users')) {
    sqlEquivalent = `SELECT * FROM users WHERE username LIKE '%${query}%' OR '1'='1'`;
  } else {
    sqlEquivalent = `SELECT * FROM orders WHERE user_id = ${userId}`;
  }
  
  store.executeNoSqlSimulation(sqlEquivalent, (err, results) => {
    if (err) {
      return res.status(500).json({
        error: 'NoSQL query execution failed',
        details: err.message,
        nosqlQuery: nosqlQuery,
        sqlEquivalent: sqlEquivalent,
        vulnerability: 'NoSQL Injection'
      });
    }
    
    res.json({
      success: true,
      aiResponse: `NoSQL injection executed. Found ${results.length} documents.`,
      nosqlQuery: nosqlQuery,
      sqlEquivalent: sqlEquivalent,
      results: results,
      vulnerability: 'NoSQL Injection',
      educationalNote: 'NoSQL databases use different query languages but are still vulnerable to injection attacks through operators like $where, $regex, and logical operators.'
    });
  });
});

module.exports = router;
