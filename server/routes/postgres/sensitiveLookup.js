const express = require('express');
const path = require('path');
const fs = require('fs');
const { didReadOutsideRoot } = require('../../services/legacyPathEvidence');

module.exports=function createSensitiveLookupRouter({store=require('../../database/postgres/sensitiveLookupDb').getSensitiveLookupDb(),filesDir=require('../../database/sensitiveInfoFiles').sensitiveFilesDir,aiService=require('../../services/multiProviderAIService'),authenticate=require('../../middleware/adminAuth').authenticateToken,coordinator=require('../../agent-runtime/runCoordinator').createRunCoordinator({family:'SensitiveLookup'})}={}) {
const router=express.Router();
const registerGet=router.get.bind(router);
router.get=(url,handler)=>registerGet(url,(req,res,next)=>Promise.resolve(handler(req,res,next)).catch(next));
const mysqlDB=store,sensitiveFilesDir=filesDir;
const {ownerWorkflowRoute,checkOwnerRun}=require('../../agent-runtime/ownerWorkflowRoutes');
router.use(authenticate);
router.use((req,res,next)=>{const json=res.json.bind(res);res.json=value=>json({...value,engine:'postgres',dialect:'PostgreSQL',legacyRoutePrefix:'mysql'});next();});
const registerPost=router.post.bind(router);
router.post=(url,handler)=>registerPost(url,ownerWorkflowRoute(coordinator,req=>req.user.id,handler));
// =====================================================
// MYSQL-BACKED VULNERABLE ENDPOINTS - EDUCATIONAL USE
// =====================================================

/**
 * Pattern 1: Directory Traversal via PostgreSQL-Backed Path Resolution
 * 
 * User input → AI Agent → PostgreSQL Query → Path from DB → File Access
 */
router.post('/mysql/path-traversal', async (req, res) => {
  const { userInput, referenceKey, userId } = req.body;
  
  if (!userInput && !referenceKey) {
    return res.status(400).json({ error: 'User input or reference key required' });
  }

  console.log(`[PostgreSQL Path Traversal] User input: ${userInput || referenceKey}`);

  try {
    // Step 1: Query PostgreSQL for file path (VULNERABLE)
    const filePathFromDB = await mysqlDB.getFilePathByReference(
      referenceKey || 'help',
      userInput
    );

    if (!filePathFromDB) {
      return res.status(404).json({
        success: false,
        error: 'File reference not found in database',
        hint: 'Try: db_creds, admin_pass, api_keys, db_config'
      });
    }

    console.log(`[PostgreSQL Path Traversal] DB returned path: ${filePathFromDB}`);

    // Step 2: VULNERABILITY - Use DB path directly without validation
    const fullPath = path.join(sensitiveFilesDir, filePathFromDB);
    
    console.log(`[PostgreSQL Path Traversal] Attempting to read: ${fullPath}`);

    // Step 3: Read file (Path Traversal occurs here)
    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found on filesystem',
        dbPath: filePathFromDB,
        hint: 'The path from database may be incorrect'
      });
    }

    const fileContent = fs.readFileSync(fullPath, 'utf8');
    
    // Step 4: Check for flags
    const flagMatch = fileContent.match(/FLAG:\s*([A-Z_0-9{}]+)/i) || 
                      fileContent.match(/FLAG\{[^}]+\}/i);
    const flagFound = flagMatch ? flagMatch[0] : null;

    // Step 5: Detect if traversal occurred
    const isTraversal = didReadOutsideRoot(sensitiveFilesDir, fullPath);

    // Step 6: Log to PostgreSQL
    await checkOwnerRun();
    await mysqlDB.logExploitation({
      userId: req.user.id,
      userInput: userInput || referenceKey,
      queryExecuted: `SELECT file_path FROM file_references WHERE reference_key = '${referenceKey}'`,
      vulnerabilityType: 'PostgreSQL-Backed Path Traversal',
      fileAccessed: filePathFromDB,
      flagCaptured: flagFound,
      success: isTraversal,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      vulnerability: isTraversal ? 'PostgreSQL-Backed Directory Traversal' : null,
      exploited: isTraversal,
      fileReference: referenceKey || 'user_input',
      pathFromDatabase: filePathFromDB,
      resolvedPath: fullPath,
      fileContent: fileContent,
      fileSize: fileContent.length,
      flagCaptured: flagFound,
      message: isTraversal ? 
        '⚠️ VULNERABILITY EXPLOITED: PostgreSQL returned path that allowed directory traversal!' :
        'File accessed successfully via PostgreSQL reference',
      pattern: 'User Chat → AI → PostgreSQL Query → Path Resolution → File Access'
    });

  } catch (error) {
    console.error('[PostgreSQL Path Traversal] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      hint: 'Make sure PostgreSQL is running and configured'
    });
  }
});

/**
 * Pattern 2: SSI Injection via PostgreSQL-Stored Templates
 * 
 * User input → AI Agent → PostgreSQL Query → Template from DB → SSI Processing
 */
router.post('/mysql/ssi-injection', async (req, res) => {
  const { userInput, templateName, userId } = req.body;
  
  if (!userInput && !templateName) {
    return res.status(400).json({ error: 'User input or template name required' });
  }

  console.log(`[PostgreSQL SSI Injection] User input: ${userInput || templateName}`);

  try {
    // Step 1: Query PostgreSQL for template (VULNERABLE)
    const template = await mysqlDB.getTemplateByName(
      templateName || 'greeting',
      userInput
    );

    if (!template) {
      return res.status(404).json({
        success: false,
        error: 'Template not found in database',
        hint: 'Try: database_response, admin_template, secret_template, config_template'
      });
    }

    console.log(`[PostgreSQL SSI] DB returned template: ${template.content.substring(0, 100)}...`);

    let processedContent = template.content;
    const originalContent = template.content;

    // Step 2: VULNERABILITY - Process SSI directives if enabled
    if (template.ssiEnabled) {
      // Process <!--#echo var="..." --> directives
      const echoMatches = processedContent.matchAll(/<!--#echo var="([^"]+)" -->/g);
      for (const match of echoMatches) {
        const varName = match[1];
        // Get value from PostgreSQL config
        const varValue = await mysqlDB.getConfigValue(varName) || `[${varName} not found]`;
        processedContent = processedContent.replace(match[0], varValue);
      }

      // Process <!--#include virtual="..." --> directives
      const includeMatches = processedContent.matchAll(/<!--#include (virtual|file)="([^"]+)" -->/g);
      for (const match of includeMatches) {
        const includePath = match[2];
        try {
          const includeFullPath = path.join(sensitiveFilesDir, includePath);
          if (fs.existsSync(includeFullPath)) {
            const includeContent = fs.readFileSync(includeFullPath, 'utf8');
            processedContent = processedContent.replace(match[0], includeContent);
          }
        } catch (err) {
          // Silent fail
        }
      }
    }

    // Step 3: Check for flags
    const flagMatch = processedContent.match(/FLAG:\s*([A-Z_0-9{}]+)/i) || 
                      processedContent.match(/FLAG\{[^}]+\}/i);
    const flagFound = flagMatch ? flagMatch[0] : null;

    // Step 4: Detect if SSI was processed
    const wasProcessed = processedContent !== originalContent;
    const hasSSIDirectives = originalContent.includes('<!--#');

    // Step 5: Log to PostgreSQL
    await checkOwnerRun();
    await mysqlDB.logExploitation({
      userId: req.user.id,
      userInput: userInput || templateName,
      queryExecuted: `SELECT template_content FROM chatbot_templates WHERE template_name = '${templateName}'`,
      vulnerabilityType: 'PostgreSQL-Backed SSI Injection',
      fileAccessed: templateName,
      flagCaptured: flagFound,
      success: wasProcessed && hasSSIDirectives,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      vulnerability: (wasProcessed && hasSSIDirectives) ? 'PostgreSQL-Backed SSI Injection' : null,
      exploited: wasProcessed && hasSSIDirectives,
      templateName: templateName || 'user_input',
      templateFromDatabase: originalContent,
      processedContent: processedContent,
      ssiEnabled: template.ssiEnabled,
      ssiDirectivesFound: hasSSIDirectives,
      wasProcessed: wasProcessed,
      flagCaptured: flagFound,
      message: (wasProcessed && hasSSIDirectives) ? 
        '⚠️ VULNERABILITY EXPLOITED: PostgreSQL-stored template contained SSI directives that were processed!' :
        'Template rendered from PostgreSQL successfully',
      pattern: 'User Chat → AI → PostgreSQL Query → Template Retrieval → SSI Processing'
    });

  } catch (error) {
    console.error('[PostgreSQL SSI] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      hint: 'Make sure PostgreSQL is running and configured'
    });
  }
});

/**
 * Pattern 3: Combined Attack - Path Traversal + SSI via PostgreSQL
 * 
 * User input → AI → PostgreSQL Path Query → File Access → PostgreSQL Template Query → SSI Processing
 */
router.post('/mysql/combined-attack', async (req, res) => {
  const { userInput, referenceKey, templateName, userId } = req.body;
  
  if (!userInput && !referenceKey && !templateName) {
    return res.status(400).json({ error: 'User input, reference key, or template name required' });
  }

  console.log(`[PostgreSQL Combined Attack] User input: ${userInput || referenceKey || templateName}`);

  try {
    let finalContent = '';
    let pathTraversalOccurred = false;
    let ssiInjectionOccurred = false;
    let pathFromDB = null;
    let templateFromDB = null;
    let flagsFound = [];

    // Step 1: Path Traversal via PostgreSQL
    if (referenceKey || userInput) {
      pathFromDB = await mysqlDB.getFilePathByReference(
        referenceKey || 'help',
        userInput
      );

      if (pathFromDB) {
        const fullPath = path.join(sensitiveFilesDir, pathFromDB);
        if (fs.existsSync(fullPath)) {
          const fileContent = fs.readFileSync(fullPath, 'utf8');
          finalContent = fileContent;
          
          pathTraversalOccurred = didReadOutsideRoot(sensitiveFilesDir, fullPath);
          
          // Check for flags in file
          const flagMatch = fileContent.match(/FLAG:\s*([A-Z_0-9{}]+)/i) || 
                           fileContent.match(/FLAG\{[^}]+\}/i);
          if (flagMatch) flagsFound.push(flagMatch[0]);
        }
      }
    }

    // Step 2: SSI Processing via PostgreSQL Template
    if (templateName || userInput) {
      templateFromDB = await mysqlDB.getTemplateByName(
        templateName || 'greeting',
        userInput
      );

      if (templateFromDB && templateFromDB.ssiEnabled) {
        let templateContent = templateFromDB.content;
        const originalTemplate = templateContent;

        // Process SSI directives
        const echoMatches = templateContent.matchAll(/<!--#echo var="([^"]+)" -->/g);
        for (const match of echoMatches) {
          const varName = match[1];
          const varValue = await mysqlDB.getConfigValue(varName) || `[${varName}]`;
          templateContent = templateContent.replace(match[0], varValue);
        }

        const includeMatches = templateContent.matchAll(/<!--#include (virtual|file)="([^"]+)" -->/g);
        for (const match of includeMatches) {
          const includePath = match[2];
          try {
            const includeFullPath = path.join(sensitiveFilesDir, includePath);
            if (fs.existsSync(includeFullPath)) {
              const includeContent = fs.readFileSync(includeFullPath, 'utf8');
              templateContent = templateContent.replace(match[0], includeContent);
            }
          } catch (err) {}
        }

        ssiInjectionOccurred = templateContent !== originalTemplate;
        
        // Combine with path traversal result
        if (finalContent) {
          finalContent = finalContent + '\n\n--- Template Response ---\n\n' + templateContent;
        } else {
          finalContent = templateContent;
        }

        // Check for flags in template
        const flagMatch = templateContent.match(/FLAG:\s*([A-Z_0-9{}]+)/i) || 
                         templateContent.match(/FLAG\{[^}]+\}/i);
        if (flagMatch) flagsFound.push(flagMatch[0]);
      }
    }

    // Step 3: Log combined attack
    const isCombinedExploit = pathTraversalOccurred && ssiInjectionOccurred;
    
    await checkOwnerRun();
    await mysqlDB.logExploitation({
      userId: req.user.id,
      userInput: userInput || `${referenceKey}+${templateName}`,
      queryExecuted: 'Combined PostgreSQL queries for path and template',
      vulnerabilityType: isCombinedExploit ? 'PostgreSQL-Backed Combined Attack (Path Traversal + SSI)' : 
                         pathTraversalOccurred ? 'PostgreSQL-Backed Path Traversal' :
                         ssiInjectionOccurred ? 'PostgreSQL-Backed SSI Injection' : 'Normal Access',
      fileAccessed: pathFromDB || templateName,
      flagCaptured: flagsFound.join(', '),
      success: isCombinedExploit,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      vulnerability: isCombinedExploit ? 'PostgreSQL-Backed Combined Attack (Path Traversal + SSI Injection)' : null,
      exploited: isCombinedExploit,
      pathTraversal: {
        occurred: pathTraversalOccurred,
        pathFromDatabase: pathFromDB
      },
      ssiInjection: {
        occurred: ssiInjectionOccurred,
        templateFromDatabase: templateFromDB ? templateFromDB.content : null
      },
      finalContent: finalContent,
      flagsCaptured: flagsFound,
      message: isCombinedExploit ?
        '🔥 CRITICAL VULNERABILITY: Combined PostgreSQL-backed Path Traversal AND SSI Injection exploited in single attack!' :
        pathTraversalOccurred ? '⚠️ Path Traversal via PostgreSQL exploited' :
        ssiInjectionOccurred ? '⚠️ SSI Injection via PostgreSQL exploited' :
        'Request processed via PostgreSQL',
      pattern: 'User Chat → AI → PostgreSQL (Path Query + Template Query) → File Access → SSI Processing → Combined Result',
      attackFlow: [
        '1. User provides conversational input',
        '2. AI analyzes intent',
        '3. PostgreSQL queried for file path reference',
        '4. Path from DB used to access file (Path Traversal)',
        '5. PostgreSQL queried for response template',
        '6. Template from DB processed with SSI (SSI Injection)',
        '7. Combined result returned to user'
      ]
    });

  } catch (error) {
    console.error('[PostgreSQL Combined Attack] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      hint: 'Make sure PostgreSQL is running and configured'
    });
  }
});

/**
 * AI Chat Interface - PostgreSQL-Backed Version
 * Natural language → AI analysis → PostgreSQL queries → Exploitation
 */
router.post('/mysql/ai-chat', async (req, res) => {
  const { message, userId } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  console.log(`[PostgreSQL AI Chat] User: ${message}`);

  try {
    // Step 1: AI analyzes user intent
    const aiResult = await aiService.processSensitiveInfoRequest(message, {
      databaseEngine:'postgres'
    });

    let mysqlPath = null;
    let mysqlTemplate = null;
    let fileContent = null;
    let processedTemplate = null;
    let flagsFound = [];
    let vulnerabilityType = null;

    // Step 2: Based on AI intent, query PostgreSQL
    const lowerMessage = message.toLowerCase();
    
    // Try path traversal via PostgreSQL
    if (lowerMessage.includes('file') || lowerMessage.includes('read') || 
        lowerMessage.includes('access') || lowerMessage.includes('show')) {
      
      let referenceKey = 'help';
      if (lowerMessage.includes('database') || lowerMessage.includes('db') || lowerMessage.includes('cred')) {
        referenceKey = 'db_creds';
      } else if (lowerMessage.includes('admin') || lowerMessage.includes('password')) {
        referenceKey = 'admin_pass';
      } else if (lowerMessage.includes('api') || lowerMessage.includes('key')) {
        referenceKey = 'api_keys';
      } else if (lowerMessage.includes('config')) {
        referenceKey = 'db_config';
      }

      mysqlPath = await mysqlDB.getFilePathByReference(referenceKey, message);
      
      if (mysqlPath) {
        const fullPath = path.join(sensitiveFilesDir, mysqlPath);
        if (fs.existsSync(fullPath)) {
          fileContent = fs.readFileSync(fullPath, 'utf8');
          
          const flagMatch = fileContent.match(/FLAG:\s*([A-Z_0-9{}]+)/i) || 
                           fileContent.match(/FLAG\{[^}]+\}/i);
          if (flagMatch) flagsFound.push(flagMatch[0]);
          
          if (didReadOutsideRoot(sensitiveFilesDir, fullPath)) {
            vulnerabilityType = 'PostgreSQL-Backed Path Traversal';
          }
        }
      }
    }

    // Try SSI injection via PostgreSQL
    if (lowerMessage.includes('template') || lowerMessage.includes('variable') || 
        lowerMessage.includes('config') || lowerMessage.includes('password')) {
      
      let templateKey = 'greeting';
      if (lowerMessage.includes('database')) {
        templateKey = 'database_response';
      } else if (lowerMessage.includes('admin')) {
        templateKey = 'admin_template';
      } else if (lowerMessage.includes('secret')) {
        templateKey = 'secret_template';
      } else if (lowerMessage.includes('config')) {
        templateKey = 'config_template';
      }

      mysqlTemplate = await mysqlDB.getTemplateByName(templateKey, message);
      
      if (mysqlTemplate && mysqlTemplate.ssiEnabled) {
        processedTemplate = mysqlTemplate.content;
        
        // Process SSI
        const echoMatches = processedTemplate.matchAll(/<!--#echo var="([^"]+)" -->/g);
        for (const match of echoMatches) {
          const varName = match[1];
          const varValue = await mysqlDB.getConfigValue(varName) || `[${varName}]`;
          processedTemplate = processedTemplate.replace(match[0], varValue);
        }

        if (processedTemplate !== mysqlTemplate.content) {
          vulnerabilityType = vulnerabilityType ? 
            'PostgreSQL-Backed Combined Attack (Path Traversal + SSI)' :
            'PostgreSQL-Backed SSI Injection';
        }

        const flagMatch = processedTemplate.match(/FLAG:\s*([A-Z_0-9{}]+)/i) || 
                         processedTemplate.match(/FLAG\{[^}]+\}/i);
        if (flagMatch) flagsFound.push(flagMatch[0]);
      }
    }

    // Step 3: Build AI response
    let aiResponse = aiResult.response || "I can help you access files and templates via the database.";
    
    if (fileContent) {
      aiResponse += `\n\n📄 I found this file in the database:\n${fileContent.substring(0, 500)}${fileContent.length > 500 ? '...' : ''}`;
    }
    
    if (processedTemplate) {
      aiResponse += `\n\n📋 Template response:\n${processedTemplate}`;
    }

    // Step 4: Log to PostgreSQL
    if (vulnerabilityType) {
      await checkOwnerRun();
    await mysqlDB.logExploitation({
        userId: req.user.id,
        userInput: message,
        queryExecuted: 'AI-driven PostgreSQL queries',
        vulnerabilityType: vulnerabilityType,
        fileAccessed: mysqlPath || 'template',
        flagCaptured: flagsFound.join(', '),
        success: true,
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });
    }

    res.json({
      success: true,
      aiResponse: aiResponse,
      vulnerability: vulnerabilityType,
      exploited: vulnerabilityType !== null,
      mysqlPathUsed: mysqlPath,
      mysqlTemplateUsed: mysqlTemplate ? mysqlTemplate.content : null,
      flagsCaptured: flagsFound,
      model: aiResult.model,
      provider: aiResult.provider,
      pattern: 'Natural Language → AI Analysis → PostgreSQL Queries → Vulnerability Exploitation'
    });

  } catch (error) {
    console.error('[PostgreSQL AI Chat] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      aiResponse: "I'm having trouble accessing the database. Please try again."
    });
  }
});

/**
 * Get exploitation statistics from PostgreSQL
 */
router.get('/mysql/stats', async (req, res) => {
  try {
    const stats = await mysqlDB.getExploitationStats(req.user.id);
    
    res.json({
      success: true,
      stats: stats,
      databaseAvailable: await mysqlDB.health(),
      mysqlAvailable: false
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Health check - PostgreSQL availability
 */
router.get('/mysql/health', async (req, res) => {
  res.json({
    databaseAvailable: await mysqlDB.health(),
      mysqlAvailable: false,
    message: 'PostgreSQL-backed vulnerabilities are available; /mysql is a compatibility URL'
  });
});

return router;
};

