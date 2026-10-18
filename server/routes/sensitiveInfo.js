const {SSI_FLAG,findChallengeFlag}=require('../config/legacySensitiveFlags');
const {fileBoundary,observedFacts}=require('../agent-runtime/legacySensitiveEvidence');
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Try to use multi-provider AI service, fallback to ollama service
let aiService;
try {
  aiService = require('../services/multiProviderAIService');
  console.log('[Sensitive Info Routes] Using Multi-Provider AI Service');
} catch (error) {
  aiService = require('../services/ollamaService');
  console.log('[Sensitive Info Routes] Using Ollama Service (fallback)');
}

const {
  db,
  engine,
  logFileAccess,
  getPublicDocuments,
  getAccessLogs,
  getChallengeStats,
  sensitiveFilesDir,
  publicDir,
  secretDir,
  adminDir,
  configDir
} = require('../database/sensitiveInfoDb');
const legacySensitiveTools=require('../services/legacySensitiveTools').createLegacySensitiveTools({
  sensitiveFilesDir,publicDir:publicDir||path.join(sensitiveFilesDir,'public'),fsImpl:fs,
});

const {authenticateToken}=require('../middleware/adminAuth');
const {ownerWorkflowRoute,getOwnerExecution}=require('../agent-runtime/ownerWorkflowRoutes');
const suggestLegacyPayload=require('../services/legacySensitivePayloadSuggestion').createLegacySensitivePayloadSuggestion(aiService);
const legacyRuns=require('../services/legacySensitiveRunCoordinator').legacySensitiveRuns;
const legacyModeAuthority=require('../services/workshopModeRunAuthority').createWorkshopModeRunAuthority({
  workshopKey:'legacy_sensitive_file_ssi',
  readScope:(userId,key)=>engine==='postgres'
    ? require('../services/postgresPlatformStores').getPostgresPlatformStores().progress.getEvaluationScope(userId,key)
    : Promise.resolve({generation:0,mode:null,modeStamp:'default'}),
});
const gradeLegacy=require('../agent-runtime/legacySensitiveJudge').createLegacySensitiveGrader(
  require('../services/legacySensitiveProgressStore').createLegacySensitiveProgressStore(engine==='postgres'?require('../database/sensitiveInfoDb'):db));
const resolveCanonicalComposition=()=>require('../services/legacySensitiveCandidateComposition')
  .getLegacySensitiveCandidateComposition({legacyRuns});
router.use(authenticateToken);
// Candidate production path stays mounted but unavailable until a reviewed
// composition supplies canonical catalog, Judge, model, and aggregate-reset
// readiness. The historical teaching routes below retain their current sinks.
router.use('/canonical-agent', require('./legacySensitiveCandidate').createLegacySensitiveCandidateRouter({
  resolveApplication: async () => (await resolveCanonicalComposition())?.application || null,
}));
function gradedRoute(handler,{modeAware=false}={}){
 return ownerWorkflowRoute(legacyRuns,req=>req.user.id,async(req,res)=>{
  let canonical=null;
  try{canonical=await resolveCanonicalComposition();}
  catch{return res.status(503).json({success:false,unavailable:true,error:'Canonical Legacy Sensitive grading is not ready'});}
  const execution=getOwnerExecution();
  const canonicalAttempt=canonical?await canonical.application.begin(req.user.id,execution):null;
  if(modeAware){const captured=await legacyModeAuthority.capture(req.user.id,execution);
   req.legacyMode=captured.mode;req.checkLegacyMode=captured.check;}
  const judgments=[];
  req.gradeLegacy=async(objectiveId,request,result,facts,flagFound,exploitUsed)=>{
   const outcome=canonical
    ?await canonical.application.assess({userId:req.user.id,objectiveId,request,result,execution,attempt:canonicalAttempt})
    :await gradeLegacy({userId:Number(req.user.id),objectiveId,request,result,facts:observedFacts(objectiveId,result,{realModel:facts.real_model}),flagFound,exploitUsed,execution});
   const projected=canonical?{objectiveId,completed:outcome.completed===true,verdict:outcome.judgment?.verdict,
    judgeVersion:outcome.judgment?.judgeVersion,rubricVersion:outcome.judgment?.rubricVersion,
    evaluationId:outcome.receipt?.evaluationId}:outcome;
   judgments.push(projected);return projected;
  };
  const response=new Proxy(res,{get(target,key){if(key==='json')return payload=>target.json({...payload,judgments});if(key==='status')return code=>{target.status(code);return response;};const value=target[key];return typeof value==='function'?value.bind(target):value;}});
  return handler(req,response);
 });
}
function actualModel(result){return Boolean(result?.provider)&&!['mock','fallback'].includes(String(result.provider).toLowerCase())&&!result.mocked&&!result.fallback;}

// ============================================
// VULNERABLE ENDPOINTS - FOR EDUCATIONAL USE
// ============================================

// 1. DIRECTORY/PATH TRAVERSAL VULNERABILITY
// Deliberately vulnerable file reader - allows path traversal
router.post('/file/read', gradedRoute(async (req, res) => {
  const { filename, userId } = req.body;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }

  console.log(`[Path Traversal Challenge] User requesting file: ${filename}`);

  try {
    await req.checkLegacyMode();
    if(req.legacyMode==='fixed'){
      const fixed=legacySensitiveTools.readTeachingFile({path:filename,mode:'fixed'});
      await req.checkLegacyMode();
      return fixed.success?res.json({success:true,filename,content:fixed.content,size:fixed.content.length,
        exploited:false,flagFound:false,message:'Public teaching file read',vulnerability:null})
        :res.status(404).json({success:false,error:'File not found',code:fixed.code||'FILE_NOT_FOUND'});
    }
    // VULNERABILITY: No path sanitization - allows ../ traversal
    const fileResult = legacySensitiveTools.readTeachingFile({path:filename});
    
    // Log the access attempt
    await logFileAccess(
      req.user.id,
      filename,
      'read',
      'attempted',
      req.ip,
      req.get('user-agent')
    );

    // Check if file exists
    if (!fileResult.success) {
      await logFileAccess(req.user.id, filename, 'read', 'not_found', req.ip, req.get('user-agent'));
      return res.status(404).json({
        success: false,
        error: 'File not found',
        message: `The file "${filename}" does not exist`,
        hint: 'Try listing available files first'
      });
    }

    // VULNERABILITY: Reading file without access control
    const fileContent = fileResult.content;
    
    // Detect if sensitive file was accessed
    const boundary=fileResult.boundary;
    const isSensitiveAccess=boundary.outsidePublic;
    
    // Check for flag extraction
    const flagFound = findChallengeFlag(fileContent);

    if (isSensitiveAccess || flagFound) {
      await logFileAccess(req.user.id, filename, 'read', 'exploited', req.ip, req.get('user-agent'));
      
      {
        await req.gradeLegacy('path_traversal',filename,{path:filename,content:fileContent,boundary},{},flagFound,'directory_traversal');
      }
    } else {
      await logFileAccess(req.user.id, filename, 'read', 'success', req.ip, req.get('user-agent'));
    }

    res.json({
      success: true,
      filename: filename,
      content: fileContent,
      size: fileContent.length,
      exploited: isSensitiveAccess,
      flagFound: flagFound,
      message: isSensitiveAccess ? 
        '⚠️ WARNING: You have accessed a sensitive file!' : 
        'File read successfully',
      vulnerability: isSensitiveAccess ? 'Path Traversal' : null
    });

  } catch (error) {
    console.error('File read error:', error);
    await logFileAccess(req.user.id, filename, 'read', 'error', req.ip, req.get('user-agent'));
    
    res.status(500).json({
      success: false,
      error: error.message,
      message: 'Failed to read file',
      stack: error.stack // VULNERABILITY: Stack trace exposure
    });
  }
},{modeAware:true}));

// 2. SERVER SIDE INCLUDE (SSI) INJECTION VULNERABILITY
// Vulnerable SSI template processor
router.post('/template/render', gradedRoute(async (req, res) => {
  const { template, variables, userId } = req.body;
  
  if (!template) {
    return res.status(400).json({ error: 'Template content is required' });
  }

  console.log(`[SSI Injection Challenge] Processing template: ${template.substring(0, 100)}...`);

  try {
    await req.checkLegacyMode();
    if(req.legacyMode==='fixed'){
      const fixed=legacySensitiveTools.renderSsiTemplate({template,mode:'fixed'});
      await req.checkLegacyMode();
      return res.json({success:true,rendered:fixed.rendered,ssiDetected:fixed.ssiDetected,
        execDetected:false,includeDetected:false,exploitedDirectives:[],flagFound:false,
        vulnerability:null,executionMode:fixed.executionMode,
        message:'Template rendered literally in Fixed mode',warning:null});
    }
    // VULNERABILITY: Processing SSI directives without sanitization
    let processedTemplate = template;
    
    // Simulate SSI directive processing
    const ssiPatterns = [
      { pattern: /<!--#echo var="([^"]+)" -->/g, type: 'echo' },
      { pattern: /<!--#include virtual="([^"]+)" -->/g, type: 'include' },
      { pattern: /<!--#include file="([^"]+)" -->/g, type: 'file_include' },
      { pattern: /<!--#exec cmd="([^"]+)" -->/g, type: 'exec' },
      { pattern: /<!--#config timefmt="([^"]+)" -->/g, type: 'config' }
    ];

    let ssiDetected = false;
    let ssiSucceeded = false;
    let execDetected = false;
    let includeDetected = false;
    let exploitedDirectives = [];

    // Process echo directives
    processedTemplate = processedTemplate.replace(/<!--#echo var="([^"]+)" -->/g, (match, varName) => {
      ssiDetected = true;
      exploitedDirectives.push(`echo:${varName}`);
      
      const envVars = {
        'DATE_LOCAL': new Date().toString(),
        'REMOTE_ADDR': req.ip,
        'REMOTE_USER': 'guest_user',
        'DOCUMENT_NAME': 'template.html',
        'DOCUMENT_URI': req.path,
        'SERVER_NAME': req.hostname,
        'HTTP_USER_AGENT': req.get('user-agent') || 'Unknown',
        'PATH_INFO': req.path,
        'QUERY_STRING': req.url.split('?')[1] || '',
        // VULNERABILITY: Exposing sensitive environment variables
        'DATABASE_PASSWORD': 'Db@dmin#Pass2024',
        'API_KEY': 'sk-proj-abc123def456',
        'SECRET_TOKEN': 'ultra-secret-token-987654'
      };
      
      if (Object.prototype.hasOwnProperty.call(envVars, varName)) ssiSucceeded = true;
      return envVars[varName] || `[${varName}]`;
    });

    // Process include directives (file inclusion)
    const includeMatches = processedTemplate.matchAll(/<!--#include (virtual|file)="([^"]+)" -->/g);
    for (const match of includeMatches) {
      ssiDetected = true;
      includeDetected = true;
      const includeType = match[1];
      const includePath = match[2];
      exploitedDirectives.push(`include:${includePath}`);
      
      try {
        // VULNERABILITY: Arbitrary file inclusion
        const included=legacySensitiveTools.readTeachingFile({path:includePath});
        if (included.success) {
          ssiSucceeded = true;
          const includeContent = included.content;
          processedTemplate = processedTemplate.replace(match[0], () => includeContent);
        } else {
          processedTemplate = processedTemplate.replace(match[0], () => `[Error: File not found: ${includePath}]`);
        }
      } catch (err) {
        processedTemplate = processedTemplate.replace(match[0], () => `[Error including file: ${err.message}]`);
      }
    }

    // Process exec directives (command execution simulation)
    const execMatches = processedTemplate.matchAll(/<!--#exec cmd="([^"]+)" -->/g);
    for (const match of execMatches) {
      ssiDetected = true;
      execDetected = true;
      const command = match[1];
      exploitedDirectives.push(`exec:${command}`);
      
      // VULNERABILITY: Simulated command execution
      const cmdResults = {
        'whoami': 'www-data',
        'pwd': '/var/www/html',
        'ls': 'index.html  config.php  secret.txt  admin.txt',
        'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
        'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
        'env': 'PATH=/usr/local/bin:/usr/bin\nDATABASE_PASSWORD=Db@dmin#Pass2024\nAPI_KEY=sk-proj-abc123def456'
      };
      
      const result = cmdResults[command] || `Command executed: ${command}\n[Output simulated for security]`;
      processedTemplate = processedTemplate.replace(match[0], () => `<pre>${result}</pre>`);
    }

    // Check for flag in processed template
    const flagFound = findChallengeFlag(processedTemplate);

    if (ssiDetected) {
      await req.gradeLegacy('ssi_injection',template,{original:template,rendered:processedTemplate,directives:exploitedDirectives,ssiSucceeded,executionSource:'lab_ssi_processor'},{},flagFound,exploitedDirectives.join(', '));
    }

    res.json({
      success: true,
      rendered: processedTemplate,
      ssiDetected: ssiDetected,
      execDetected: execDetected,
      includeDetected: includeDetected,
      exploitedDirectives: exploitedDirectives,
      flagFound: flagFound,
      vulnerability: ssiDetected ? 'Server Side Include (SSI) Injection' : null,
      executionMode: 'lab_ssi_interpreter',
      message: ssiDetected ? 'SSI directives were processed by the lab interpreter.' : 'Template rendered',
      warning: execDetected ? 'Command output is simulated by the lab interpreter; no operating-system command was executed.' : null
    });

  } catch (error) {
    console.error('SSI template error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
},{modeAware:true}));

// 3. COMBINED PATH TRAVERSAL + SSI INJECTION
// Most dangerous - combines both vulnerabilities
router.post('/document/process', gradedRoute(async (req, res) => {
  const { documentPath, processSSI, userId } = req.body;
  
  if (!documentPath) {
    return res.status(400).json({ error: 'Document path is required' });
  }

  console.log(`[Combined Vulnerability] Processing document: ${documentPath}`);

  try {
    await req.checkLegacyMode();
    if(req.legacyMode==='fixed'){
      const fixed=legacySensitiveTools.processTeachingDocument({path:documentPath,
        processSsi:Boolean(processSSI),mode:'fixed'});
      await req.checkLegacyMode();
      if(!fixed.success)return res.status(404).json({success:false,error:'Document not found',code:fixed.code||'FILE_NOT_FOUND'});
      return res.json({success:true,documentPath,content:fixed.rendered,
        processedSSI:false,flagFound:false,exploited:false,vulnerability:null,
        message:'Public document read; SSI directives remain literal in Fixed mode'});
    }
    // VULNERABILITY 1: Path Traversal
    const fileResult=legacySensitiveTools.readTeachingFile({path:documentPath});
    
    if (!fileResult.success) {
      return res.status(404).json({
        success: false,
        error: 'Document not found'
      });
    }

    let content = fileResult.content;
    const originalContent=content;
    let ssiSucceeded = false;
    
    // VULNERABILITY 2: SSI Processing if requested
    if (processSSI) {
      // Process SSI directives in the loaded file
      content = content.replace(/<!--#echo var="([^"]+)" -->/g, (match, varName) => {
        const vars = {
          'DATE_LOCAL': new Date().toString(),
          'REMOTE_ADDR': req.ip,
          'DATABASE_PASSWORD': 'Db@dmin#Pass2024',
          'SECRET_KEY': 'ultra-secret-key-abc123'
        };
        if (Object.prototype.hasOwnProperty.call(vars, varName)) ssiSucceeded = true;
        return vars[varName] || `[${varName}]`;
      });

      const includeMatches = content.matchAll(/<!--#include (virtual|file)="([^"]+)" -->/g);
      for (const match of includeMatches) {
        try {
          const included=legacySensitiveTools.readTeachingFile({path:match[2]});
          if (included.success) {
            ssiSucceeded = true;
            const includeContent = included.content;
            content = content.replace(match[0], () => includeContent);
          }
        } catch (err) {
          // Silent fail
        }
      }
    }

    const flagFound = findChallengeFlag(content);

    const boundary=fileResult.boundary;
    const isCombinedExploit=boundary.outsidePublic&&Boolean(processSSI);

    if (typeof content==='string') {
      await req.gradeLegacy('combined_traversal_ssi',documentPath,{path:documentPath,original:originalContent,rendered:content,ssiRequested:Boolean(processSSI),ssiSucceeded,boundary},{},flagFound,'path_traversal+ssi_injection');
    }

    res.json({
      success: true,
      documentPath: documentPath,
      content: content,
      processedSSI: processSSI,
      flagFound: flagFound,
      exploited: isCombinedExploit,
      vulnerability: isCombinedExploit ? 'Combined Path Traversal + SSI Injection' : null,
      message: isCombinedExploit ? '🔥 CRITICAL: Multiple vulnerabilities exploited!' : 'Document processed'
    });

  } catch (error) {
    console.error('Document processing error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
},{modeAware:true}));

// 4. AI-POWERED PAYLOAD GENERATION
// LLM generates exploitation payloads from natural language
router.post('/ai/generate-payload', async (req, res) => {
  const { userPrompt, targetVulnerability, userId } = req.body;
  
  if (!userPrompt) {
    return res.status(400).json({ error: 'User prompt is required' });
  }

  console.log(`[AI Payload Generation] User: ${userPrompt}, Target: ${targetVulnerability}`);

  try {
    // Text-only teaching assistance. This endpoint never executes or grades the
    // suggested payload.
    const result = await suggestLegacyPayload(userPrompt, targetVulnerability);
    
    res.json({
      success: true,
      userPrompt: userPrompt,
      targetVulnerability: targetVulnerability,
      generatedPayload: result.payload,
      explanation: result.explanation,
      exampleUsage: result.example,
      vulnerability: result.vulnerability,
      model: result.model,
      warning: '⚠️ These payloads are for educational purposes only!'
    });

  } catch (error) {
    console.error('AI payload generation error:', error);
    res.status(503).json({
      success: false,
      error: 'AI payload suggestion is unavailable',
      unavailable: true
    });
  }
});

// 5. AI CHAT INTERFACE - Converts natural language to exploitation attempts
router.post('/ai/chat', gradedRoute(async (req, res) => {
  const { message, context, userId } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  console.log(`[AI Chat] User message: ${message}`);

  try {
    const result = await aiService.processSensitiveInfoRequest(message, context);
    
    // If AI generated an exploit payload, try to execute it
    let executionResult = null;
    let exploited = false;
    let flagFound = null;
    let exploitType = null;
    let accessedPath = null;

    if (result.payload && result.vulnerability) {
      try {
        // Auto-execute the payload
        if (result.vulnerability === 'path_traversal' || result.vulnerability.includes('traversal')) {
          const filePath = result.payload.replace(/^file:\/\//, '');
          const fileResult = legacySensitiveTools.readTeachingFile({path:filePath});
          
          accessedPath = filePath;
          
          if (fileResult.success) {
            const content = fileResult.content;
            
            const boundary=fileResult.boundary;
            const isSensitive=boundary.outsidePublic;
            
            executionResult = {
              success: true,
              content: content,
              flagFound: findChallengeFlag(content),
              accessedPath: filePath
            };

            if (isSensitive) {
              exploited = true;
              exploitType = 'AI-Driven Path Traversal';
            }

            if (typeof content==='string') {
              flagFound = findChallengeFlag(content);
              await req.gradeLegacy('ai_assisted_path_traversal',message,{...executionResult,boundary,modelResponse:result.response||'',payload:result.payload,payloadSelection:'scripted'},{real_model:actualModel(result)},flagFound,'ai_assisted_scripted_payload');
              await logFileAccess(req.user.id, filePath, 'read', 'exploited', req.ip, 'AI Assistant');
            }
          } else {
            executionResult = {
              success: false,
              error: 'File not found',
              hint: 'Try a different path or file name'
            };
          }
        } 
        else if (result.vulnerability === 'ssi_injection' || result.vulnerability.includes('ssi')) {
          // Process SSI payload
          let processed = result.payload;
          const originalPayload = processed;
          
          // Process #echo directives
          processed = processed.replace(/<!--#echo var="([^"]+)" -->/g, (match, varName) => {
            const vars = {
              'DATABASE_PASSWORD': 'Db@dmin#Pass2024',
              'API_KEY': 'sk-proj-abc123def456',
              'SECRET_TOKEN': 'ultra-secret-token-987654',
              'ADMIN_KEY': 'admin_key_12345',
              'SECRET_FLAG': SSI_FLAG
            };
            return vars[varName] || `[${varName} not found]`;
          });

          // Process #include directives
          const includeMatches = processed.matchAll(/<!--#include (virtual|file)="([^"]+)" -->/g);
          for (const match of includeMatches) {
            try {
              const included=legacySensitiveTools.readTeachingFile({path:match[2]});
              if (included.success) {
                const includeContent = included.content;
                processed = processed.replace(match[0], () => includeContent);
                accessedPath = match[2];
              }
            } catch (err) {
              // Silent fail
            }
          }

          // Check if anything was actually processed/changed
          const wasProcessed = processed !== originalPayload;
          
          if (wasProcessed) {
            exploited = true;
            exploitType = 'AI-Driven SSI Injection';
          }

          // Check for flags in processed content
          if (typeof processed==='string') {
            flagFound = findChallengeFlag(processed);
            await req.gradeLegacy('ai_assisted_ssi',message,{original:originalPayload,rendered:processed,modelResponse:result.response||'',payloadSelection:'scripted'},{real_model:actualModel(result)},flagFound,'ai_assisted_scripted_ssi');
          }

          executionResult = {
            success: true,
            rendered: processed,
            originalPayload: originalPayload,
            wasProcessed: wasProcessed
          };
        }
        else if (result.vulnerability === 'combined' || message.toLowerCase().includes('combined')) {
          // Handle combined exploitation
          exploited = true;
          exploitType = 'AI-Driven Combined Attack (Path Traversal + SSI)';
          
          executionResult = {
            success: true,
            message: 'Combined exploitation technique recognized',
            hint: 'Try using path traversal to access a file, then process it with SSI directives'
          };
        }
      } catch (execError) {
        executionResult = {
          success: false,
          error: execError.message
        };
      }
    }

    // Enhanced response with more context
    let enhancedResponse = result.response;
    
    if (result.payload) {
      enhancedResponse += `\n\n🔧 I've generated a payload for you: \`${result.payload}\``;
    }
    
    if (executionResult && executionResult.success) {
      if (executionResult.content) {
        const preview = executionResult.content.length > 200 
          ? executionResult.content.substring(0, 200) + '...' 
          : executionResult.content;
        enhancedResponse += `\n\n📄 I was able to access the file!`;
      } else if (executionResult.rendered) {
        enhancedResponse += `\n\n✅ Template processed successfully!`;
      }
    }

    res.json({
      success: true,
      message: message,
      aiResponse: enhancedResponse,
      payload: result.payload,
      vulnerability: result.vulnerability,
      executionResult: executionResult,
      model: result.model,
      exploited: exploited,
      exploitType: exploitType,
      flagFound: flagFound,
      combinedExploit: exploitType && exploitType.includes('Combined'),
      hint: result.suggestion || (executionResult && executionResult.hint)
    });

  } catch (error) {
    console.error('AI chat error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      aiResponse: "I'm here to help, but I encountered an error. Try asking me to read a file or process a template."
    });
  }
}));

// ============================================
// UTILITY ENDPOINTS
// ============================================

// Get list of public documents
router.get('/documents/list', async (req, res) => {
  try {
    const documents = await getPublicDocuments();
    res.json({
      success: true,
      documents: documents,
      message: 'Public documents retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get file access logs (for educational tracking)
router.get('/logs/access', async (req, res) => {
  try {
    const logs = await getAccessLogs(...(engine==='postgres'?[req.user.id,100]:[100]));
    res.json({
      success: true,
      logs: logs,
      count: logs.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get challenge statistics
if(engine==='postgres'){
 router.post('/progress/reset',async(req,res,next)=>{
  let aggregate;
  try{aggregate=await resolveCanonicalComposition();}
  catch{return res.status(503).json({success:false,unavailable:true,error:'Canonical Legacy Sensitive reset is not ready'});}
  if(!aggregate)return res.status(503).json({success:false,unavailable:true,
   error:'Canonical Legacy Sensitive reset is disabled for maintenance'});
  try{const result=await aggregate.reset.reset(req.user.id,{operationId:req.get('x-reset-operation-id')||undefined});
   return res.json({success:true,reset:{operationId:result.operationId,fromGeneration:result.fromGeneration,
    toGeneration:result.toGeneration,status:result.status}});}
  catch(error){if(error instanceof TypeError)return res.status(400).json({success:false,error:'Invalid reset operation'});
   if(error?.name==='AbortError'||['LEGACY_FILE_SSI_RESET_BUSY','LEGACY_FILE_SSI_RESET_SCOPE_MISMATCH'].includes(error?.code))return res.status(409).json({success:false,error:'Reset unavailable'});
   return next(error);}
 });
}

router.get('/stats', async (req, res) => {
  try {
    const stats = await getChallengeStats(req.user.id);
    res.json({
      success: true,
      stats: stats,
      totalChallenges: stats.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get available vulnerabilities and their descriptions
router.get('/vulnerabilities/info', (req, res) => {
  res.json({
    success: true,
    vulnerabilities: [
      {
        id: 'path_traversal',
        name: 'Directory/Path Traversal',
        description: 'Access files outside the intended directory using ../ sequences',
        difficulty: 'Medium',
        flags: 7,
        examples: [
          '../secret/database_credentials.txt',
          '../admin/admin_passwords.txt',
          '../../etc/passwd'
        ]
      },
      {
        id: 'ssi_injection',
        name: 'Server Side Include (SSI) Injection',
        description: 'Inject SSI directives into a lab interpreter. File inclusion reads isolated teaching files; command output comes from a fixed simulator and does not execute operating-system commands.',
        executionMode: 'lab_ssi_interpreter',
        difficulty: 'Hard',
        flags: 3,
        examples: [
          '<!--#echo var="DATABASE_PASSWORD" -->',
          '<!--#include virtual="../secret/api_keys.json" -->',
          '<!--#exec cmd="whoami" -->'
        ]
      },
      {
        id: 'combined',
        name: 'Combined Path Traversal + SSI',
        description: 'Combine both vulnerabilities for maximum impact',
        difficulty: 'Expert',
        flags: 2,
        examples: [
          'Load ../admin/config.txt with SSI processing enabled',
          'Include ../secret/credentials.txt and echo sensitive vars'
        ]
      },
      {
        id: 'ai_assisted',
        name: 'AI-Assisted Exploitation',
        description: 'Use AI to generate and execute payloads from natural language',
        difficulty: 'Advanced',
        flags: 5,
        examples: [
          'Hey AI, help me read the database credentials file',
          'Generate a payload to access admin passwords',
          'Show me how the lab SSI command simulator processes a directive'
        ]
      }
    ],
    totalFlags: 17,
    tips: [
      'Start with simple path traversal: try accessing ../secret/ files',
      'Learn SSI syntax: <!--#echo var="VARIABLE" -->',
      'Combine techniques for more complex exploits',
      'Use the AI assistant to generate payloads from natural language',
      'Check access logs to see what worked',
      'Inspect actual file content and Judge feedback; a FLAG marker alone does not establish completion',
      'SSI command output is simulated; file inclusion uses isolated teaching files'
    ]
  });
});

module.exports = router;
