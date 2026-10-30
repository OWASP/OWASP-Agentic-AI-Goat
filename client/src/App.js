import { hasPlatformAdminLevel } from './utils/platformAdmin';
import React, { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

// --- Eager imports: layout, the initial auth path, and small structural
// components stay in the main chunk so the first paint is instant. Everything
// else is lazy-loaded below (route-based code splitting) to keep the initial
// JS bundle small instead of shipping every page up front.
import WorkshopNavbar from './components/WorkshopNavbar';
import LandingPage from './pages/LandingPage';
import WorkshopLogin from './pages/WorkshopLogin';
import WorkshopSignup from './pages/WorkshopSignup';
import SecureShopSpinner from './pages/secureshop/components/Spinner';

// Context + structural
import { AuthProvider, useAuth } from './context/AuthContext';
import { WorkshopConfigProvider } from './context/WorkshopConfigContext';
import ErrorBoundary from './components/ErrorBoundary';
import VisibilityProtectedRoute from './components/VisibilityProtectedRoute';

// --- Lazy-loaded pages: each becomes its own chunk fetched on first visit.
const WorkshopChallenges = lazy(() => import('./pages/WorkshopChallenges'));
const AgentRunsPage = lazy(() => import('./pages/AgentRunsPage'));
const XSSWorkshop = lazy(() => import('./pages/challenges/XSSWorkshop'));
const CSRFWorkshop = lazy(() => import('./pages/challenges/CSRFWorkshop'));
const DirectPromptInjectionChallenge = lazy(() => import('./pages/challenges/DirectPromptInjectionChallenge'));
const IndirectPromptInjectionChallenge = lazy(() => import('./pages/challenges/IndirectPromptInjectionChallenge'));
const MCPWorkshop = lazy(() => import('./pages/challenges/MCPWorkshop'));
const ExcessiveAgencyBolaLab = lazy(() => import('./pages/challenges/ExcessiveAgencyBolaLab'));
const CTFDashboard = lazy(() => import('./pages/CTFDashboard'));
const CTFChallenge = lazy(() => import('./pages/CTFChallenge'));
const CTFLeaderboard = lazy(() => import('./pages/CTFLeaderboard'));
const SQLWorkshop = lazy(() => import('./pages/workshops/SQLWorkshop'));
const NoSQLWorkshop = lazy(() => import('./pages/workshops/NoSQLWorkshop'));
const SensitiveInfoWorkshop = lazy(() => import('./pages/workshops/SensitiveInfoWorkshop'));
const LegacyFileSsiWorkshopPage = lazy(() => import('./pages/workshops/LegacyFileSsiWorkshopPage'));
const SupplyChainWorkshop = lazy(() => import('./pages/workshops/SupplyChainWorkshop'));
const SecureShopWorkshop = lazy(() => import('./pages/secureshop/SecureShopWorkshop'));
const SecureShopGuestLanding = lazy(() => import('./pages/secureshop/SecureShopGuestLanding'));
const SecureShopStandalone = lazy(() => import('./pages/secureshop/SecureShopStandalone'));
const AIAssistant = lazy(() => import('./pages/labs/AIAssistant'));
const SessionDisclosureDemo = lazy(() => import('./pages/SessionDisclosureDemo'));
const UserProfile = lazy(() => import('./pages/UserProfile'));
const EditProfile = lazy(() => import('./pages/EditProfile'));
const UserActivity = lazy(() => import('./pages/UserActivity'));
const ComprehensiveAdminDashboard = lazy(() => import('./pages/ComprehensiveAdminDashboard'));

// Lightweight fallback shown while a lazy route chunk downloads.
function SuspenseFallback() {
  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
      <div style={{
        width: '40px', height: '40px',
        border: '4px solid #f3f3f3', borderTop: '4px solid #667eea',
        borderRadius: '50%', animation: 'spin 1s linear infinite'
      }} />
    </div>
  );
}

function SecureShopFallback({ message = 'Opening OWASP AI SecureShop…', error, onRetry }) {
  return <main style={{ minHeight: '100dvh', display: 'grid', placeItems: 'center',
    background: '#f7f5f0', color: '#252525', fontFamily: 'Inter, sans-serif' }}>
    <div style={{ textAlign: 'center', padding: 24 }}>
      <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.12em', marginBottom: 20 }}>OWASP AI SecureShop</div>
      {!error && <SecureShopSpinner aria-hidden="true" style={{
        display: 'block', width: 20, height: 20, margin: '0 auto 20px',
        border: '2px solid rgba(11,13,16,0.15)', borderTopColor: '#E5451A',
        borderRadius: 999, animation: 'spin 800ms linear infinite',
      }} />}
      <p role={error ? 'alert' : 'status'}>{error || message}</p>
      {error && <button type="button" onClick={onRetry}>Retry session check</button>}
    </div>
  </main>;
}

function AppContent() {
  return (
    <ErrorBoundary>
      <div>
        <WorkshopApp />
      </div>
    </ErrorBoundary>
  );
}

function WorkshopApp() {
  const { user, loading, authError, checkAuthStatus } = useAuth();
  const location = useLocation();
  const isShop = location.pathname === '/secureshop' || location.pathname.startsWith('/secureshop/');

  if (loading || (authError && !user)) {
    if (isShop) return <SecureShopFallback error={authError && !user ? authError : null}
      onRetry={checkAuthStatus} />;
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      }}>
        <div style={{
          background: 'white',
          padding: '40px',
          borderRadius: '12px',
          boxShadow: '0 20px 40px rgba(0,0,0,0.1)',
          textAlign: 'center'
        }}>
          <div style={{
            width: '40px',
            height: '40px',
            border: '4px solid #f3f3f3',
            borderTop: '4px solid #667eea',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 20px'
          }}></div>
          <h3>{authError || 'Loading Workshop...'}</h3>
          {authError && <button type="button" onClick={checkAuthStatus}>Retry session check</button>}
        </div>
      </div>
    );
  }

  return (
    <WorkshopConfigProvider token={user ? localStorage.getItem('token') : null}>
      <div className={isShop ? 'SecureShopHost' : 'Workshop'}>
      <Suspense fallback={isShop ? <SecureShopFallback /> : <SuspenseFallback />}>
      <Routes>
        <Route path="/" element={user ? <Navigate to="/workshop/challenges" replace /> : <LandingPage />} />
        <Route path="/workshop/login" element={<WorkshopLogin />} />
        <Route path="/workshop/signup" element={<WorkshopSignup />} />
        <Route path="/workshop-login" element={<Navigate to="/workshop/login" replace />} />
        <Route path="/login" element={<Navigate to="/workshop/login" replace />} />
        <Route path="/workshop-dashboard" element={
          user ? <Navigate to="/workshop/challenges" replace /> : <Navigate to="/workshop-login" replace />
        } />
        <Route path="/workshop/challenges" element={
          user ? (
            <>
              <WorkshopNavbar />
              <WorkshopChallenges />
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop/agent-runs" element={
          user ? (<><WorkshopNavbar /><AgentRunsPage /></>) : <Navigate to="/workshop-login" />
        } />
        {/* Legacy student destinations resolve to the canonical exercise library. */}
        <Route path="/workshop/progress" element={
          user ? <Navigate to="/workshop/challenges" replace /> : <Navigate to="/workshop-login" replace />
        } />
        <Route path="/workshop/profile" element={
          user ? (
            <>
              <WorkshopNavbar />
              <UserProfile />
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop/edit-profile" element={
          user ? (
            <>
              <WorkshopNavbar />
              <EditProfile />
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop/user-activity" element={
          user ? (
            <>
              <WorkshopNavbar />
              <UserActivity />
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop/sql" element={
          user ? (
            <VisibilityProtectedRoute challengeId="sql_injection_workshop">
              <WorkshopNavbar />
              <SQLWorkshop />
            </VisibilityProtectedRoute>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop/nosql" element={
          user ? (
            <VisibilityProtectedRoute challengeId="nosql_injection_workshop">
              <WorkshopNavbar />
              <NoSQLWorkshop />
            </VisibilityProtectedRoute>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop" element={
          user ? <Navigate to="/workshop/challenges" replace /> : <Navigate to="/workshop-login" />
        } />
        <Route path="/admin" element={
          hasPlatformAdminLevel(user) ? (
            <Navigate to="/admin/dashboard" replace />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/dashboard" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/students" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/locked-users" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/student-workshop-view" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/exercises" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        {/* Merged into Exercises Management */}
        <Route path="/admin/challenges" element={<Navigate to="/admin/exercises" replace />} />
        <Route path="/admin/vulnerability-visibility" element={<Navigate to="/admin/exercises" replace />} />
        <Route path="/admin/activity" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/settings" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        {/* Merged into Exercises Management */}
        <Route path="/admin/solutions" element={<Navigate to="/admin/exercises" replace />} />
        <Route path="/admin/progress-analytics" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/llm-health" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/ai-providers" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/server-logs" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin/agent-runs" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (<Navigate to="/workshop/challenges" replace />) : (<Navigate to="/workshop-login" />)
        } />
        <Route path="/admin/ctf-management" element={
          hasPlatformAdminLevel(user) ? (
            <ComprehensiveAdminDashboard />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
        <Route path="/admin-dashboard" element={
          hasPlatformAdminLevel(user) ? (
            <Navigate to="/admin/dashboard" replace />
          ) : user ? (
            <Navigate to="/workshop/challenges" replace />
          ) : (
            <Navigate to="/workshop-login" />
          )
        } />
         <Route path="/vulnerabilities/xss" element={
           user ? (
             <VisibilityProtectedRoute challengeId="reflected_xss_llm" alternateChallengeId="xss_email_builder">
               <WorkshopNavbar />
               <XSSWorkshop />
             </VisibilityProtectedRoute>
           ) : <Navigate to="/workshop-login" />
         } />
         <Route path="/vulnerabilities/csrf-via-ai" element={
           user ? (
             <VisibilityProtectedRoute challengeId="csrf_prompt_injection">
               <WorkshopNavbar />
               <CSRFWorkshop />
             </VisibilityProtectedRoute>
           ) : <Navigate to="/workshop-login" />
         } />
         <Route path="/vulnerabilities/direct-prompt-injection" element={
           user ? (
             <VisibilityProtectedRoute challengeId="direct_prompt_injection">
               <WorkshopNavbar />
               <DirectPromptInjectionChallenge />
             </VisibilityProtectedRoute>
           ) : <Navigate to="/workshop-login" />
         } />
          <Route path="/vulnerabilities/indirect-prompt-injection" element={
           user ? (
             <VisibilityProtectedRoute challengeId="indirect_prompt_injection">
               <WorkshopNavbar />
               <IndirectPromptInjectionChallenge />
             </VisibilityProtectedRoute>
           ) : <Navigate to="/workshop-login" />
         } />
        <Route path="/vulnerabilities/ctf-prompt-injection" element={
          <Navigate to="/ctf" replace />
        } />
        <Route path="/vulnerabilities/sensitive-info-disclosure" element={
          user ? (
            <VisibilityProtectedRoute challengeId="sensitive_info_disclosure">
              <WorkshopNavbar />
              <SensitiveInfoWorkshop challengeId="sensitive_info_disclosure" />
            </VisibilityProtectedRoute>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/vulnerabilities/mcp-server" element={
          user ? (
            <VisibilityProtectedRoute challengeId="mcp_server_rce">
              <WorkshopNavbar />
              <MCPWorkshop />
            </VisibilityProtectedRoute>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/vulnerabilities/excessive-agency" element={
          user ? (
            <VisibilityProtectedRoute challengeId="excessive_agency">
              <WorkshopNavbar />
              <ExcessiveAgencyBolaLab />
            </VisibilityProtectedRoute>
          ) : <Navigate to="/workshop-login" />
        } />
         
         <Route path="/workshop/file-ssi" element={
           user ? <VisibilityProtectedRoute challengeId="legacy_sensitive_file_ssi"><WorkshopNavbar /><LegacyFileSsiWorkshopPage /></VisibilityProtectedRoute> : <Navigate to="/workshop-login" />
         } />
         <Route path="/workshop/sensitive-info" element={
           user ? (
             <VisibilityProtectedRoute challengeId="sensitive_info_disclosure">
               <WorkshopNavbar />
               <SensitiveInfoWorkshop />
             </VisibilityProtectedRoute>
           ) : <Navigate to="/workshop-login" />
         } />

         <Route path="/workshop/supply-chain" element={
           user ? (
             <VisibilityProtectedRoute challengeId="supply_chain_rce">
               <WorkshopNavbar />
               <SupplyChainWorkshop />
             </VisibilityProtectedRoute>
           ) : <Navigate to="/workshop-login" />
         } />

         <Route path="/workshop/secureshop" element={<Navigate to="/secureshop" replace />} />
         <Route path="/secureshop/*" element={
           user ? (
             <VisibilityProtectedRoute challengeId="secureshop_agent_security" visibilityEndpoint="/api/workshop/applications/secureshop" presentation="application" fallbackRoute="/">
               <SecureShopWorkshop />
             </VisibilityProtectedRoute>
           ) : <SecureShopGuestLanding />
         } />

        {/* CTF Routes - Separate CTF System */}
         <Route path="/ctf" element={
           user ? (
             <>
               <WorkshopNavbar />
               <CTFDashboard />
             </>
           ) : <Navigate to="/workshop-login" />
         } />
         <Route path="/ctf/challenge" element={
           user ? (
             <>
               <WorkshopNavbar />
               <CTFChallenge />
             </>
           ) : <Navigate to="/workshop-login" />
         } />
         <Route path="/ctf/leaderboard" element={
           user ? (
             <>
               <WorkshopNavbar />
               <CTFLeaderboard />
             </>
           ) : <Navigate to="/workshop-login" />
         } />
         <Route path="/ctf/dashboard" element={
           user ? (
             <>
               <WorkshopNavbar />
               <CTFDashboard />
             </>
           ) : <Navigate to="/workshop-login" />
         } />
        <Route path="/ecommerce/ai-assistant" element={
          user ? (
            <>
              <WorkshopNavbar />
              <AIAssistant />
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/ecommerce/product/:id" element={
          user ? (
            <>
              <WorkshopNavbar />
              <div style={{
                minHeight: '100vh',
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                textAlign: 'center',
                padding: '2rem'
              }}>
                <div>
                  <h1>🔍 XSS Scenario Briefing: Product Reviews</h1>
                  <p>This static page introduces stored-XSS risk in review systems.</p>
                  <p>There is no review form or graded objective on this page.</p>
                  <div style={{ marginTop: '2rem', padding: '1rem', background: 'rgba(255,255,255,0.1)', borderRadius: '10px' }}>
                    <h3>Objectives:</h3>
                    <ul style={{ textAlign: 'left', maxWidth: '400px', margin: '0 auto' }}>
                      <li>Recognize an unsanitized review sink</li>
                      <li>Distinguish stored from reflected XSS</li>
                      <li>Use the XSS workshop for browser exercises</li>
                    </ul>
                  </div>
                </div>
              </div>
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/ecommerce/checkout" element={
          user ? (
            <>
              <WorkshopNavbar />
              <div style={{
                minHeight: '100vh',
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                textAlign: 'center',
                padding: '2rem'
              }}>
                <div>
                  <h1>🛡️ CSRF Scenario Briefing: Checkout Process</h1>
                  <p>This static page introduces cross-site request forgery in payment systems.</p>
                  <p>This page does not submit transactions or award objective credit.</p>
                  <div style={{ marginTop: '2rem', padding: '1rem', background: 'rgba(255,255,255,0.1)', borderRadius: '10px' }}>
                    <h3>Objectives:</h3>
                    <ul style={{ textAlign: 'left', maxWidth: '400px', margin: '0 auto' }}>
                      <li>Recognize a missing anti-CSRF token</li>
                      <li>Describe a cross-site form request</li>
                      <li>Identify cookie and origin prerequisites</li>
                      <li>Use the CSRF workshop for executed effects</li>
                    </ul>
                    <a href="/vulnerabilities/csrf-via-ai?scenario=post&objective=csrf_p1"
                      style={{ display: 'inline-block', marginTop: '1rem', color: 'white', fontWeight: 700 }}>
                      Open the graded POST CSRF exercise
                    </a>
                  </div>
                </div>
              </div>
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/ecommerce/profile" element={
          user ? (
            <>
              <WorkshopNavbar />
              <div style={{
                minHeight: '100vh',
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                textAlign: 'center',
                padding: '2rem'
              }}>
                <div>
                  <h1>📁 File Upload Scenario Briefing</h1>
                  <p>This static page introduces unrestricted-upload risk.</p>
                  <p>This page does not upload or execute files, or award objective credit.</p>
                  <div style={{ marginTop: '2rem', padding: '1rem', background: 'rgba(255,255,255,0.1)', borderRadius: '10px' }}>
                    <h3>Objectives:</h3>
                    <ul style={{ textAlign: 'left', maxWidth: '400px', margin: '0 auto' }}>
                      <li>Identify missing file validation</li>
                      <li>Explain type-validation bypasses</li>
                      <li>Distinguish file storage from server-side execution</li>
                    </ul>
                  </div>
                </div>
              </div>
            </>
          ) : <Navigate to="/workshop-login" />
        } />
        <Route path="/workshop/session-demo" element={
          user ? <SessionDisclosureDemo key={user.id} /> : <Navigate to="/workshop-login" />
        } />
      </Routes>
      </Suspense>
      <ToastContainer
        position="top-right"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={true}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="colored"
        limit={3}
      />
      </div>
    </WorkshopConfigProvider>
  );
}

function AppSurface() {
  const location = useLocation();
  if (/^\/secureshop\/v2\/(?:login|register)\/?$/.test(location.pathname)) {
    return <Navigate to={{ pathname: location.pathname.replace(/^\/secureshop\/v2\/(login|register)\/?$/, '/secureshop/$1'),
      search: location.search, hash: location.hash }} replace />;
  }
  if (location.pathname === '/secureshop' || location.pathname.startsWith('/secureshop/')) {
    return <Suspense fallback={<SecureShopFallback />}><SecureShopStandalone /></Suspense>;
  }
  return <AuthProvider><AppContent /></AuthProvider>;
}

function App() {
  return (
    <ErrorBoundary>
      <Router>
        <AppSurface />
      </Router>
    </ErrorBoundary>
  );
}

export default App;
