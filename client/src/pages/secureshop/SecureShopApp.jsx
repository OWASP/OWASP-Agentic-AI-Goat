import React, { lazy, Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import SSv2Shell from './components/Shell';
import SSv2RequireAuth from './components/RequireAuth';
import { AuthProvider as SSv2AuthProvider } from './context/AuthContext';
import Spinner from './components/Spinner';

// SecureShop v2 pages (lazy — only loaded when a user enters /secureshop)
const SSv2Home = lazy(() => import('./pages/Home'));
const SSv2Catalog = lazy(() => import('./pages/Catalog'));
const SSv2Product = lazy(() => import('./pages/Product'));
const SSv2Cart = lazy(() => import('./pages/Cart'));
const SSv2Checkout = lazy(() => import('./pages/Checkout'));
const SSv2Orders = lazy(() => import('./pages/Orders'));
const SSv2Account = lazy(() => import('./pages/Account'));
const SSv2Inbox = lazy(() => import('./pages/Inbox'));
const SSv2MOverview = lazy(() => import('./pages/merchant/Overview'));
const SSv2MListings = lazy(() => import('./pages/merchant/Listings'));
const SSv2MReviews = lazy(() => import('./pages/merchant/Reviews'));
const SSv2MPricing = lazy(() => import('./pages/merchant/Pricing'));
const SSv2MAnalytics = lazy(() => import('./pages/merchant/Analytics'));
const SSv2MInbox = lazy(() => import('./pages/merchant/Inbox'));
const SSv2AOverview = lazy(() => import('./pages/admin/Overview'));
const SSv2AUsers = lazy(() => import('./pages/admin/Users'));
const SSv2AAudit = lazy(() => import('./pages/admin/Audit'));
const SSv2ATickets = lazy(() => import('./pages/admin/Tickets'));
const SSv2APolicies = lazy(() => import('./pages/admin/Policies'));
const SSv2AMCP = lazy(() => import('./pages/admin/MCP'));
const SSv2ASystem = lazy(() => import('./pages/admin/System'));
const SSv2AAccessControl = lazy(() => import('./pages/admin/AccessControl'));
const SSv2Login = lazy(() => import('./pages/Login'));
const SSv2Register = lazy(() => import('./pages/Register'));
const SSv2Landing = lazy(() => import('./pages/Landing'));
const SSv2NotFound = lazy(() => import('./pages/NotFound'));

function SuspenseFallback() {
  return (
    <div className="ss-root" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
      <Spinner label="Opening SecureShop page" />
    </div>
  );
}

function SecureShopApp() {
  // M7 cutover — `/secureshop/*` and the transitional `/secureshop/v2/*` alias
  // both point at the SecureShop v2 pages. The alias exists so bookmarks and
  // any external links from M2–M6 continue to work.
  //
  // M8 Task C — wrap the entire mount in <SSv2AuthProvider>. /login and
  // /register are public; everything under the Shell is behind <SSv2RequireAuth>.
  // The landing home (index /) is currently protected too — Wave 2 will split
  // out a public Landing when the marketing home is rebuilt.
  return (
    <SSv2AuthProvider>
      <Suspense fallback={<SuspenseFallback />}>
      <Routes>
        {/* Public marketing landing (Wave 2A) */}
        <Route path="/secureshop" element={<SSv2Landing />} />

        {/* Public auth surfaces */}
        <Route path="/secureshop/login" element={<SSv2Login />} />
        <Route path="/secureshop/register" element={<SSv2Register />} />

        {/* Authed home lives at /secureshop/home */}
        <Route path="/secureshop/home" element={<SSv2RequireAuth requireRole="customer"><SSv2Shell /></SSv2RequireAuth>}>
          <Route index element={<SSv2Home />} />
        </Route>

        {/* M12 D2 — Public catalog surface. Real e-commerce sites let guests
            browse the catalog, view products, and inspect the cart. Only the
            checkout / orders / account / inbox routes require auth. Cart
            operations still call the backend, which degrades gracefully when
            unauth (CartContext no-ops loading; POST /cart returns friendly
            error the UI surfaces as "Sign in to save your cart"). */}
        <Route path="/secureshop" element={<SSv2Shell />}>
          <Route path="catalog" element={<SSv2Catalog />} />
          <Route path="product/:id" element={<SSv2Product />} />
          <Route path="cart" element={<SSv2Cart />} />
        </Route>

        {/* Authed customer surface — checkout, orders, account, inbox */}
        <Route path="/secureshop" element={<SSv2RequireAuth><SSv2Shell /></SSv2RequireAuth>}>
          <Route path="checkout" element={<SSv2Checkout />} />
          <Route path="orders" element={<SSv2Orders />} />
          <Route path="account" element={<SSv2Account />} />
          <Route path="inbox" element={<SSv2Inbox />} />
        </Route>

        {/* Merchant surface — Wave 5B U6: requireRole="merchant". */}
        <Route path="/secureshop" element={<SSv2RequireAuth requireRole="merchant"><SSv2Shell /></SSv2RequireAuth>}>
          <Route path="merchant" element={<SSv2MOverview />} />
          <Route path="merchant/listings" element={<SSv2MListings />} />
          <Route path="merchant/reviews" element={<SSv2MReviews />} />
          <Route path="merchant/pricing" element={<SSv2MPricing />} />
          <Route path="merchant/analytics" element={<SSv2MAnalytics />} />
          <Route path="merchant/inbox" element={<SSv2MInbox />} />
        </Route>

        {/* Admin surface — Wave 5B U6: requireRole="admin". */}
        <Route path="/secureshop" element={<SSv2RequireAuth requireRole="admin"><SSv2Shell /></SSv2RequireAuth>}>
          <Route path="admin" element={<SSv2AOverview />} />
          <Route path="admin/users" element={<SSv2AUsers />} />
          <Route path="admin/audit" element={<SSv2AAudit />} />
          <Route path="admin/tickets" element={<SSv2ATickets />} />
          <Route path="admin/policies" element={<SSv2APolicies />} />
          <Route path="admin/mcp" element={<SSv2AMCP />} />
          <Route path="admin/system" element={<SSv2ASystem />} />
          <Route path="admin/access-control" element={<SSv2AAccessControl />} />
        </Route>

        {/* Transitional alias — preserved so M2–M6 bookmarks still work.
            M12 D2 — public catalog also applies to the /v2 alias. */}
        <Route path="/secureshop/v2" element={<SSv2Shell />}>
          <Route path="catalog" element={<SSv2Catalog />} />
          <Route path="product/:id" element={<SSv2Product />} />
          <Route path="cart" element={<SSv2Cart />} />
        </Route>
        <Route path="/secureshop/v2" element={<SSv2RequireAuth><SSv2Shell /></SSv2RequireAuth>}>
          <Route index element={<SSv2RequireAuth requireRole="customer"><SSv2Home /></SSv2RequireAuth>} />
          <Route path="checkout" element={<SSv2Checkout />} />
          <Route path="orders" element={<SSv2Orders />} />
          <Route path="account" element={<SSv2Account />} />
          <Route path="inbox" element={<SSv2Inbox />} />
        </Route>
        <Route path="/secureshop/v2" element={<SSv2RequireAuth requireRole="merchant"><SSv2Shell /></SSv2RequireAuth>}>
          <Route path="merchant" element={<SSv2MOverview />} />
          <Route path="merchant/listings" element={<SSv2MListings />} />
          <Route path="merchant/reviews" element={<SSv2MReviews />} />
          <Route path="merchant/pricing" element={<SSv2MPricing />} />
          <Route path="merchant/analytics" element={<SSv2MAnalytics />} />
          <Route path="merchant/inbox" element={<SSv2MInbox />} />
        </Route>
        <Route path="/secureshop/v2" element={<SSv2RequireAuth requireRole="admin"><SSv2Shell /></SSv2RequireAuth>}>
          <Route path="admin" element={<SSv2AOverview />} />
          <Route path="admin/users" element={<SSv2AUsers />} />
          <Route path="admin/audit" element={<SSv2AAudit />} />
          <Route path="admin/tickets" element={<SSv2ATickets />} />
          <Route path="admin/policies" element={<SSv2APolicies />} />
          <Route path="admin/mcp" element={<SSv2AMCP />} />
          <Route path="admin/system" element={<SSv2ASystem />} />
          <Route path="admin/access-control" element={<SSv2AAccessControl />} />
        </Route>

        {/* Fallback 404 under the SecureShop mount */}
        <Route path="/secureshop/*" element={<SSv2NotFound />} />
      </Routes>
      </Suspense>
    </SSv2AuthProvider>
  );
}

export default SecureShopApp;
