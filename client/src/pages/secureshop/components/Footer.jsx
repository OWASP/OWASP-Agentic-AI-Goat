import React from 'react';
import { Link } from 'react-router-dom';

/**
 * SecureShop v2 Footer — category shortcuts, legal stubs, disclosure text.
 */
export default function Footer() {
  return (
    <footer className="ss-footer">
      <div className="ss-footer__grid">
        <div>
          <div className="ss-footer__brand">SecureShop</div>
          <div style={{ maxWidth: '46ch', fontSize: 13, opacity: 0.75, lineHeight: 1.5, marginBottom: 12 }}>
            An agentic e-commerce demo. Product summaries are written by LLMs.
            Reviews are moderated by LLMs. Prices are set by LLMs. Watch the
            agent lane on the right — that's the honest surface of an agentic system.
          </div>
          <div style={{ fontSize: 11, fontFamily: 'var(--mono)', opacity: 0.55, lineHeight: 1.5 }}>
            NOTE — SecureShop is a security teaching lab. Every "vulnerability" is
            intentional. Do not enter real payment credentials.
          </div>
        </div>
        <div>
          <div className="ss-footer__title">Shop</div>
          <Link className="ss-footer__link" to="/secureshop/catalog?category=Electronics">Electronics</Link>
          <Link className="ss-footer__link" to="/secureshop/catalog?category=Books">Books</Link>
          <Link className="ss-footer__link" to="/secureshop/catalog?category=Home%20%26%20Kitchen">Home</Link>
          <Link className="ss-footer__link" to="/secureshop/catalog?category=Beauty">Beauty</Link>
          <Link className="ss-footer__link" to="/secureshop/catalog">All catalog</Link>
        </div>
        <div>
          <div className="ss-footer__title">Account</div>
          <Link className="ss-footer__link" to="/secureshop/account">Profile</Link>
          <Link className="ss-footer__link" to="/secureshop/orders">Orders</Link>
          <Link className="ss-footer__link" to="/secureshop/inbox">Inbox</Link>
          <Link className="ss-footer__link" to="/secureshop/cart">Cart</Link>
        </div>
        <div>
          <div className="ss-footer__title">About</div>
          {/* MemoryRouter keeps section hashes inside the opaque shop frame. */}
          <Link className="ss-footer__link" to="/secureshop#about">How SecureShop thinks</Link>
          <Link className="ss-footer__link" to="/secureshop#agent-lane">Agent lane</Link>
          <Link className="ss-footer__link" to="/secureshop#lab-notes">Lab notes</Link>
          <a
            className="ss-footer__link"
            href="https://github.com/hackerabhinavverma/Damn-Vulnerable-AI-Application"
            target="_blank"
            rel="noreferrer"
          >
            Source on GitHub
          </a>
        </div>
      </div>
      <div className="ss-footer__legal">
        © 2026 SecureShop · An educational agentic-commerce lab · v2
      </div>
    </footer>
  );
}
