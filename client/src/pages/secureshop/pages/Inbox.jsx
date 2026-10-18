import MailMessageBody from '../components/MailMessageBody.jsx';
import MailCapabilityStatus from './MailCapabilityStatus';
import MailAssessment from './MailAssessment';
import { useRequests, readResponse, persistedId, useMailCommands } from './mailRequests';
import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Mail, Send, Archive, Reply, Inbox as InboxIcon, Sparkles } from 'lucide-react';

import Button from '../components/Button.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Badge from '../components/Badge.jsx';
import Dialog from '../components/Dialog.jsx';
import Input from '../components/Input.jsx';
import Spinner from '../components/Spinner.jsx';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext.jsx';
import PersonaInboxLab from '../components/PersonaInboxLab.jsx';

/**
 * Inbox.jsx — 2-column: thread list + thread view.
 *
 * intentional — teaches xss-stored-email + html-injection: body_html rendered
 * via dangerouslySetInnerHTML.
 */
export default function Inbox() {
  const { user, token } = useAuth();
  // Changing persona or credentials destroys all pending UI work and selections.
  const authority = useRef({});
  const previous = authority.current;
  if (previous.id !== user?.id || previous.role !== user?.role || previous.token !== token || previous.transport !== fetch) {
    authority.current = { id: user?.id, role: user?.role, token, transport: fetch, epoch: (previous.epoch || 0) + 1 };
  }
  return <InboxSession key={authority.current.epoch || 0} />;
}


function InboxSession() {
  const { user } = useAuth();
  const toast = useToast();
  const reduce = useReducedMotion();
  const userId = user?.id;
  const request = useRequests();
  const mail = useMailCommands();
  const loadVersion = useRef(0);
  const replying = useRef(false);

  const [emails, setEmails] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [autoReplyBusy, setAutoReplyBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [autoReplyResults, setAutoReplyResults] = useState({});
  const [composeOpen, setComposeOpen] = useState(false);
  const recoveryRunning = useRef(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [pendingUnconfirmed, setPendingUnconfirmed] = useState(null);
  const [unresolvedStatus, setUnresolvedStatus] = useState({});

  const load = async () => {
    const version = ++loadVersion.current;
    const pending = request();
    setLoading(true); setLoadError(null);
    try {
      if (!userId) throw new Error('Sign in to load your inbox');
      const j = await readResponse(await mail.read(userId, pending.signal));
      if (!Array.isArray(j.emails)) throw new Error('Invalid inbox response');
      if (pending.signal.aborted || version !== loadVersion.current) return;
      setEmails(j.emails);
      setSelected(previous => j.emails.find(email => email.id === previous?.id) || null);
    } catch (e) {
      if (!pending.signal.aborted && version === loadVersion.current) {
        setEmails([]); setSelected(null); setLoadError(e.message);
      }
    } finally {
      if (!pending.signal.aborted && version === loadVersion.current) setLoading(false);
      pending.finish();
    }
  };

  useEffect(() => { void load(); }, [userId]);

  const runAutoReply = async (thread_id) => {
    if (replying.current) return;
    replying.current = true; setAutoReplyBusy(true);
    const pending = request();
    setAutoReplyResults(previous => {
      const next = { ...previous };
      delete next[thread_id];
      return next;
    });
    try {
      const j = await readResponse(await mail.command('autoReply', {}, pending.signal, thread_id));
      if (j.status === 'declined') {
        if (j.terminalNoSend !== true || j.threadId !== thread_id || typeof j.requestId !== 'string')
          throw new Error('Auto-reply outcome is unresolved; use Check pending mail');
        if (!pending.signal.aborted) {
          setAutoReplyResults(previous => ({ ...previous, [thread_id]: j }));
          toast.info('Auto-reply finished without a confirmed saved reply');
        }
        return;
      }
      if (!persistedId(j.sent_email_id)) throw new Error('No saved reply was confirmed');
      if (pending.signal.aborted) return;
      setAutoReplyResults(previous => ({ ...previous, [thread_id]: j }));
      toast.success('Auto-reply saved to lab mail');
      void load();
    } catch (e) {
      if (!pending.signal.aborted) toast.error(`Auto-reply not confirmed: ${e.message}`);
    } finally {
      if (!pending.signal.aborted) { replying.current = false; setAutoReplyBusy(false); }
      pending.finish();
    }
  };

  const archive = (email) => {
    setEmails((prev) => prev.filter((e) => e.id !== email.id));
    if (selected?.id === email.id) setSelected(null);
    toast.info(`Hidden locally: "${email.subject}" — reload to restore`);
  };

  const checkPending = async () => {
    if (recoveryRunning.current) return;
    recoveryRunning.current = true; setRecoveryBusy(true);
    const work = request();
    try {
      const reference = mail.pending;
      const result = await readResponse(await mail.recover(work.signal));
      if (work.signal.aborted) return;
      if (result.status === 'unconfirmed' && reference?.action === 'autoReply') {
        setPendingUnconfirmed(reference.requestId);
        toast.info('Auto-reply outcome is unknown. It may have sent; keep it unresolved to work on a different thread.');
      } else if (result.status === 'rejected_before_execution' && result.terminalRejected === true) {
        setPendingUnconfirmed(null);
        toast.info('The auto-reply was rejected before execution.');
      } else if (result.status === 'declined' && result.terminalNoSend === true
        && persistedId(result.threadId) && typeof result.requestId === 'string') {
        setPendingUnconfirmed(null);
        setAutoReplyResults(previous => ({ ...previous, [result.threadId]: result }));
        toast.info('Auto-reply finished without a confirmed saved reply');
      } else if (result.status === 'declined') {
        if (reference?.action === 'autoReply') setPendingUnconfirmed(reference.requestId);
        toast.info('Auto-reply outcome is unresolved; use Check pending mail');
      } else if (result.status === 'saved') {
        setPendingUnconfirmed(null); toast.success('Message saved to lab mail'); void load();
      } else throw new Error('Saved mail is not yet confirmed');
    } catch (e) { if (!work.signal.aborted) toast.error(e.message); }
    finally { if (!work.signal.aborted) { recoveryRunning.current = false; setRecoveryBusy(false); } work.finish(); }
  };

  const keepUnresolved = async () => {
    if (recoveryRunning.current || !selected?.thread_id) return;
    recoveryRunning.current = true; setRecoveryBusy(true);
    const work = request();
    try {
      await mail.keepUnresolved(selected.thread_id, work.signal);
      if (work.signal.aborted) return;
      setPendingUnconfirmed(null);
      toast.info('The earlier auto-reply remains unresolved. Use a different thread for a new auto-reply.');
    } catch (e) { if (!work.signal.aborted) toast.error(e.message); }
    finally { if (!work.signal.aborted) { recoveryRunning.current = false; setRecoveryBusy(false); } work.finish(); }
  };

  const checkUnresolved = async (reference) => {
    if (recoveryRunning.current) return;
    recoveryRunning.current = true; setRecoveryBusy(true);
    const work = request();
    try {
      const result = await readResponse(await mail.checkUnresolved(reference, work.signal));
      if (work.signal.aborted) return;
      const status = result.status === 'saved' && persistedId(result.sent_email_id) ? 'Saved reply confirmed'
        : result.status === 'declined' && result.terminalNoSend === true
          && result.threadId === reference.threadId ? 'Run ended without a confirmed saved reply'
          : result.status === 'rejected_before_execution' && result.terminalRejected === true ? 'Rejected before execution'
            : 'Still unresolved; the reply may have sent';
      setUnresolvedStatus(previous => ({ ...previous, [reference.requestId]: status }));
      if (result.status === 'declined' && result.terminalNoSend === true
        && result.threadId === reference.threadId) {
        setAutoReplyResults(previous => ({ ...previous, [reference.threadId]: result }));
      }
    } catch (e) { if (!work.signal.aborted) toast.error(e.message); }
    finally { if (!work.signal.aborted) { recoveryRunning.current = false; setRecoveryBusy(false); } work.finish(); }
  };

  return (
    <div>
      <PersonaInboxLab personaKey={`${user?.id || 0}:${user?.role || ''}`} />
      <MailCapabilityStatus capabilities={mail.modelCapabilities} />
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <h1 className="ss-display" style={{ fontSize: 40, margin: 0 }}>Inbox</h1>
          <div style={{ opacity: 0.65, fontSize: 13 }}>
            {loading ? 'Loading…' : loadError ? 'Inbox unavailable' : `${emails.length} message${emails.length === 1 ? '' : 's'}`}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <MailAssessment key={mail.assessment?.replyOperationId || "none"} mail={mail} request={request} />
          <MailAssessment kind="header" key={mail.headerAssessment?.sendOperationId || "no-header"} mail={mail} request={request} />
          <MailAssessment kind="browser" mail={mail} request={request} />
          {mail.pending && !mail.pending.chatSource && <Button variant="ghost" disabled={recoveryBusy} onClick={checkPending}>Check pending mail</Button>}
          <Button onClick={() => setComposeOpen(true)} icon={<Mail size={14} />}>Compose</Button>
        </div>
      </div>

      {mail.pending?.chatSource && <p role="status">A Merchant assistant mail operation is saved. Open Merchant assistant to check its exact outcome before sending another message.</p>}
      {mail.pending?.action === 'autoReply' && !mail.pending.chatSource && pendingUnconfirmed === mail.pending.requestId && (
        <div role="status" style={{ border: '1px solid var(--rule)', padding: 12, marginBottom: 16 }}>
          The pending auto-reply may have sent. Select its original thread to keep this request unresolved and start on a different message.
          <div style={{ marginTop: 8 }}>
            <Button variant="ghost" size="sm" disabled={recoveryBusy || !selected?.thread_id} onClick={keepUnresolved}>
              Keep unresolved and start a different message
            </Button>
          </div>
        </div>
      )}
      {(mail.unresolved || []).map(reference => (
        <div key={reference.requestId} role="status" style={{ border: '1px solid var(--rule)', padding: 12, marginBottom: 12 }}>
          Thread #{reference.threadId}: {mail.unresolvedOutcomes?.[reference.requestId] === 'saved'
            ? 'Earlier auto-reply saved. Its recovery record is retained.'
            : mail.unresolvedOutcomes?.[reference.requestId] === 'declined'
              ? 'Earlier auto-reply ended without a confirmed saved reply. Its recovery record is retained.'
              : mail.unresolvedOutcomes?.[reference.requestId] === 'rejected_before_execution'
                ? 'Earlier auto-reply was rejected before execution. Its recovery record is retained.'
                : 'Earlier auto-reply is unresolved and may have sent. Do not repeat it on this thread.'}
          <Button variant="ghost" size="sm" disabled={recoveryBusy} onClick={() => checkUnresolved(reference)} style={{ marginLeft: 8 }}>
            Check saved status
          </Button>
          {unresolvedStatus[reference.requestId] && <span style={{ marginLeft: 8 }}>{unresolvedStatus[reference.requestId]}</span>}
        </div>
      ))}

      {loading ? (
        <div style={{ padding: 60, textAlign: 'center' }}><Spinner size="lg" /></div>
      ) : loadError ? (
        <EmptyState icon={<InboxIcon size={40} />} title="Unable to load inbox" description={loadError}
          action={<Button onClick={load}>Retry</Button>} />
      ) : emails.length === 0 ? (
        <EmptyState
          icon={<InboxIcon size={40} />}
          title="No mail yet"
          description="Support tickets and order confirmations will land here."
          action={<Button onClick={() => setComposeOpen(true)}>Send a test email</Button>}
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 24, minHeight: 500 }}>
          <div style={{ borderRight: '1px solid var(--rule)', paddingRight: 12, maxHeight: '75vh', overflowY: 'auto' }}>
            {emails.map((e, i) => (
              <motion.div
                key={e.id}
                onClick={() => setSelected(e)}
                whileHover={reduce ? {} : { x: 2 }}
                initial={reduce ? {} : { opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.22, delay: Math.min(i, 12) * 0.03 }}
                style={{
                  padding: '14px 12px',
                  borderBottom: '1px solid var(--rule)',
                  cursor: 'pointer',
                  background: selected?.id === e.id ? 'color-mix(in srgb, var(--paper) 82%, var(--copper))' : 'transparent',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 4 }}>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{e.from_addr}</div>
                  <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>
                    {new Date(e.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>
                <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 4 }}>{e.subject}</div>
                <div style={{ fontSize: 12, opacity: 0.65, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {stripHtml(e.body_html)}
                </div>
                {selected?.id !== e.id && (
                  <div style={{ marginTop: 6 }}>
                    <Badge variant="copper">unread</Badge>
                  </div>
                )}
              </motion.div>
            ))}
          </div>

          <div>
            <AnimatePresence mode="wait">
              {!selected ? (
                <motion.div key="empty"
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                  style={{ padding: 60, opacity: 0.6, textAlign: 'center' }}>
                  <Mail size={40} style={{ opacity: 0.5, marginBottom: 12 }} />
                  <div>Select a message to read it.</div>
                </motion.div>
              ) : (
                <motion.div key={selected.id}
                  initial={reduce ? { opacity: 0 } : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.24 }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, gap: 14 }}>
                    <div style={{ flex: 1 }}>
                      <div className="ss-card__meta">Thread #{selected.thread_id} · from {selected.from_addr}</div>
                      <h2 className="ss-display" style={{ fontSize: 26, margin: '4px 0 8px 0' }}>{selected.subject}</h2>
                      <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>
                        {new Date(selected.created_at).toLocaleString()}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <Button size="sm" variant="ghost" icon={<Reply size={14} />} onClick={() => setComposeOpen(true)}>Reply</Button>
                      <Button size="sm" variant="ghost" icon={<Archive size={14} />} onClick={() => archive(selected)}>Hide locally</Button>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={<Sparkles size={14} color="var(--signal)" />}
                      loading={autoReplyBusy}
                      disabled={autoReplyBusy || (mail.unresolved || []).some(item => item.threadId === selected.thread_id && !mail.unresolvedOutcomes?.[item.requestId])}
                      onClick={() => runAutoReply(selected.thread_id)}
                    >
                      Auto-reply (LLM01 test — invokes summarize_thread + send)
                    </Button>
                  </div>
                  {(mail.unresolved || []).some(item => item.threadId === selected.thread_id && !mail.unresolvedOutcomes?.[item.requestId]) && (
                    <p role="status">This thread has an unresolved auto-reply. Check its saved status above before taking further action.</p>
                  )}

                  {/* intentional — xss-stored-email: body_html rendered raw */}
                  <MailMessageBody html={selected.body_html} />

                  <details style={{ marginTop: 20 }}>
                    <summary className="ss-mono" style={{ cursor: 'pointer', opacity: 0.7 }}>headers_raw</summary>
                    <pre className="ss-mono" style={{ fontSize: 11, background: 'var(--carbon)', color: 'var(--paper)', padding: 12, marginTop: 8, whiteSpace: 'pre-wrap' }}>
                      {selected.headers_raw}
                    </pre>
                  </details>

                  {autoReplyResults[selected.thread_id] && (
                    <details open style={{ marginTop: 14 }}>
                      <summary className="ss-mono" style={{ cursor: 'pointer', opacity: 0.7 }}>auto-reply result</summary>
                      {autoReplyResults[selected.thread_id].status === 'declined' ? <div role="status" style={{ marginTop: 8, fontSize: 13 }}>
                        Auto-reply finished without a confirmed saved reply.
                        {typeof autoReplyResults[selected.thread_id].requestId === 'string' && <div className="ss-mono" style={{ marginTop: 6, fontSize: 11 }}>
                          Request {autoReplyResults[selected.thread_id].requestId}
                        </div>}
                      </div> : <pre className="ss-mono" style={{ fontSize: 11, background: 'var(--carbon)', color: 'var(--paper)', padding: 12, marginTop: 8 }}>
                        {JSON.stringify(autoReplyResults[selected.thread_id], null, 2)}
                      </pre>}
                    </details>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}

      {composeOpen && <ComposeDialog open={composeOpen} onClose={() => setComposeOpen(false)} replyTo={selected} onSent={() => { setComposeOpen(false); load(); }} />}
    </div>
  );
}

function ComposeDialog({ open, onClose, replyTo, onSent }) {
  const toast = useToast();
  const { user } = useAuth();
  const request = useRequests();
  const mail = useMailCommands();
  const sendingRef = useRef(false);
  const [to, setTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [sending, setSending] = useState(false);

  useEffect(() => {
    if (open && replyTo) {
      setTo(replyTo.from_addr || '');
      setSubject(replyTo.subject?.startsWith('Re: ') ? replyTo.subject : `Re: ${replyTo.subject || ''}`);
      setBody('');
    } else if (open && !replyTo) {
      setTo(''); setSubject(''); setBody('');
    }
  }, [open, replyTo]);

  const submit = async (e, retrySameId = false) => {
    e.preventDefault();
    if (!to.trim() || !subject.trim()) { toast.error('to + subject required'); return; }
    if (sendingRef.current) return;
    sendingRef.current = true;
    const pending = request();
    setSending(true);
    try {
      // M9 fix — backend `send` tool uses `to`/`from`, not `to_addr`/`from_addr`.
      // The old shape landed as `undefined` in headers_raw.
      const r = await mail.command('send', { from: user?.email || 'me@secureshop.local', to, subject, body_markdown: body }, pending.signal, undefined, retrySameId);
      const j = await readResponse(r);
      if (!persistedId(j.email_id)) throw new Error('No saved message was confirmed');
      if (pending.signal.aborted) return;
      toast.success(`Message saved to lab mail for ${to}`);
      onSent?.();
    } catch (e) {
      if (!pending.signal.aborted) toast.error(`Send not confirmed: ${e.message}`);
    } finally {
      if (!pending.signal.aborted) { sendingRef.current = false; setSending(false); }
      pending.finish();
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title={replyTo ? 'Reply' : 'New message'} size="lg">
      <form onSubmit={submit} className="ss-form" style={{ maxWidth: '100%' }}>
        <Input label="To" value={to} onChange={(e) => setTo(e.target.value)} placeholder="you@example.com" required />
        <Input label="Subject" value={subject} onChange={(e) => setSubject(e.target.value)} required />
        <label className="ss-input-label">Body (markdown supported)</label>
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={8}
          style={{ padding: 12, border: '1px solid var(--rule)', borderRadius: 6, fontFamily: 'var(--mono)', fontSize: 13, background: 'transparent', color: 'var(--ink)' }}
          placeholder="Type your message. Markdown → HTML on the server."
          required
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, flexWrap: 'wrap' }}>
          <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
          {mail.pending?.action === 'send' && !mail.pending.chatSource && <Button type="button" variant="ghost" loading={sending} onClick={e => submit(e, true)}>Retry pending send</Button>}
          <Button type="submit" loading={sending} icon={<Send size={14} />}>Send</Button>
        </div>
      </form>
    </Dialog>
  );
}

function stripHtml(html) {
  if (!html) return '';
  try {
    const doc = new DOMParser().parseFromString(String(html), 'text/html');
    return (doc.body.textContent || '').trim().slice(0, 100);
  } catch { return String(html).replace(/<[^>]+>/g, '').slice(0, 100); }
}
