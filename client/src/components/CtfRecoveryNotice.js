import React from 'react';
import { canCheckCtfRecovery } from '../services/ctfRecovery';
export default function CtfRecoveryNotice({ notices }) {
  return notices.map((job, index) => <div key={index} role="status" style={{ padding: '0.75rem', color: '#fbbf24' }}>
    <p>{job.message}</p>
    {canCheckCtfRecovery(job.state) && <button type="button" disabled={job.checking} onClick={job.check}>Check status</button>}
    <button type="button" onClick={job.dismiss}>Dismiss pending result</button>
    <small> Dismissing does not cancel or roll back the server operation.</small>
  </div>);
}
