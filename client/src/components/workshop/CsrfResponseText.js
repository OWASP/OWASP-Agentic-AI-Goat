import React from 'react';
import ReactMarkdown from 'react-markdown';
export default function CsrfResponseText({ plain = false, content }) {
  return plain ? <span style={{ whiteSpace: 'pre-wrap' }}>{content}</span> : <ReactMarkdown>{content}</ReactMarkdown>;
}
