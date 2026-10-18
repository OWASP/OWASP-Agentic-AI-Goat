-- Synthetic exercise classification; this makes no claim about real paper access.
ALTER TABLE nova.papers ADD COLUMN access_level text NOT NULL DEFAULT 'public'
 CHECK (access_level IN ('public','restricted'));
UPDATE nova.papers SET access_level='restricted'
 WHERE (paper_id='PAPER-2024-039' AND title='Segment Anything')
 OR (paper_id='PAPER-2024-040' AND title='Chain-of-Thought Prompting Elicits Reasoning in Large Language Models');
