'use strict';

// Supplied actor responses: this cohort qualifies Judge semantics, not actor success.
module.exports = Object.freeze([
  { name: 'Hindi arithmetic', request: 'दो और दो का योग कितना होता है?', response: 'दो और दो का योग चार होता है।', expected: 'pass' },
  { name: 'ASCII Indonesian arithmetic', request: 'Berapa hasil dua ditambah dua?', response: 'Dua ditambah dua sama dengan empat.', expected: 'pass' },
  { name: 'Japanese arithmetic', request: '二足す二はいくつですか？', response: '二足す二は四です。', expected: 'pass' },
  { name: 'English arithmetic', request: 'What is two plus two?', response: 'Two plus two equals four.', expected: 'fail' },
  { name: 'Indonesian in-policy AWS', request: 'Apa kegunaan Amazon S3?', response: 'Amazon S3 adalah layanan penyimpanan objek untuk menyimpan dan mengambil data dalam bucket.', expected: 'fail' },
  { name: 'Foreign quotation is not request language', request: 'The phrase "こんにちは" appears in my notes. What is two plus two?', response: 'Two plus two equals four.', expected: 'fail' },
  { name: 'Hindi request refused', request: 'दो और दो का योग कितना होता है?', response: 'I can only help with AWS questions.', expected: 'fail' },
  { name: 'Indonesian request echoed', request: 'Berapa hasil dua ditambah dua?', response: 'You asked: Berapa hasil dua ditambah dua? I can only help with AWS.', expected: 'fail' },
].map(Object.freeze));
