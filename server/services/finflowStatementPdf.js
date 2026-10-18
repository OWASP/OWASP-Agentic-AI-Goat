'use strict';
// Dependency-free synthetic statement PDF. Offsets and lengths are bytes, not
// JavaScript characters. ActualText retains Unicode when Helvetica lacks a glyph.
const SPECIAL = new Map([[0x20ac,128],[0x201a,130],[0x192,131],[0x201e,132],[0x2026,133],[0x2020,134],[0x2021,135],[0x2c6,136],[0x2030,137],[0x160,138],[0x2039,139],[0x152,140],[0x17d,142],[0x2018,145],[0x2019,146],[0x201c,147],[0x201d,148],[0x2022,149],[0x2013,150],[0x2014,151],[0x2dc,152],[0x2122,153],[0x161,154],[0x203a,155],[0x153,156],[0x17e,158],[0x178,159]]);
function literal(text) {
  let out='';
  for (const char of text) {
    const cp=char.codePointAt(0), byte=(cp>=32&&cp<=126)||(cp>=160&&cp<=255)?cp:SPECIAL.get(cp);
    if(byte===undefined){out+=`[U+${cp.toString(16).toUpperCase().padStart(4,'0')}]`;continue;}
    out+=byte<32||byte>126?'\\'+byte.toString(8).padStart(3,'0'):[40,41,92].includes(byte)?'\\'+char:char;
  }
  return out;
}
function unicodeHex(text) {const bytes=Buffer.from(text,'utf16le');bytes.swap16();return 'FEFF'+bytes.toString('hex').toUpperCase();}
function statementPdf(accountId, customerRecords, date=new Date()) {
  const customer=customerRecords.find(c=>c.id===accountId)||{name:'Account Holder',account_balance:0,account_type:'Standard'};
  const lines=['FinFlow Digital Banking','Account Statement — Annual Summary 2024','',`Account ID   : ${accountId}`,`Account Name : ${customer.name}`,`Account Type : ${customer.account_type}`,`Statement Date: ${date.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})}`,'','Transaction Summary','-------------------','Total Credits  : $18,250.00','Total Debits   : $12,340.50',`Closing Balance: $${customer.account_balance.toFixed(2)}`,'','This is a simulated statement for educational purposes.','FinFlow Digital Banking — finflow.example.com'];
  const stream=Buffer.from('BT\n/F1 12 Tf\n50 750 Td\n'+lines.map((line,i)=>`0 ${i===0?0:-18} Td /Span << /ActualText <${unicodeHex(line)}> >> BDC (${literal(line)}) Tj EMC`).join('\n')+'\nET\n','ascii');
  const objects=[Buffer.from('<< /Type /Catalog /Pages 2 0 R >>'),Buffer.from('<< /Type /Pages /Kids [3 0 R] /Count 1 >>'),Buffer.from('<< /Type /Page /MediaBox [0 0 595 842] /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>'),Buffer.from('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'),Buffer.concat([Buffer.from(`<< /Length ${stream.length} >>\nstream\n`),stream,Buffer.from('endstream')])];
  const chunks=[Buffer.from('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n','latin1')],offsets=[0];let size=chunks[0].length;
  objects.forEach((obj,i)=>{offsets.push(size);const bytes=Buffer.concat([Buffer.from(`${i+1} 0 obj\n`),obj,Buffer.from('\nendobj\n')]);chunks.push(bytes);size+=bytes.length;});
  chunks.push(Buffer.from(`xref\n0 ${objects.length+1}\n0000000000 65535 f \n${offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('')}trailer\n<< /Size ${objects.length+1} /Root 1 0 R >>\nstartxref\n${size}\n%%EOF\n`));
  return Buffer.concat(chunks);
}
module.exports={statementPdf};
