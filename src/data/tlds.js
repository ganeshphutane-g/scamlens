// TLDs with heavily disproportionate abuse rates in phishing feeds
// (Spamhaus / APWG reporting). Presence alone is a weak signal — it only
// adds weight, it never condemns a URL by itself.
export const RISKY_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',            // legacy Freenom free TLDs
  'top', 'xyz', 'icu', 'click', 'link', 'work', 'rest', 'fit', 'loan',
  'win', 'bid', 'stream', 'download', 'racing', 'party', 'science', 'men',
  'date', 'trade', 'accountant', 'faith', 'review', 'country', 'kim',
  'cricket', 'gdn', 'mom', 'lol', 'pw', 'cam', 'buzz', 'monster',
  'cyou', 'sbs', 'cfd', 'beauty', 'hair', 'skin', 'makeup', 'quest',
  'zip', 'mov', 'shop', 'live', 'vip', 'bond', 'lat'
]);

// Common multi-part public suffixes so we can find the registrable domain
// ("example.co.in" → registrable "example.co.in", not "co.in").
export const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'nic.in',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.cl',
  'co.za', 'org.za', 'gov.za', 'web.za',
  'com.sg', 'com.my', 'com.ph', 'com.vn', 'com.id', 'co.id',
  'com.tr', 'com.tw', 'com.hk', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.kr', 'or.kr', 'go.kr',
  'com.pk', 'com.bd', 'com.np', 'com.lk', 'com.mm',
  'co.th', 'go.th', 'in.th',
  'com.eg', 'com.ng', 'com.gh', 'com.ke', 'co.ke',
  'co.il', 'org.il', 'com.ua', 'com.sa', 'com.ae', 'com.qa', 'com.kw'
]);

// Services whose whole purpose is hiding the destination. Common in
// legitimate marketing too, so this is a weak signal on its own.
export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly', 's.id',
  'v.gd', 't.ly', 'surl.li', 'u.to', 'clck.ru', 'bl.ink', 'shorte.st',
  'adf.ly', 'soo.gd', 'qps.ru', 'l.ead.me', 'kutt.it'
]);
