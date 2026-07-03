// Frequently-impersonated organizations and their official registrable
// domains. A URL whose domain *is* one of these is treated as the real
// brand; a URL that merely *resembles* one of these raises a lookalike flag.
//
// `generic: true` marks brand tokens that are also ordinary words, so we
// skip the "brand token inside another domain" check for them (too many
// false positives), while keeping exact-domain and typo checks.

export const BRANDS = [
  { name: 'Google', domains: ['google.com', 'gmail.com', 'youtube.com', 'google.co.in'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'microsoftonline.com'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'primevideo.com'] },
  { name: 'Facebook', domains: ['facebook.com', 'fb.com', 'messenger.com'] },
  { name: 'Instagram', domains: ['instagram.com'] },
  { name: 'WhatsApp', domains: ['whatsapp.com', 'wa.me'] },
  { name: 'Netflix', domains: ['netflix.com'] },
  { name: 'PayPal', domains: ['paypal.com', 'paypal.me'] },
  { name: 'LinkedIn', domains: ['linkedin.com', 'lnkd.in'] },
  { name: 'X (Twitter)', domains: ['twitter.com', 'x.com'] },
  { name: 'Telegram', domains: ['telegram.org', 't.me'] },
  { name: 'GitHub', domains: ['github.com'] },
  { name: 'Dropbox', domains: ['dropbox.com'] },
  { name: 'Adobe', domains: ['adobe.com'] },
  { name: 'DocuSign', domains: ['docusign.com', 'docusign.net'] },
  { name: 'eBay', domains: ['ebay.com'] },
  { name: 'Walmart', domains: ['walmart.com'] },
  { name: 'Target', domains: ['target.com'], generic: true },
  { name: 'Costco', domains: ['costco.com'] },
  { name: 'Best Buy', domains: ['bestbuy.com'] },
  { name: 'AliExpress', domains: ['aliexpress.com'] },
  { name: 'Flipkart', domains: ['flipkart.com'] },
  { name: 'Myntra', domains: ['myntra.com'] },
  { name: 'Paytm', domains: ['paytm.com'] },
  { name: 'PhonePe', domains: ['phonepe.com'] },
  { name: 'SBI', domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbicard.com'] },
  { name: 'HDFC Bank', domains: ['hdfcbank.com'] },
  { name: 'ICICI Bank', domains: ['icicibank.com'] },
  { name: 'Axis Bank', domains: ['axisbank.com'] },
  { name: 'Kotak Bank', domains: ['kotak.com'] },
  { name: 'IRCTC', domains: ['irctc.co.in'] },
  { name: 'Income Tax India', domains: ['incometax.gov.in'] },
  { name: 'UIDAI (Aadhaar)', domains: ['uidai.gov.in'] },
  { name: 'NPCI / BHIM UPI', domains: ['npci.org.in', 'bhimupi.org.in'] },
  { name: 'FedEx', domains: ['fedex.com'] },
  { name: 'DHL', domains: ['dhl.com', 'dhl.de'] },
  { name: 'UPS', domains: ['ups.com'] },
  { name: 'USPS', domains: ['usps.com'] },
  { name: 'India Post', domains: ['indiapost.gov.in'] },
  { name: 'Bank of America', domains: ['bankofamerica.com'] },
  { name: 'Chase', domains: ['chase.com'], generic: true },
  { name: 'Wells Fargo', domains: ['wellsfargo.com'] },
  { name: 'Citibank', domains: ['citi.com', 'citibank.com'] },
  { name: 'HSBC', domains: ['hsbc.com', 'hsbc.co.uk'] },
  { name: 'Barclays', domains: ['barclays.co.uk', 'barclays.com'] },
  { name: 'American Express', domains: ['americanexpress.com'] },
  { name: 'Coinbase', domains: ['coinbase.com'] },
  { name: 'Binance', domains: ['binance.com'] },
  { name: 'MetaMask', domains: ['metamask.io'] },
  { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'], generic: true },
  { name: 'Roblox', domains: ['roblox.com'] },
  { name: 'Epic Games', domains: ['epicgames.com'] },
  { name: 'Spotify', domains: ['spotify.com'] },
  { name: 'Zoom', domains: ['zoom.us', 'zoom.com'], generic: true },
  { name: 'IRS (US)', domains: ['irs.gov'] },
  { name: 'Airbnb', domains: ['airbnb.com'] },
  { name: 'Booking.com', domains: ['booking.com'], generic: true },
  // Delivery / logistics — the single biggest smishing-impersonation target
  { name: 'Royal Mail', domains: ['royalmail.com'] },
  { name: 'Evri', domains: ['evri.com'] },
  { name: 'Canada Post', domains: ['canadapost.ca', 'canadapost-postescanada.ca'] },
  { name: 'Australia Post', domains: ['auspost.com.au'] },
  { name: 'An Post', domains: ['anpost.ie'] },
  { name: 'Correos', domains: ['correos.es'] },
  { name: 'Poste Italiane', domains: ['poste.it'] },
  { name: 'Blue Dart', domains: ['bluedart.com'] },
  { name: 'Delhivery', domains: ['delhivery.com'] },
  // Fintech / neobanks / payment apps
  { name: 'Revolut', domains: ['revolut.com'] },
  { name: 'Monzo', domains: ['monzo.com'] },
  { name: 'Wise', domains: ['wise.com'] },
  { name: 'N26', domains: ['n26.com'] },
  { name: 'Venmo', domains: ['venmo.com'] },
  { name: 'Zelle', domains: ['zellepay.com'] },
  { name: 'Cash App', domains: ['cash.app'] },
  { name: 'Santander', domains: ['santander.com', 'santander.co.uk'] },
  { name: 'NatWest', domains: ['natwest.com'] },
  { name: 'Lloyds Bank', domains: ['lloydsbank.com'] },
  { name: 'Capital One', domains: ['capitalone.com'] },
  { name: 'Discover', domains: ['discover.com'], generic: true },
  // Crypto exchanges / wallets (high-value impersonation)
  { name: 'Kraken', domains: ['kraken.com'], generic: true },
  { name: 'Crypto.com', domains: ['crypto.com'] },
  { name: 'Trust Wallet', domains: ['trustwallet.com'] },
  { name: 'Ledger', domains: ['ledger.com'], generic: true },
  // Big-tech accounts / social
  { name: 'Snapchat', domains: ['snapchat.com'] },
  { name: 'TikTok', domains: ['tiktok.com'] },
  { name: 'Discord', domains: ['discord.com'] },
  { name: 'Yahoo', domains: ['yahoo.com'] },
  { name: 'Proton', domains: ['proton.me', 'protonmail.com'] },
  { name: 'Disney+', domains: ['disneyplus.com'] },
  { name: 'Temu', domains: ['temu.com'] },
  { name: 'Shein', domains: ['shein.com'] },
  // Government / tax (non-India)
  { name: 'HMRC (UK)', domains: ['hmrc.gov.uk', 'tax.service.gov.uk'] },
  { name: 'Social Security (US)', domains: ['ssa.gov'] },
  { name: 'DVLA (UK)', domains: ['dvla.gov.uk'] }
];

/** Set of every official registrable domain above, for exact-match checks. */
export const OFFICIAL_DOMAINS = new Set(BRANDS.flatMap(b => b.domains));

// Minimum token length for typo / brand-in-domain comparisons. Short tokens
// ("fb", "ups", "sbi", "citi", "x") collide with ordinary strings far too often.
export const MIN_BRAND_TOKEN = 5;

/**
 * Comparison tokens per brand: the second-level label of each official
 * domain ("paypal" from paypal.com), keeping only tokens long enough to
 * compare safely, minus generic words when `generic` is set.
 */
export function brandTokens() {
  const tokens = [];
  for (const brand of BRANDS) {
    for (const domain of brand.domains) {
      const sld = domain.split('.')[0];
      if (sld.length < MIN_BRAND_TOKEN) continue;
      if (sld === 'live' || sld === 'office') continue; // ordinary words, typo-check only causes noise
      tokens.push({ token: sld, brand: brand.name, generic: !!brand.generic });
    }
  }
  return tokens;
}
