// Content red-flag patterns. Each fires at most once per message —
// a scammer repeating "URGENT" ten times shouldn't inflate the score.
//
// Weights are calibrated so that no single weak signal (urgency, a link
// shortener) can push a message past "medium" on its own, while the
// signature combinations real scams use (threat + secrecy, lookalike
// link + credential request) land in "high"/"critical".

export const CONTENT_PATTERNS = [
  {
    id: 'credential-request',
    category: 'credentials',
    weight: 30,
    title: 'Asks you to send a code, PIN, or password to someone else',
    detail: 'No legitimate bank, company, or government agency ever asks you to share an OTP, PIN, CVV, or password. Only fraudsters do.',
    re: [
      // Unambiguous "give it to a third party" verbs only — NOT enter/verify/
      // confirm/update, which are equally common in legitimate self-service
      // 2FA prompts ("enter the OTP to log in"). Those are handled by the
      // separate, lower-weight 'credential-entry-prompt' pattern below.
      /\b(shar(e|ed|ing)|sen(d|t|ding)|provid(e|ed|ing)|giv(e|en|ing)|gave|tell|told|telling|repl(y|ied|ying)|forward(ed|ing)?|read (it )?out|read us|reading (it )?out)\b[^.\n!?]{0,50}\b(otp|one[- ]?time (password|passcode|pin)|password|passcode|pin\b|cvv|card number|debit card|credit card|upi pin|mpin|atm pin|aadhaar number|pan (card|number)|ssn|social security|bank (details|account)|net ?banking|login (details|credentials)|security code|verification code)\b/i,
      /\b(otp|upi pin|cvv|password|mpin|verification code)\b[^.\n!?]{0,40}\b(shar(e|ed|ing)|sen(d|t|ding)|provid(e|ed|ing)|repl(y|ied|ying)|batao|bhejo)\b/i,
      // "Read/confirm/repeat the code you just received" to a caller — the
      // signature of SIM-swap and voice-phishing social engineering.
      /\b(read|confirm|repeat|tell (us|me))\b.{0,15}\b(code|otp|pin)\b.{0,25}\b(texted|sent|received|got|just sent)\b/i,
      // "Enter your PIN to receive money" is never true — entering a PIN
      // authorizes a payment OUT, never in. Unlike bare "enter your PIN"
      // (ambiguous, see credential-entry-prompt), this specific framing is
      // the deceptive core of the UPI "collect request" scam and is
      // unambiguous on its own.
      /\benter\b.{0,15}\bpin\b.{0,20}\b(receive|get)\b/i
    ]
  },
  {
    id: 'credential-entry-prompt',
    category: 'credentials',
    weight: 10,
    title: 'Asks you to enter or verify a code, PIN, or password',
    detail: 'Entering a code on the REAL site you already trust is normal 2FA. The danger is doing it through a link in this message — check the link before you type anything.',
    re: [
      /\b(enter(ed|ing)?|verif(y|ied|ying)|confirm(ed|ing)?|updat(e|ed|ing))\b[^.\n!?]{0,50}\b(otp|one[- ]?time (password|passcode|pin)|password|passcode|pin\b|cvv|upi pin|mpin|atm pin|security code|verification code)\b/i
    ]
  },
  {
    id: 'untraceable-payment',
    category: 'payment',
    weight: 28,
    title: 'Demands untraceable payment',
    detail: 'Gift cards, wire transfers, and cryptocurrency are favored by scammers because payments cannot be reversed or traced. No genuine organization collects fees this way.',
    re: [
      /\b(gift ?cards?|itunes card|google play (card|gift|voucher)|steam (card|wallet)|amazon (gift|pay gift)|prepaid (card|voucher)|western union|moneygram|wire transfer|bitcoin|btc\b|usdt|crypto(currency)? (wallet|payment|address)|pay (via|with|in|using) (bitcoin|crypto|gift|usdt)|recharge (coupon|voucher))\b/i
    ]
  },
  {
    id: 'threat',
    category: 'threat',
    weight: 26,
    title: 'Threatens arrest, police, or legal action',
    detail: 'Real police and courts never announce arrests by message or demand money over a call. "Digital arrest" is not a real legal process — it is a well-known scam script.',
    re: [
      /\b(legal action|lawsuit|arrest warrant|(will|shall) be arrested|digital arrest|police (case|complaint|verification)|fir (will be|has been) (filed|registered)|court (case|summons|notice)|money laundering case|cbi\b|narcotics|customs has (seized|held|detained)|your (number|sim|aadhaar( number)?|account)\b.{0,15}(is|was|has been) (linked to|used in|involved in).{0,30}(crime|illegal|fraud|laundering)|pay.{0,30}(fine|penalty).{0,30}(avoid|or face)|suspended by (trai|rbi|police))\b/i
    ]
  },
  {
    id: 'tech-support',
    category: 'tech-support',
    weight: 32,
    title: 'Fake virus / tech-support alert',
    detail: 'Pop-ups and calls claiming your device is infected and telling you to call a number are fake. Microsoft, Apple, and antivirus companies never cold-call you or put a phone number in a virus warning.',
    re: [
      /\b((your (computer|pc|device|iphone|mac|system) (is|has been|may be) (infected|hacked|compromised|blocked|at risk))|virus (detected|found|alert)|malware detected|(microsoft|apple|windows|norton|mcafee) (support|security|technician).{0,40}(call|contact|dial)|call (this )?(toll[- ]?free )?number.{0,30}(support|technician|microsoft|apple|remove|virus)|do not (restart|turn off|shut down) your (computer|pc|device))\b/i
    ]
  },
  {
    id: 'emergency',
    category: 'emergency',
    weight: 22,
    title: 'Family-emergency money request',
    detail: 'The "grandparent scam" impersonates a relative in sudden trouble (accident, arrest, hospital) needing money urgently and secretly. Verify by calling the real person on a number you already have before doing anything.',
    re: [
      /\b(it'?s me|it is me|this is your)\b.{0,20}\b(grand)?(son|daughter|child|mom|dad|nephew|niece)\b/i,
      /\b(i'?m|i am|i'?ve been|i have been) (in (an? )?(accident|jail|hospital|trouble)|arrested|stranded|kidnapped|detained)\b/i,
      /\bneed (money|bail|cash|help) (right )?(now|urgently|immediately|asap|today)\b/i,
      /\b(mom|dad|grandma|grandpa|mum),? i (need|lost)\b.{0,40}(money|phone|help)/i
    ]
  },
  {
    id: 'quishing',
    category: 'quishing',
    weight: 16,
    title: 'Asks you to scan a QR code',
    detail: 'Scan a QR code from an unexpected message, email, parking meter sticker, or letter and it can send you straight to a phishing site or authorize a payment. Type addresses yourself instead of scanning codes from strangers.',
    re: [
      /\b(scan (the |this |below )?qr( ?code)?|qr ?code (to|below|attached|and)|scan (the |this )?code (to|below|and) (pay|verify|log ?in|claim|confirm|receive))\b/i
    ]
  },
  {
    id: 'remote-access',
    category: 'remote-access',
    weight: 26,
    title: 'Asks you to install a remote-access or unknown app',
    detail: 'Fraudsters ask victims to install AnyDesk, TeamViewer, or APK files so they can watch your screen and empty your accounts. Support staff of real companies never need this.',
    re: [
      /\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?shar(e|ing)|remote (access|control|support) (app|software|tool)?|install (this|the) (app|apk|application)|download (this|the) apk)\b/i
    ]
  },
  {
    id: 'prize',
    category: 'too-good',
    weight: 25,
    title: 'Announces a prize or lottery you never entered',
    detail: 'You cannot win a lottery you never bought a ticket for. Prize messages exist to collect "processing fees" or personal details.',
    re: [
      /\b(you (have |'ve )?(won|been selected)|congratulations?[!, ]|lucky (winner|draw|customer)|lottery|jackpot|prize (money|of|worth)|claim your (prize|reward|gift|winnings)|free (iphone|gift|recharge|money|voucher)|inheritance|unclaimed (funds|money)|kbc (lottery|winner))\b/i
    ]
  },
  {
    id: 'investment',
    category: 'too-good',
    weight: 25,
    title: 'Promises guaranteed or unrealistic returns',
    detail: 'Guaranteed profit does not exist. "Double your money" and daily-return schemes are the signature of investment fraud and pig-butchering scams.',
    re: [
      /\b(guaranteed (returns?|profit|income)|double your (money|investment)|(daily|weekly|monthly) (profit|returns?|income) of|risk[- ]?free (investment|returns?|profit)|earn (₹|rs\.?|\$|€|£)?\s?[\d,]+ (per|a|every|each) (day|week|hour)|(trading|forex|crypto) (tips|signals|group)|100% (profit|return|safe investment))\b/i
    ]
  },
  {
    id: 'impersonation-official',
    category: 'impersonation',
    weight: 24,
    title: 'Imitates a bank, utility, or government notice',
    detail: 'Fake KYC-expiry, electricity-disconnection, tax-refund, and parcel-stuck notices are the most common phishing lures. Real organizations use their official app or website, and never a random link.',
    re: [
      /\b(kyc (update|expired?|expiring|pending|verification|suspended)|pan card.{0,30}(update|link|expire)|aadhaar.{0,30}(link|update|suspend|verify)|electricity (bill|connection|meter).{0,40}(disconnect\w*|cut\w*|suspend\w*)|(income )?tax refund|customs (duty|clearance|fee)|(parcel|package|shipment|courier).{0,40}(held|stuck|detained|customs|on hold|could not be delivered|delivery failed|address (issue|problem|incomplete))|delivery attempt (was )?(failed|unsuccessful)|account.{0,25}(frozen|blocked|suspended|deactivated|locked)|sim (card )?(will be )?(blocked|deactivated|suspended)|upgrad(e|ing) (our|the|your)?\s?network|port(ing)? (your|the) number|prevent(ing)? (a |the )?(sim )?port|keep your number (active|safe))\b/i
    ]
  },
  {
    id: 'toll-fine-threat',
    category: 'toll-fine',
    weight: 22,
    title: 'Fake unpaid-toll notice with a fine threat',
    detail: 'Fake toll-payment texts (impersonating E-ZPass, SunPass, and similar services) are one of the most common SMS scams — real toll agencies bill through your account, not a surprise text with a payment link.',
    re: [
      // Plain "." quantifier (not the sentence-bounded [^.\n!?] used
      // elsewhere) because real toll texts naturally span sentences and
      // contain decimal amounts ("toll of $6.99. Pay by ... or a $50 fine").
      /\b(unpaid|outstanding|overdue) toll\b.{0,120}\b(fine|penalty|suspen(sion|d(ed)?)|driving privileges?|license (suspension|revocation)|collections)\b/i
    ]
  },
  {
    id: 'payment-redirect',
    category: 'payment-redirect',
    weight: 24,
    title: 'Asks you to send future payments to "new" bank details',
    detail: 'Business-email-compromise scams intercept a real conversation and ask you to redirect payments to a fraudulent account. This is the single costliest type of online fraud for businesses — always confirm changed bank details by phone, using a number you already had, not one from this message.',
    re: [
      /\b(bank(ing)? (details?|account) (have |has )?changed|switched banks|new (bank )?account (number|details)|updat(e|ed) (our|your) (bank(ing)?|payment) (details|records|information)|(send|use|redirect) (all )?future (invoice )?payments? to)\b/i
    ]
  },
  {
    id: 'job-scam',
    category: 'job',
    weight: 22,
    title: 'Job offer that asks for money or trivial "tasks"',
    detail: 'Real employers pay you — they never charge registration, training, or "refundable" fees. Like-and-subscribe or prepaid-task jobs are wholesale fraud operations.',
    re: [
      /\b(work[- ]from[- ]home.{0,50}(earn|salary|income|₹|\$)|part[- ]?time (job|work).{0,40}(earn|daily|₹|\$)|registration fee|refundable (deposit|fee|amount)|training fee|security deposit.{0,30}job|pay.{0,25}(to|for).{0,15}(get|start|secure|confirm).{0,10}(the )?job|like (and|&) subscribe.{0,30}(earn|paid)|simple tasks?.{0,30}(earn|payment|paid)|telegram.{0,25}(task|job|work)|(shortlisted|selected|congratulations).{0,180}(telegram|whatsapp).{0,100}(interview|starter kit|onboarding))\b/i
    ]
  },
  {
    id: 'secrecy',
    category: 'secrecy',
    weight: 18,
    title: 'Tells you to keep it secret',
    detail: 'Scammers isolate victims. Anyone who says "do not tell your family or your bank" is hiding from the people who would recognize the fraud instantly.',
    re: [
      /\b(do n?o?'?t (tell|share|inform|disclose|mention)( this)?( to)? (anyone|anybody|family|mom|dad|mum|parents|your (family|wife|husband|son|daughter|children|parents|mom|dad|bank))|keep (this|it) (confidential|secret|private|between us)|must not (tell|inform))\b/i
    ]
  },
  {
    id: 'refund-bait',
    category: 'refund',
    weight: 16,
    title: 'Unexpected refund or cashback bait',
    detail: 'Surprise refunds and cashbacks that need a link click or an app approval are designed to make you authorize a payment in the wrong direction.',
    re: [
      /\b(refund (of|is|has been) (₹|rs\.?|\$|€|£)?\s?[\d,]+|claim (your )?refund|cashback (of|credited|waiting)|you are eligible for (a )?(refund|cashback)|approve.{0,20}(request|collect).{0,20}(receive|get))\b/i
    ]
  },
  {
    id: 'verify-link',
    category: 'phishing-action',
    weight: 14,
    title: 'Pushes you to click a link and "verify"',
    detail: 'Verify/re-activate/update-billing links are how credentials get stolen. Open the official app or type the official website yourself instead.',
    re: [
      /\b(click (the |this |on the |below )?(link|button|here)|verify (your )?(account|identity|email|details|information)|re-?activate (your )?account|update your (payment|billing|bank) (info|information|details|method)|login (to|and) (verify|confirm|update)|complete (the )?verification)\b/i
    ]
  },
  {
    id: 'urgency',
    category: 'urgency',
    weight: 12,
    title: 'Manufactured urgency',
    detail: 'Deadlines of hours, "final warning", "act immediately" — urgency exists to stop you from thinking or asking someone. Real organizations give you time and options.',
    re: [
      /\b(act (now|immediately|fast)|urgent(ly)?|immediate (action|attention)|within (24|48) hours?|expires? (today|tonight|soon|in)|last (chance|warning|day)|final (notice|warning|reminder)|right away|limited time|(will be|gets?) (suspended|blocked|closed|deactivated|terminated) (today|tonight|within|in \d)|avoid (suspension|disconnection|termination))\b/i
    ]
  },
  {
    id: 'private-channel',
    category: 'channel',
    weight: 10,
    title: 'Moves you to WhatsApp/Telegram or a phone number',
    detail: 'Fraud operations push conversations to unmonitored channels. A company that only exists on WhatsApp or Telegram is not a company.',
    re: [
      /\b(whats ?app (me|us|on|at|number|only)|message (me|us) on (whatsapp|telegram)|join (our|the|my) telegram|telegram (group|channel|id)|contact (on|via|through) (whatsapp|telegram)|call (this|the below|below|this given) number|reply ['"]?yes['"]?)\b/i
    ]
  },
  {
    id: 'romance-advance-fee',
    category: 'advance-fee',
    weight: 20,
    title: 'Stranger needs money released to you or from you',
    detail: 'Packages stuck at customs, funds needing a "clearance fee", sudden overseas emergencies — the advance-fee script always ends with you paying first.',
    re: [
      /\b(my (dear|love|darling|beloved)|(customs|clearance|processing|handling|release) fee.{0,40}(release|receive|claim|deliver)|send (me )?(some )?money (for|to|so)|stuck (at|in) (the )?(airport|customs|immigration)|need (money|funds|help) (for|to) (a )?(ticket|visa|hospital|surgery|emergency))\b/i
    ]
  }
];

// Extra weight when signals that only co-occur in scams appear together.
export const COMBOS = [
  {
    id: 'combo-link-credentials',
    weight: 15,
    title: 'Suspicious link combined with a credential request',
    needsUrlFlag: true,
    categories: ['credentials'],
    detail: 'A message that both carries a deceptive link and asks for codes or logins is a phishing attempt with near certainty.'
  },
  {
    id: 'combo-threat-secrecy',
    weight: 15,
    title: 'Threats plus secrecy — the "digital arrest" signature',
    categories: ['threat', 'secrecy'],
    detail: 'Threatening arrest while forbidding you to tell family or your bank is the exact script of digital-arrest and impersonation scams.'
  },
  {
    id: 'combo-impersonation-urgency',
    weight: 12,
    title: 'Official-looking notice with a countdown',
    categories: ['impersonation', 'urgency'],
    detail: 'Real institutions do not give you 24 hours by SMS. Impersonation plus a deadline is a phishing pattern.'
  },
  {
    id: 'combo-payment-pressure',
    weight: 10,
    title: 'Untraceable payment with time pressure',
    categories: ['payment', 'urgency'],
    detail: 'Being rushed to pay by gift card, wire, or crypto is a hallmark of fraud.'
  }
];

// Plain-language guidance shown when a category fires.
export const ADVICE = {
  credentials: 'Never share an OTP, PIN, CVV, or password with anyone — not even someone claiming to be your bank. Banks never ask.',
  payment: 'Refuse any request to pay by gift card, wire transfer, or cryptocurrency. Legitimate organizations never collect money this way.',
  threat: 'Hang up / do not reply. Police and courts never demand money or announce arrests by phone or message. Call your local police directly if worried.',
  'remote-access': 'Never install remote-access apps (AnyDesk, TeamViewer) or APK files at a stranger\'s request — they can see and control everything on your device.',
  'too-good': 'If it sounds too good to be true, it is. Do not pay any "fee" to claim a prize or unlock returns.',
  impersonation: 'Contact the organization yourself through its official app or by typing its website address — never through a link or number in the message.',
  job: 'Never pay to get a job. Real employers do not charge registration or training fees.',
  secrecy: 'Do the opposite: tell a family member or friend right now. Scammers isolate victims because outsiders spot the fraud immediately.',
  refund: 'Do not click. Check refunds only inside the official app or website. In UPI apps, remember: you never need to approve a request or enter a PIN to RECEIVE money.',
  'phishing-action': 'Do not click the link. Open the official app or type the official address in your browser yourself.',
  urgency: 'Slow down. Urgency is manufactured to stop you from thinking. Take ten minutes and ask someone you trust.',
  channel: 'Be wary of any business that operates only over WhatsApp or Telegram or pushes you to call unknown numbers.',
  'advance-fee': 'Never send money to receive money, a parcel, or a prize. The "fee" is the scam.',
  'tech-support': 'Close the pop-up / hang up. Never call a number in a virus warning or let anyone remotely access your device. Real tech companies never cold-call you about infections.',
  'emergency': 'Stop and verify. Call the relative directly on the number you already have, or check with another family member, before sending any money — even if the caller sounds panicked and says not to.',
  'quishing': 'Do not scan QR codes from unexpected messages, emails, or stickers. Type the official web address yourself instead.',
  'toll-fine': 'Do not click the link or pay. Check unpaid tolls only through the official toll agency\'s app or website, typed in yourself — never a link from a text.',
  'payment-redirect': 'Never change payment or bank details based on an email or message alone. Call the person or company using a phone number you already had on file — not one from this message — to confirm before sending any payment.',
  url: 'Check the address carefully: the real domain is what comes just before the last dot (e.g. "paypal.com", not "paypal.com.verify-login.xyz").'
};
