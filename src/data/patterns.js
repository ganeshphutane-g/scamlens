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
      // Hinglish / Devanagari: "OTP batao/bhejo", "PIN share karo"
      /\b(otp|pin|password|cvv|code|number)\b.{0,20}\b(batao|bta ?do|bhejo|bhej ?do|share ?karo|de ?do|likho|forward ?karo)\b/i,
      /(ओटीपी|पासवर्ड|पिन|कोड).{0,15}(बताओ|भेजो|भेज दो|साझा|शेयर)/,
      // Unambiguous "give it to a third party" verbs only — NOT enter/verify/
      // confirm/update (legit self-service 2FA), NOT past-tense delivery
      // ("we SENT you an OTP"), and NOT negated safety advice ("NEVER share
      // your OTP", "do not share it with anyone" — the exact line banks
      // themselves send). The leading negative lookbehind drops negated
      // advice; present-imperative/gerund-only verbs drop the delivery case.
      /(?<!\b(?:not|never|dont|don'?t|n'?t|kabhi|mat|nahi)\b[\s\w]{0,25})\b(shar(e|ing)|send(ing)?|provid(e|ing)|giv(e|ing)|tell(ing)?|repl(y|ying)|forward(ing)?|read (it )?out|read us|reading (it )?out)\b[^.\n!?]{0,50}\b(otp|one[- ]?time (password|passcode|pin)|password|passcode|pin\b|cvv|card number|debit card|credit card|upi pin|mpin|atm pin|aadhaar number|pan (card|number)|ssn|social security|bank (details|account)|net ?banking|login (details|credentials)|security code|verification code)\b/i,
      /\b(otp|upi pin|cvv|password|mpin|verification code)\b[^.\n!?]{0,40}(?<!\b(?:not|never|dont|don'?t|n'?t|kabhi|mat|nahi)\b[\s\w]{0,20})\b(shar(e|ing)|send(ing)?|provid(e|ing)|repl(y|ying)|batao|bhejo)\b/i,
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
      // Hinglish / Devanagari — must name an UNTRACEABLE rail (gift card,
      // crypto, voucher, recharge code). Bare "paise bhej do" is an ordinary
      // request between people, not a scam, so it is intentionally excluded.
      /\b(gift ?card|google play|itunes|voucher|recharge (code|coupon)|bitcoin|crypto|usdt|paytm cash)\b.{0,25}\b(bhejo|bhej ?do|kharido|khareedo|le ?lo|de ?do|transfer ?karo)\b/i,
      /(गिफ्ट कार्ड|वाउचर|बिटकॉइन|रिचार्ज कोड).{0,20}(भेजो|भेज दो|खरीदो)/,
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
      // Hinglish / Devanagari arrest/police threats
      /\b(giraftar|gireftar|giraftari|police ?case|thane ?(bula|aana)|jail ?bhej|arrest ?ho|warrant ?nikla|kanooni ?(karyawahi|karvai)|digital ?arrest)\b/i,
      /(गिरफ्तार|पुलिस केस|कानूनी कार्रवाई|वारंट|जेल)/,
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
      /\b((your (computer|pc|device|iphone|mac|system) (is|has been|may be) (infected|hacked|compromised|blocked|at risk))|virus (detected|found|alert)|malware detected|(microsoft|apple|windows|norton|mcafee) (support|security|technician).{0,40}(call|contact|dial)|call (this )?(toll[- ]?free )?number.{0,30}(support|technician|microsoft|apple|remove|virus)|do not (restart|turn off|shut down) your (computer|pc|device))\b/i,
      // Hinglish / Devanagari tech-support
      /\b(computer|system|laptop|device|pc)\b.{0,25}\b(virus (hai|aa gaya|mil)|infect\w*|hack ho|band ho|block ho gaya)\b/i,
      /\b(virus|technician|microsoft|support)\b.{0,25}\b(call kare|number par call|number pe call|se baat kare)\b/i,
      /(वायरस|हैक हो|तकनीशियन|कंप्यूटर.{0,15}(वायरस|संक्रमित))/
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
      // Money-specific only — "need help right now" is everyday phrasing and
      // must not fire this on its own.
      /\bneed (money|bail|cash) (right )?(now|urgently|immediately|asap|today)\b/i,
      /\b(mom|dad|grandma|grandpa|mum),? i (need|lost)\b.{0,40}(money|phone)/i
    ]
  },
  {
    id: 'quishing',
    category: 'quishing',
    weight: 16,
    title: 'Asks you to scan a QR code to pay or log in',
    detail: 'A QR code in an unexpected message, email, sticker, or letter can send you straight to a phishing site or authorize a payment. Type the address yourself instead of scanning codes from strangers.',
    re: [
      // Only fire when the QR is tied to a payment/login/account action —
      // NOT benign uses like a restaurant menu or event check-in QR.
      /\bqr ?code\b.{0,45}\b(pay|verif|log ?in|sign ?in|claim|confirm|receive|account|fee|parcel|deliver|redeliver|bank|wallet|refund|prize|reward|unlock|kyc)\b/i,
      /\b(pay|verif|log ?in|sign ?in|claim|confirm|unlock|kyc)\b.{0,30}\bqr ?code\b/i
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
      // Hinglish / Devanagari lottery/prize lures
      /\b(inaam|inam|lottery ?lag|lucky ?draw ?(jeeta|jita)|free ?recharge|muft|paisa ?jeeta|jeet ?gaye|badhai ?ho)\b/i,
      /(इनाम|लॉटरी|मुफ्त|बधाई हो|जीत)/,
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
      // Hinglish / Devanagari: account/KYC/electricity notices
      /\b((khata|account) (band|block) ?ho|kyc ?(update|karo|karwao|expire|khatam)|bijli ?(kat|katega|cut|connection)|(sim|number) ?band ?ho|verify ?karo)\b/i,
      /(खाता बंद|केवाईसी|बिजली (कट|कनेक्शन)|सिम बंद|सत्यापन)/,
      /\b(kyc (update|expired?|expiring|pending|verification|suspended)|pan card.{0,30}(update|link|expire)|aadhaar.{0,30}(link|update|suspend|verify)|electricity (bill|connection|meter).{0,40}(disconnect\w*|cut\w*|suspend\w*)|(income )?tax refund|customs (duty|clearance|fee)|(parcel|package|shipment|courier).{0,40}(held|stuck|detained|on hold|could not be delivered|delivery failed|address (issue|problem|incomplete)).{0,70}(pay (a |the |your |₹|\$|rs)|(re-?delivery|redelivery|customs|clearance|handling) (fee|charge|duty)|click (here|the link|below)|(re-?schedule|reschedule) (your )?delivery|update your (address|payment)|to release|link below)|account.{0,25}(frozen|blocked|suspended|deactivated|locked)|sim (card )?(will be )?(blocked|deactivated|suspended)|upgrad(e|ing) (our|the|your)?\s?network|port(ing)? (your|the) number|prevent(ing)? (a |the )?(sim )?port|keep your number (active|safe))\b/i
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
    id: 'subscription-refund',
    category: 'subscription-refund',
    weight: 32,
    title: 'Fake subscription-renewal charge with a "call to cancel" hook',
    detail: 'A surprise "your subscription auto-renewed for a large amount, call us to cancel or get a refund" message is a scam. The number connects you to fraudsters who will try to take control of your device or bank account. Check subscriptions only inside the real app or your card statement.',
    re: [
      // Trigger requires a phone/dispute hook (call/dial/refund/dispute/
      // unauthorized) — NOT bare "cancel"/"contact", which legit renewal
      // emails use for self-service ("to cancel, go to Settings").
      /\b(subscription|membership|antivirus|norton|mcafee|geek squad|auto[- ]?renew\w*|your plan)\b.{0,90}\b(renew|charg|debit|bill)\w*\b.{0,90}\b(call|dial|refund|dispute|unauthorized|did ?n'?t authorize|not authorize)\b/i
    ]
  },
  {
    id: 'crypto-recovery',
    category: 'crypto-recovery',
    weight: 32,
    title: 'Fake "we can recover your lost crypto/funds" offer',
    detail: 'These scams target people who were already defrauded, promising to recover lost money for an upfront fee or your wallet details — then steal again. No legitimate service guarantees recovery of lost crypto, and none needs your seed phrase or private key.',
    re: [
      /\blost (money|funds|crypto|bitcoin|investment)\b.{0,45}(scam|fraud|scammer|hack)\b.{0,70}(recover|get (it|them|your.{0,20})?back|reclaim|retriev)/i,
      /\b(recover|recovery|reclaim|retriev\w+)\b.{0,45}\b(lost|stolen|scammed)\b.{0,30}\b(crypto|bitcoin|btc|funds|money|investment|wallet)\b/i,
      /\b(recovery|upfront) fee\b.{0,45}\b(crypto|bitcoin|funds|wallet|recover)\b/i,
      /\b(send|share|provide)\b.{0,25}\b(wallet (address|details)|seed phrase|private key|recovery phrase)\b/i
    ]
  },
  {
    id: 'overpayment',
    category: 'payment',
    weight: 24,
    title: 'Overpayment / fake-check "send the extra back" scam',
    detail: 'A buyer who "accidentally" overpays and asks you to refund the difference is running a fake-check scam: their payment bounces days later, but the money you sent back is real and gone. Never refund an overpayment.',
    re: [
      /\b(cashier'?s? ?check|cheque|check|money ?order|payment|zelle|wire)\b.{0,60}\b(more than|extra|over ?paid|overpay\w*|too much|by mistake|wrong amount)\b/i,
      /\bsend (the |me the )?(extra|difference|balance|remaining|overpaid|excess)( amount)? back\b/i,
      /\b(refund|send|wire|return)\b.{0,30}\b(extra|difference|balance)\b.{0,40}\b(shipping (agent|company)|mover|shipper|courier|my agent)\b/i
    ]
  },
  {
    id: 'sextortion',
    category: 'sextortion',
    weight: 28,
    title: 'Sextortion / webcam blackmail',
    detail: 'Emails claiming to have recorded you through your webcam and threatening to send it to your contacts are a bluff sent to millions at once. They have no video. Do not pay, do not reply — delete it.',
    re: [
      /\b(recorded|filmed|captured|footage|video|webcam|camera|screen ?record)\b.{0,45}\b(adult|porn|explicit|xxx|you (were )?(watching|visiting)|while you)\b/i,
      /\b(send|leak|share|release|publish|expose|post|forward)\b.{0,45}\b(video|footage|recording|clip|it)\b.{0,30}\b(all (your|of your) )?(contacts|friends|family|everyone you know|social media)\b/i,
      /\b(i (have|know) your (password|contacts)|i (hacked|have access to) your (device|phone|camera|webcam|email))\b/i
    ]
  },
  {
    id: 'bank-fraud-alert',
    category: 'bank-fraud-alert',
    weight: 24,
    title: 'Fake bank fraud-alert callback',
    detail: 'A "we blocked a suspicious transaction, call us to reverse it" message tricks you into calling fraudsters who then walk you into approving the real theft. Never use a number from the message — call the number printed on your card.',
    re: [
      /\b(suspicious|unauthorized|unauthorised|fraudulent|unusual|declined) (transaction|charge|payment|activity|transfer|purchase|login|sign[- ]?in)\b.{0,80}\b(call|contact|dial|reply|press \d|tap|click)\b/i,
      /\bdid you (make|attempt|authorize|try to make)\b.{0,25}\b(a |this )?(payment|transaction|purchase|transfer|charge)\b/i,
      /\b(call|contact|dial) (us|our (fraud|security) (team|department))\b.{0,30}\b(reverse|cancel|dispute|decline|block|secure|stop) (it|this|the (transaction|charge|payment))\b/i
    ]
  },
  {
    id: 'rental-deposit',
    category: 'rental-deposit',
    weight: 22,
    title: 'Rental deposit ("landlord away, pay to hold") scam',
    detail: 'A landlord who is conveniently out of town and wants a deposit or first month\'s rent before you can view the place is a scam — they do not own it. Never send money for a rental you have not seen in person with a verified owner.',
    re: [
      /\b(apartment|flat|house|room|rental|property|place|condo)\b.{0,80}\b(out of (town|the country|state|the city)|abroad|overseas|another (city|state|country)|can'?t (show|meet|be there)|working (away|abroad|remotely)|missionary|military)\b/i,
      /\b(send|transfer|pay|wire|deposit)\b.{0,35}\b(deposit|holding fee|first month'?s? rent|security deposit)\b.{0,45}\b(hold|reserve|secure|before (anyone|someone|others)|ship (you )?the keys|mail (you )?the keys)\b/i
    ]
  },
  {
    id: 'advance-fee-payout',
    category: 'advance-fee',
    weight: 24,
    title: 'Pay a "fee" to release your payout/refund/claim',
    detail: 'Being told to pay a GST, processing, clearance, or release "fee" before you can receive a payout, refund, insurance claim, or prize is always a scam. Real payouts are never gated behind a fee you must pay first.',
    re: [
      /\b(payout|maturity (amount|value)|claim (amount|money)|pension|policy (amount|bonus)|insurance|prize money|refund|inheritance|compensation)\b.{0,80}\b(gst|processing|release|clearance|handling|service|registration|legal|transfer) (charge|fee|tax|amount)\b/i,
      /\b(deposit|pay|submit)\b.{0,30}\b(gst|processing|release|clearance|handling) (charge|fee|tax)\b.{0,45}\b(to (release|receive|claim|get|unlock)|before)\b/i
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
    // Deliberately below the STRONG_SIGNAL_WEIGHT anchor (18): a secrecy
    // request alone (e.g. "don't tell mom about the surprise party") is
    // often innocent, so on its own it must stay in "low". Its real power is
    // in the threat+secrecy combo (digital-arrest signature), which fires
    // regardless of this base weight.
    weight: 12,
    title: 'Tells you to keep it secret',
    detail: 'Scammers isolate victims. Anyone who says "do not tell your family or your bank" is hiding from the people who would recognize the fraud instantly.',
    re: [
      // Hinglish / Devanagari secrecy demands
      /\b(kisi ?ko ?(mat|na) ?(batao|bataye|bata|bolo)|kisi ?ko ?mat|private ?rakho|raaz ?rakho|gupt ?rakho)\b/i,
      /(किसी को (मत|ना) बता|गुप्त रखो|राज़ रखो)/,
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
      // Hinglish / Devanagari urgency
      /\b(turant|jaldi ?(karo|se)|abhi ?karo|aaj ?hi|foran|jald ?se ?jald|samay ?kam|der ?mat ?karo)\b/i,
      /(तुरंत|जल्दी|अभी करो|आज ही|देर मत)/,
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
  'subscription-refund': 'Do not call the number. Check any subscription directly in the real app or on your card statement. Scammers use fake renewal charges to get you to call, then take over your device or bank account.',
  'crypto-recovery': 'Ignore it. No legitimate service can guarantee recovery of lost crypto, and none needs an upfront fee, your seed phrase, or your private key. These target people who were already scammed.',
  'toll-fine': 'Do not click the link or pay. Check unpaid tolls only through the official toll agency\'s app or website, typed in yourself — never a link from a text.',
  'payment-redirect': 'Never change payment or bank details based on an email or message alone. Call the person or company using a phone number you already had on file — not one from this message — to confirm before sending any payment.',
  sextortion: 'It is a bluff sent to millions at once — they have no video. Do not pay and do not reply. Delete it, and change any password they quote (it came from an old data breach, not your device).',
  'bank-fraud-alert': 'Do not call the number in the message. Hang up and call the number printed on the back of your card or in your official banking app. Real fraud teams never need you to "reverse" a charge by sending money or sharing codes.',
  'rental-deposit': 'Never pay a deposit or rent for a place you have not seen in person. A landlord who is "out of town" and cannot show it, but wants money to hold it, does not own it.',
  url: 'Check the address carefully: the real domain is what comes just before the last dot (e.g. "paypal.com", not "paypal.com.verify-login.xyz").'
};
