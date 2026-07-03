// Real-world-shaped corpus: known scam scripts must score high; ordinary
// legitimate messages must stay low. This is the regression net that keeps
// detection honest while patterns evolve.

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, LEVELS } from '../src/engine.js';

const SCAMS = [
  ['bank OTP phishing', 'Dear customer your SBI account will be blocked within 24 hours. Please verify your KYC immediately. Share your OTP and click http://sbi-kyc-update.xyz/verify'],
  ['digital arrest', 'This is CBI officer. Your Aadhaar is linked to a money laundering case. You are under digital arrest. Do not tell anyone or your family. Pay fine of Rs 50,000 immediately to avoid arrest warrant.'],
  ['lottery', 'CONGRATULATIONS! You have won $2,500,000 in the international lottery. To claim your prize money send processing fee via Western Union.'],
  ['gift card demand', 'This is your CEO. I am in a meeting and need you to buy 5 Google Play gift cards of $100 each right away. Keep this confidential. Send the codes here.'],
  ['parcel customs', 'FedEx: Your parcel is held at customs. Pay customs clearance fee of Rs 280 to release delivery: http://fedex-parcel-release.top/pay'],
  ['electricity disconnect', 'Dear consumer your electricity connection will be disconnected tonight at 9.30 pm because your previous bill was not updated. Immediately contact our officer. Call this number 9812345678.'],
  ['job task scam', 'Part-time job offer! Earn Rs 5000 per day from home doing simple tasks. Just like and subscribe YouTube videos and get paid. Join our telegram channel to start. Small refundable registration fee required.'],
  ['investment', 'Join our crypto trading group! Guaranteed returns of 10% daily. Double your money in one week. 100% risk-free investment. WhatsApp me to start.'],
  ['phishing verify link', 'Your Netflix account has been suspended due to a billing problem. Update your payment information within 24 hours: https://netflix-billing-update.icu/verify'],
  ['remote access', 'Hello I am calling from Paytm support. Your KYC is expired. Install AnyDesk app so I can help you verify your account. Then share the code shown.'],
  ['UPI refund bait', 'You are eligible for a cashback of Rs 1,499. Approve the collect request in your UPI app and enter PIN to receive the money immediately.'],
  ['romance advance fee', 'My dear, the customs officer needs a clearance fee of $300 to release the package I sent you with the gold jewelry. Send money via MoneyGram today so you can receive it.'],
  ['typosquat link', 'Security alert: unusual sign-in detected. Reset your password now at https://amaz0n-security.com/reset to avoid account suspension.'],
  ['paypal userinfo trick', 'Your PayPal account is limited. Restore access: http://paypal.com@203.0.113.9/restore. Act now to avoid permanent closure.'],
  ['digital arrest, "Aadhaar number" phrasing', 'This is calling from cyber crime branch. Your Aadhaar number has been linked to a case involving illegal drug parcels. You must cooperate fully and stay on this video call until we complete verification, or a warrant will be issued. Do not tell anyone about this call.'],
  ['toll-road smishing', 'FINAL NOTICE: You have an unpaid toll of $6.99. Pay immediately or pay a $50 fine and risk suspension of your driving privileges. Pay now: https://ezpass-toll-payments.com/pay'],
  ['business email compromise (bank-detail change)', 'Hi Tom, quick update - we have switched banks for compliance reasons. Please update your records and send this months payment to the new account within 24 hours to avoid any delay. Let me know once processed.'],
  ['SIM-swap social engineering', 'This is Alex from T-Mobile fraud prevention. We detected an attempt to port your number to a new carrier. To block this and keep your number safe, please read us the verification code that was just sent to your phone.'],
  ['fake job interview on Telegram', 'Congratulations, you have been shortlisted for the Data Entry Assistant remote position, salary $35/hour. Please proceed to our Telegram channel @hr-recruiting-2026 to complete your interview and receive your starter kit.'],
  ['trailing-dot URL evasion', 'Security alert: verify your account now at https://amaz0n-security.com./reset to avoid suspension'],
  ['IPv6 bare-IP link', 'Login here to verify your account and avoid suspension: http://[2001:db8::1]/bank-login within 24 hours'],
  ['tech-support popup', 'WARNING: Your computer is infected with a virus and has been blocked. Do not restart your computer. Call Microsoft support technician immediately at this toll-free number to remove the threat.'],
  ['grandparent emergency scam', 'Grandma, it is me your grandson. I have been in an accident and arrested. I need bail money right now urgently, please do not tell mom or dad, it is an emergency.'],
  ['quishing QR scam', 'Your parcel could not be delivered due to an address issue. Scan the QR code below to verify your details and pay the redelivery fee to receive your package.']
];

const LEGIT = [
  ['order shipped', 'Your Amazon order #171-2903 has shipped and will arrive Thursday. Track it at https://www.amazon.in/orders'],
  ['OTP delivery (not a request)', 'Your OTP for login is 482913. It is valid for 10 minutes. Do not share it with anyone. - HDFC Bank'],
  ['meeting reminder', 'Reminder: our project sync is at 3pm today in the usual room. Agenda attached. See you there!'],
  ['newsletter', 'This week in open source: 5 new releases you should know about. Read the full issue on our website.'],
  ['marketing sale', 'Flash sale! 40% off all shoes this weekend only. Shop at https://www.nike.com while stocks last.'],
  ['friend message', 'Hey, are we still on for dinner tomorrow? I found a nice place near the station. Let me know!'],
  ['bank statement notice', 'Your monthly account statement for June is now available in the HDFC Bank app under Statements.'],
  ['delivery update', 'Your package from Flipkart is out for delivery and should arrive by 8pm today.'],
  ['github notification', 'ci: build passed for scamlens#42. View the run at https://github.com/user/scamlens/actions'],
  ['invoice', 'Hi, please find attached the invoice for June services, due on the 15th as usual. Thanks!'],
  ['self-directed IT password reminder', 'IT Notice: Your corporate password expires in 3 days. Please update your password via the company portal before it expires to avoid account lockout.'],
  ['school portal password reminder', 'Reminder: Please update your password for the Parent Portal before it expires on Friday to keep receiving grade notifications.'],
  ['borderline: link + deadline + WhatsApp support (no single strong signal)', 'Please click the link below to verify your subscription before it expires today, or whatsapp us at this number for help.']
];

for (const [name, text] of SCAMS) {
  test(`scam detected: ${name}`, () => {
    const r = analyze(text);
    assert.ok(
      r.level === 'high' || r.level === 'critical',
      `expected high/critical, got ${r.level} (${r.score}) — signals: ${r.signals.map(s => s.id).join(', ') || 'none'}`
    );
  });
}

for (const [name, text] of LEGIT) {
  test(`legit not flagged: ${name}`, () => {
    const r = analyze(text);
    assert.ok(
      r.level === 'low' || r.level === 'medium',
      `expected low/medium, got ${r.level} (${r.score}) — signals: ${r.signals.map(s => s.id).join(', ')}`
    );
  });
}

test('empty input', () => {
  const r = analyze('');
  assert.equal(r.score, 0);
  assert.equal(r.level, 'low');
});

test('report shape', () => {
  const r = analyze('share your OTP now at http://paypa1.com');
  assert.ok(typeof r.score === 'number' && r.score >= 0 && r.score <= 100);
  assert.ok(LEVELS.includes(r.level));
  assert.ok(Array.isArray(r.signals) && Array.isArray(r.advice) && Array.isArray(r.urls));
  for (const s of r.signals) {
    assert.ok(s.id && s.title && s.detail && typeof s.weight === 'number');
  }
});
