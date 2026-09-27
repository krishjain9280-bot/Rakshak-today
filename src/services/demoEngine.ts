const STORE = 'rakshak-demo-investigations';

const samples: Record<string, string> = {
  safe_email: `From: Priya Sharma <priya@college.example>\nTo: Team <team@college.example>\nSubject: Project meeting notes and next review\nDate: Fri, 11 Sep 2026 10:00:00 +0530\nMessage-ID: <safe-001@college.example>\n\nHello team,\nAttached are the meeting notes. Our next review is Tuesday at 3 PM.\nRegards,\nPriya`,
  phishing_email: `From: PayPal Security <security@paypa1-login.example>\nTo: Student <student@college.example>\nReply-To: Recovery <recover@account-support.example>\nReturn-Path: <mailer@dispatch.example>\nSubject: URGENT: Verify your account or lose access\nDate: Fri, 11 Sep 2026 11:00:00 +0530\nAuthentication-Results: demo.receiver.example; spf=fail; dkim=fail; dmarc=fail\n\nYour PayPal account will be suspended within 24 hours. Sign in immediately and verify your account password at http://paypa1-login.example/login/verify. Send your OTP verification code to prevent unauthorized access. This is a fictional training email.`,
  suspicious_attachment: `From: Billing Desk <billing@vendor.example>\nTo: Accounts <accounts@company.example>\nReply-To: payment@quick-settlement.example\nSubject: Overdue invoice - immediate payment required\nDate: Fri, 11 Sep 2026 12:00:00 +0530\nMIME-Version: 1.0\nContent-Type: application/octet-stream; name="invoice.pdf.exe"\nContent-Disposition: attachment; filename="invoice.pdf.exe"\n\nYour invoice is overdue. Open the attached file and pay immediately to avoid penalties.`,
};

const header = (text: string, name: string) => text.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'))?.[1]?.trim() || '';
const address = (value: string) => value.match(/[\w.+-]+@[\w.-]+/i)?.[0] || value;
const domainOf = (value: string) => address(value).split('@')[1]?.toLowerCase() || '';
const uniq = <T,>(values: T[]) => [...new Set(values)];

function publicIp(value: string) {
  const octets = value.split('.').map(Number);
  if (octets.length !== 4 || octets.some(n => Number.isNaN(n) || n > 255)) return false;
  return !(octets[0] === 10 || octets[0] === 127 || (octets[0] === 192 && octets[1] === 168) || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31));
}

async function digest(text: string) {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map(n => n.toString(16).padStart(2, '0')).join('');
}

function displayName(value: string) {
  return value.replace(/<.*$/, '').replace(/["']/g, '').trim().toLowerCase();
}

function lookalike(domain: string, sender: string) {
  const normalized = domain.replace(/0/g, 'o').replace(/1/g, 'l').replace(/[^a-z]/g, '');
  const brands = ['paypal', 'microsoft', 'google', 'amazon', 'apple', 'swiggy'];
  return brands.find(brand => (normalized.includes(brand) || displayName(sender).includes(brand)) && !domain.endsWith(`${brand}.com`));
}

function statusFromAuth(auth: string, method: string) {
  const reported = auth.match(new RegExp(`${method}=([a-z]+)`, 'i'))?.[1]?.toUpperCase() || 'UNKNOWN';
  return {
    status: 'UNKNOWN',
    reported_status: reported,
    source: 'untrusted uploaded header',
    explanation: reported === 'UNKNOWN'
      ? `No ${method.toUpperCase()} result was present in the uploaded email.`
      : `The uploaded header reports ${method.toUpperCase()} ${reported}, but a static browser demo cannot independently verify it.`,
    evidence: auth ? [auth] : [],
  };
}

export async function analyzeDemoEmail(text: string, filename = 'uploaded-email.eml') {
  const from = header(text, 'From') || 'UNKNOWN';
  const to = header(text, 'To') || 'UNKNOWN';
  const replyTo = header(text, 'Reply-To');
  const returnPath = header(text, 'Return-Path');
  const subject = header(text, 'Subject') || '(No subject)';
  const date = header(text, 'Date') || 'UNKNOWN';
  const messageId = header(text, 'Message-ID') || 'UNKNOWN';
  const authHeader = header(text, 'Authentication-Results');
  const split = text.search(/\r?\n\r?\n/);
  const body = split >= 0 ? text.slice(split).trim() : text;
  const combined = `${subject} ${body}`;
  const urls = uniq(text.match(/https?:\/\/[^\s<>"']+/gi) || []);
  const emails = uniq(text.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi) || []);
  const domains = uniq([...emails.map(domainOf), ...urls.map(url => { try { return new URL(url).hostname; } catch { return ''; } })].filter(Boolean));
  const ips = uniq((text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(publicIp));
  const attachments = uniq([...text.matchAll(/filename\*?=(?:UTF-8''|)["']?([^"'\r\n;]+)/gi)].map(match => match[1].trim()));
  const fromDomain = domainOf(from), replyDomain = domainOf(replyTo), returnDomain = domainOf(returnPath);
  const brand = lookalike(fromDomain, from);

  const contentRules = [
    { key: 'Urgency', pattern: /urgent|immediately|within \d+ hours?|act now|final warning/i, points: 6 },
    { key: 'Credential request', pattern: /password|sign in|login|verify (?:your )?account/i, points: 14 },
    { key: 'OTP request', pattern: /\botp\b|verification code|one[- ]time password/i, points: 12 },
    { key: 'Financial request', pattern: /invoice|payment|bank transfer|gift card|send money|overdue/i, points: 10 },
    { key: 'Threatening language', pattern: /suspend|lose access|penalt|legal action|unauthorized/i, points: 6 },
  ];
  const matched = contentRules.filter(rule => rule.pattern.test(combined));
  const aiScore = Math.min(40, matched.reduce((sum, rule) => sum + rule.points, 0));
  const senderEvidence: any[] = [];
  let senderScore = 0;
  if (replyDomain && fromDomain && replyDomain !== fromDomain) { senderScore += 7; senderEvidence.push({ contribution: 7, signal: 'Reply-To domain mismatch', source: 'Reply-To', evidence: `From uses ${fromDomain}; replies go to ${replyDomain}.` }); }
  if (returnDomain && fromDomain && returnDomain !== fromDomain) { senderScore += 4; senderEvidence.push({ contribution: 4, signal: 'Return-Path domain mismatch', source: 'Return-Path', evidence: `From uses ${fromDomain}; Return-Path uses ${returnDomain}.` }); }
  if (brand) { senderScore += 20; senderEvidence.push({ contribution: 20, signal: 'Possible brand lookalike', source: 'Domain similarity', evidence: `${fromDomain} resembles or claims ${brand}.com.` }); }
  senderScore = Math.min(35, senderScore);

  const analyzedUrls = urls.map(url => {
    const parsed = new URL(url);
    const signs = [
      parsed.protocol === 'http:' ? 'Unencrypted HTTP' : '',
      /login|verify|password|payment|account/i.test(parsed.pathname) ? 'Sensitive action URL' : '',
      /^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname) ? 'IP-based URL' : '',
      parsed.port && !['80', '443'].includes(parsed.port) ? 'Unusual port' : '',
    ].filter(Boolean);
    return { url, visible_text: [url], domain: parsed.hostname, signals: signs, redirect_status: 'NOT CHECKED — static demo does not contact links', final_destination: null };
  });
  const riskyFiles = attachments.filter(name => /\.(exe|js|vbs|bat|cmd|ps1|zip|rar|iso|docm|xlsm)$/i.test(name));
  const actionBase = analyzedUrls.some(item => item.signals.length) ? 15 : 0;
  const attachmentPoints = riskyFiles.length ? 10 : 0;
  const correlation = matched.some(rule => ['Credential request', 'OTP request'].includes(rule.key)) && matched.some(rule => rule.key === 'Urgency') ? 6 : 0;
  const actionScore = Math.min(25, actionBase + attachmentPoints + correlation);
  const riskScore = Math.min(100, aiScore + senderScore + actionScore);
  const riskLevel = riskScore >= 71 ? 'High' : riskScore >= 31 ? 'Medium' : 'Low';
  const threatCategory = matched.some(rule => ['Credential request', 'OTP request'].includes(rule.key)) ? 'Credential Phishing' : matched.some(rule => rule.key === 'Financial request') ? 'Financial Fraud / Invoice Scam' : riskScore >= 31 ? 'Suspicious Email' : 'No strong threat pattern';
  const fileHash = await digest(text);
  const now = new Date().toISOString();
  const caseId = `DEMO-${fileHash.slice(0, 10).toUpperCase()}`;
  const domainRows = domains.map(domain => {
    const similar = lookalike(domain, from);
    return { domain, lookalike: similar ? `${similar}.com` : null, similarity: similar ? 92 : null, edit_distance: null, similarity_reason: similar ? `${domain} resembles ${similar}.com; this heuristic is not proof of impersonation.` : 'No configured brand match.', status: 'DATA NOT AVAILABLE', dns: {}, rdap_status: 'DATA NOT AVAILABLE', registrar: null, creation_date: null, age_days: null, nameservers: [], reputation: 'DATA NOT AVAILABLE', reason: 'Static demo does not perform network lookups.' };
  });
  const attachmentRows = await Promise.all(attachments.map(async name => ({ filename: name, extension: name.split('.').pop()?.toLowerCase() || '', mime_type: header(text, 'Content-Type') || 'application/octet-stream', size: 0, sha256: await digest(name), verdict: riskyFiles.includes(name) ? 'Potentially risky file type — not proof of malware' : 'No risky extension detected', signals: /\.[^.]+\.(exe|js|vbs|bat|cmd|ps1)$/i.test(name) ? ['Double extension', 'Potentially executable type'] : riskyFiles.includes(name) ? ['Potentially executable or archive type'] : [], limitation: 'Metadata-only browser demo. The file was not opened or executed.' })));
  const evidence = [
    ...(aiScore ? [{ category: 'AI Text Analysis', contribution: aiScore, signal: 'Deterministic language threat assessment', source: 'Browser demo rules', evidence: `Matched: ${matched.map(rule => rule.key).join(', ')}.` }] : []),
    ...senderEvidence.map(item => ({ category: 'Sender & Domain Reputation', ...item })),
    ...(actionBase ? [{ category: 'Urgent Actions, Links & Attachments', contribution: actionBase, signal: 'Suspicious link characteristics', source: 'URL analysis', evidence: analyzedUrls.flatMap(item => item.signals).join(', ') }] : []),
    ...(attachmentPoints ? [{ category: 'Urgent Actions, Links & Attachments', contribution: attachmentPoints, signal: 'Potentially risky attachment type', source: 'Attachment metadata', evidence: riskyFiles.join(', ') }] : []),
    ...(correlation ? [{ category: 'Urgent Actions, Links & Attachments', contribution: Math.min(correlation, Math.max(0, 25 - actionBase - attachmentPoints)), signal: 'Correlated high-risk request', source: 'Cross-signal correlation', evidence: 'Sensitive request combined with urgent language.' }] : []),
  ].filter(item => item.contribution > 0);
  const emailAddresses = uniq([address(from), address(to), address(replyTo), address(returnPath), ...emails].filter(Boolean));
  const iocs = [
    ...analyzedUrls.map(item => ({ type: 'URL', value: item.url, source: 'Email body', risk: item.signals.length ? 'Medium' : 'Unverified', reason: item.signals.join('; ') || 'Observed URL', confidence: 45, verified: false })),
    ...domainRows.map(item => ({ type: 'Domain', value: item.domain, source: 'Email address / URL', risk: item.lookalike ? 'Medium' : 'Unverified', reason: item.similarity_reason, confidence: 45, verified: false })),
    ...emailAddresses.map(value => ({ type: 'Email address', value, source: 'Email metadata / body', risk: 'Unverified', reason: 'Observed address; not independently verified.', confidence: 45, verified: false })),
  ];
  const threatIntel = [...urls.map(indicator => ({ type: 'url', indicator })), ...domains.map(indicator => ({ type: 'domain', indicator }))].flatMap(item => ['VirusTotal', 'URLhaus', 'AlienVault OTX'].map(provider => ({ provider, ...item, status: 'DATA NOT AVAILABLE', malicious: null, details: {}, queried_at: null, reason: 'Static frontend demo does not contact external services.' })));
  const auth = { SPF: statusFromAuth(authHeader, 'spf'), DKIM: statusFromAuth(authHeader, 'dkim'), DMARC: statusFromAuth(authHeader, 'dmarc') };
  const graphNodes = [{ id: 'email', position: { x: 0, y: 0 }, data: { label: caseId, type: 'Email', value: caseId }, style: {} }, { id: 'sender', position: { x: 280, y: 0 }, data: { label: from, type: 'Sender', value: from }, style: {} }, ...domains.map((domain, index) => ({ id: `domain-${index}`, position: { x: 560, y: index * 110 }, data: { label: domain, type: 'Domain', value: domain }, style: {} }))];
  const graphEdges = [{ id: 'email-sender', source: 'email', target: 'sender', label: 'sent as' }, ...domains.map((_, index) => ({ id: `sender-domain-${index}`, source: 'sender', target: `domain-${index}`, label: 'observed' }))];

  return {
    case_id: caseId, created_at: now, filename, email_sha256: fileHash, demo: true, subject, sender: from, threat_category: threatCategory,
    email: { from, to, cc: header(text, 'Cc'), reply_to: replyTo, return_path: returnPath, subject, date, message_id: messageId, received: [], authentication_results: authHeader ? [authHeader] : [], dkim_signatures: [], originating_ip_headers: [], link_labels: [], body_text: body, html_body: '', urls, domains, email_addresses: emailAddresses, ips, truncated: false },
    auth,
    sender_analysis: { domains: { from: fromDomain, reply_to: replyDomain, return_path: returnDomain }, signals: senderEvidence },
    ai: { engine: 'Rakshak deterministic browser demo', model_status: 'Static demo uses transparent rules only. The trained backend model and live intelligence services are not included.', language: { scripts: [], hinglish_signals: false, coverage: 'English security terms; limited mixed-language coverage.', model_applicable: false }, probability: null, confidence: null, category: threatCategory, signals: matched.map(rule => ({ signal: rule.key, evidence: [combined.match(rule.pattern)?.[0] || rule.key], weight: rule.points, source: 'subject / body' })), explanation: matched.length ? `${matched.length} transparent content signals were detected and combined with sender, link, and attachment evidence.` : 'No configured high-risk language pattern was detected. This does not certify the email as safe.' },
    urls: analyzedUrls, domains: domainRows,
    ips: ips.map(ip => ({ ip, status: 'DATA NOT AVAILABLE', country: null, region: null, city: null, asn: null, organization: null, isp: null, vpn: 'UNKNOWN', proxy: 'UNKNOWN', tor: 'UNKNOWN', reason: 'Static demo does not perform geolocation or reputation lookups.' })),
    attachments: attachmentRows, threat_intel: threatIntel, iocs, campaigns: [],
    timeline: ['Email parsing', 'Authentication headers', 'Sender comparison', 'Content rules', 'URL analysis', 'Attachment metadata', 'Explainable risk assessment', 'IOC extraction'].map(stage => ({ stage, status: 'COMPLETE', duration_ms: 0, timestamp: now })),
    risk_score: riskScore, risk_level: riskLevel,
    category_scores: { 'AI Text Analysis': aiScore, 'Sender & Domain Reputation': senderScore, 'Urgent Actions, Links & Attachments': actionScore },
    category_caps: { 'AI Text Analysis': 40, 'Sender & Domain Reputation': 35, 'Urgent Actions, Links & Attachments': 25 },
    evidence, correlations: correlation ? ['Sensitive request combined with urgent language'] : [], confidence: 45,
    confidence_explanation: 'Demo evidence coverage is limited to data present inside the .eml file. DNS, RDAP, geolocation, reputation, and provider-verified authentication require the full backend.',
    date,
    origin: { status: ips.length ? 'OBSERVED IP — NOT ATTRIBUTED TO PERSON' : 'UNKNOWN', earliest_observed_ip: ips[0] || null, reliable_origin_ip: null, sender_device_ip: null, sender_device_ip_header: null, sender_device_ip_status: 'NOT PROVIDED OR NOT VERIFIED', sender_location: 'UNKNOWN', sender_location_status: 'NOT DETERMINED', country: null, region: null, city: null, asn: null, organization: null, source_hop: null, hops: [], explanation: 'A static email cannot reliably reveal a person’s physical location. Live backend enrichment can describe observed public mail infrastructure when an IP is available.' },
    limitations: ['This is a frontend-only demonstration using transparent browser rules.', 'No DNS, RDAP, geolocation, reputation, Gemini, or provider authentication queries are made.', 'Uploaded files remain in this browser and are not sent to a server.', 'Attachment analysis is metadata-only; files are never opened or executed.', 'A low score is not proof that an email is safe.'],
    graph: { nodes: graphNodes, edges: graphEdges, truncated: false }, risk_policy_version: 'demo-1.0 — three-pillar deterministic rules',
  };
}

export async function sampleInvestigation(name: string) {
  return analyzeDemoEmail(samples[name] || samples.phishing_email, `${name}.eml`);
}

export function listInvestigations() {
  try { return JSON.parse(localStorage.getItem(STORE) || '[]'); } catch { return []; }
}

export function saveInvestigation(value: any) {
  const all = [value, ...listInvestigations().filter((item: any) => item.case_id !== value.case_id)].slice(0, 20);
  localStorage.setItem(STORE, JSON.stringify(all));
  return value;
}

export function getInvestigation(caseId: string) {
  return listInvestigations().find((item: any) => item.case_id === caseId);
}

export function deleteInvestigation(caseId: string) {
  localStorage.setItem(STORE, JSON.stringify(listInvestigations().filter((item: any) => item.case_id !== caseId)));
}
