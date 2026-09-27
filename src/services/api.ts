import { analyzeDemoEmail, deleteInvestigation, getInvestigation, listInvestigations, sampleInvestigation, saveInvestigation } from './demoEngine';

export const DEMO_MODE = true;
export const headers = () => ({});
const feedbackKey = (caseId: string) => `rakshak-demo-feedback-${caseId}`;

export async function api(path: string, options: RequestInit = {}) {
  const method = (options.method || 'GET').toUpperCase();
  if (path === '/settings') return { network_lookups: false, demo_mode: true };
  if (path === '/investigations' && method === 'GET') return listInvestigations();
  if (path.startsWith('/demo/') && method === 'POST') return saveInvestigation(await sampleInvestigation(path.split('/').pop() || 'phishing_email'));
  const match = path.match(/^\/investigations\/([^/?]+)(.*)$/);
  if (match) {
    const [, caseId, suffix] = match;
    if (!suffix && method === 'GET') {
      const value = getInvestigation(caseId);
      if (!value) throw new Error('This local demo result is no longer available.');
      return value;
    }
    if (!suffix && method === 'DELETE') { deleteInvestigation(caseId); return { status: 'deleted' }; }
    if (suffix === '/feedback' && method === 'GET') return JSON.parse(localStorage.getItem(feedbackKey(caseId)) || 'null');
    if (suffix === '/feedback' && method === 'POST') {
      const value = JSON.parse(String(options.body || '{}'));
      localStorage.setItem(feedbackKey(caseId), JSON.stringify(value));
      return value;
    }
    if (suffix.startsWith('/summary') && method === 'POST') {
      const value = getInvestigation(caseId);
      return { status: 'LOCAL DEMO SUMMARY', summary: `${value?.risk_level || 'Unknown'} risk (${value?.risk_score ?? '—'}/100). ${value?.evidence?.map((item: any) => item.signal).join('; ') || 'No weighted warning signs were found.'} Live Gemini summaries require the full backend.` };
    }
    if (suffix === '/redirect-preview' && method === 'POST') return { status: 'DATA NOT AVAILABLE', hops: [], final_destination: null, note: 'Static demo does not contact URLs.' };
  }
  throw new Error('This feature needs the full Rakshak backend.');
}

export async function upload(file: File, onProgress: (n: number) => void) {
  onProgress(15);
  const text = await file.text();
  onProgress(65);
  const result = await analyzeDemoEmail(text, file.name);
  onProgress(100);
  return saveInvestigation(result);
}
