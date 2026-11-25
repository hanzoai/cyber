/**
 * Wire types, route helpers, and deterministic helpers for Hanzo Cyber.
 *
 * Compatible with both Hanzo Cloud (`/v1/cyber/*` with Hanzo IAM bearer token)
 * and the standalone Go server (`cyber serve`, same-origin `/v1/cyber/*`).
 */

export const CYBER_TABS = [
  'overview',
  'graph',
  'findings',
  'approvals',
  'traffic',
  'chat',
  'attack',
  'coa',
  'hardening',
  'system',
] as const;

export type CyberTab = (typeof CYBER_TABS)[number];

export const CYBER_TAB_LABELS: Readonly<Record<CyberTab, string>> = {
  overview: 'Overview',
  graph: 'Mission graph',
  findings: 'Findings',
  approvals: 'Kai approvals',
  traffic: 'Traffic',
  chat: 'Cyber chat',
  attack: 'ATT&CK',
  coa: 'Course of action',
  hardening: 'Hardening',
  system: 'System & doctor',
};

export function parseCyberTab(pathname: string, search = ''): CyberTab {
  const clean = (pathname.split(/[?#]/)[0] || '').replace(/\/+$/, '');
  const stripped = clean.startsWith('/cyber/')
    ? clean.slice('/cyber/'.length)
    : clean === '/cyber'
      ? ''
      : clean.replace(/^\/+/, '');
  const seg = stripped.split('/')[0]?.trim().toLowerCase() ?? '';
  if ((CYBER_TABS as readonly string[]).includes(seg)) {
    return seg as CyberTab;
  }
  if (search) {
    const qs = search.startsWith('?') ? search.slice(1) : search;
    const tabParam = new URLSearchParams(qs).get('tab')?.trim().toLowerCase() ?? '';
    if ((CYBER_TABS as readonly string[]).includes(tabParam)) {
      return tabParam as CyberTab;
    }
  }
  return 'overview';
}

export function cyberPath(tab: CyberTab = 'overview'): string {
  return tab === 'overview' ? '/cyber' : `/cyber/${tab}`;
}

export type CyberSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type CyberFindingStatus = 'open' | 'verified' | 'remediated' | 'false_positive';
export type CyberNodeKind = 'goal' | 'intent' | 'finding' | 'hint' | 'action';
export type CyberApprovalStatus = 'pending' | 'approved' | 'denied' | 'always_allow';
export type CyberRuleAction = 'allow' | 'block' | 'require_approval' | 'tag';

export interface CyberDashboard {
  org: string;
  stage: string;
  engagements: number;
  tasks: number;
  findingsTotal: number;
  findingsVerified: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  pendingApprovals: number;
  trafficCount: number;
  rulesCount: number;
  verificationRate: number;
}

export interface CyberEngagement {
  id: string;
  name: string;
  target: string;
  scope: string[];
  mode: string;
  status: string;
  synthetic: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface CyberTask {
  id: string;
  engagementId: string;
  title: string;
  goal: string;
  status: string;
  phase: string;
  createdAt: number;
  updatedAt: number;
}

export interface CyberGraphNode {
  id: string;
  taskId: string;
  kind: CyberNodeKind;
  label: string;
  detail: string;
  status: string;
  severity?: string;
  parentId?: string;
  createdAt: number;
}

export interface CyberTaskGraph {
  task: CyberTask;
  nodes: CyberGraphNode[];
}

export interface CyberFinding {
  id: string;
  engagementId: string;
  taskId?: string;
  title: string;
  severity: CyberSeverity;
  category: string;
  cwe?: string;
  mitreTechnique?: string;
  mitreTactic?: string;
  status: CyberFindingStatus;
  target: string;
  evidenceQuote?: string;
  trafficId?: string;
  verified: boolean;
  verificationNote?: string;
  remediation?: string;
  createdAt: number;
  updatedAt: number;
}

export interface CyberTrafficRecord {
  id: string;
  engagementId: string;
  taskId?: string;
  method: string;
  url: string;
  host: string;
  statusCode: number;
  requestHeaders: string;
  requestBody: string;
  responseHeaders: string;
  responseBody: string;
  latencyMs: number;
  createdAt: number;
}

export interface CyberApproval {
  id: string;
  engagementId: string;
  taskId?: string;
  action: string;
  target: string;
  tool: string;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  kaiRationale: string;
  status: CyberApprovalStatus;
  decidedBy?: string;
  decidedAt?: number;
  createdAt: number;
}

export interface CyberInterceptRule {
  id: string;
  engagementId?: string;
  name: string;
  matchHost: string;
  matchPath: string;
  action: CyberRuleAction;
  enabled: boolean;
  createdAt: number;
}

export interface CyberAttackTechnique {
  techniqueId: string;
  tactic: string;
  name: string;
  findingCount: number;
  verifiedCount: number;
  maxSeverity: string;
}

export interface CyberAttackMatrix {
  tactics: string[];
  techniques: CyberAttackTechnique[];
}

export interface CyberCoaItem {
  id: string;
  title: string;
  priority: string;
  riskReduction: number;
  effort: string;
  mitreTechnique?: string;
  findingIds: string[];
  summary: string;
}

export interface CyberHardeningCheck {
  id: string;
  control: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
}

export interface CyberHardening {
  score: number;
  scopeEnforced: boolean;
  verbatimVerified: number;
  openCritical: number;
  checks: CyberHardeningCheck[];
}

export interface CyberChatMessage {
  id: string;
  taskId?: string;
  engagementId?: string;
  role: 'operator' | 'assistant' | 'system';
  model?: string;
  content: string;
  createdAt: number;
}

export interface CyberDoctorCheck {
  id: string;
  name: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
}

export interface CyberDoctorReport {
  status: 'ready' | 'degraded';
  version: string;
  runtime: string;
  probeAvailable: boolean;
  sandboxMode: string;
  mcpToolCount: number;
  iamConfigured: boolean;
  ensoEndpoint: string;
  checks: CyberDoctorCheck[];
}

export interface CyberSeedDemoResponse {
  engagement: CyberEngagement;
  tasks: number;
  findings: number;
  traffic: number;
  approvals: number;
  rules: number;
}

export function severityOrder(s: string): number {
  switch (s.toLowerCase()) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    default:
      return 1;
  }
}

export function formatLabel(raw: string): string {
  const clean = raw.replace(/[_-]+/g, ' ').trim();
  if (!clean) return '—';
  return clean.charAt(0).toUpperCase() + clean.slice(1).toLowerCase();
}

export function formatTime(ms: number): string {
  if (!ms) return '—';
  try {
    return new Date(ms).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return String(ms);
  }
}

export function sortFindingsBySeverity(
  findings: readonly CyberFinding[],
  severityFilter = '',
): CyberFinding[] {
  const filtered = severityFilter
    ? findings.filter((f) => f.severity === severityFilter)
    : findings;
  return [...filtered].sort((a, b) => severityOrder(b.severity) - severityOrder(a.severity));
}

export function verifyQuoteAgainstTraffic(
  quote: string | undefined,
  traffic: CyberTrafficRecord | null | undefined,
): boolean {
  const needle = quote?.trim();
  if (!needle || !traffic) return false;
  const haystack = `${traffic.responseHeaders}\n${traffic.responseBody}`;
  return haystack.includes(needle);
}

export function summarizeDoctorStatus(checks: readonly CyberDoctorCheck[]): {
  status: 'ready' | 'degraded';
  passed: number;
  warned: number;
  failed: number;
} {
  let passed = 0;
  let warned = 0;
  let failed = 0;
  for (const c of checks) {
    if (c.status === 'pass') passed++;
    else if (c.status === 'warn') warned++;
    else failed++;
  }
  return {
    status: failed === 0 ? 'ready' : 'degraded',
    passed,
    warned,
    failed,
  };
}
