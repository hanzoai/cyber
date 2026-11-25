/**
 * Standalone API client for Hanzo Cyber (`/v1/cyber/*`).
 *
 * Works against both:
 *   1. Same-origin `cyber serve` (no external host required; optional bearer token)
 *   2. Hanzo Cloud `https://api.hanzo.ai/v1/cyber/*` authenticated with Hanzo IAM (`hanzo.id`)
 */

import type {
  CyberApproval,
  CyberAttackMatrix,
  CyberChatMessage,
  CyberCoaItem,
  CyberDashboard,
  CyberDoctorReport,
  CyberEngagement,
  CyberFinding,
  CyberGraphNode,
  CyberHardening,
  CyberInterceptRule,
  CyberNodeKind,
  CyberRuleAction,
  CyberSeedDemoResponse,
  CyberSeverity,
  CyberTask,
  CyberTaskGraph,
  CyberTrafficRecord,
} from './types.ts';

const STORAGE_TOKEN_KEY = 'hanzo_cyber_token';
const STORAGE_ORG_KEY = 'hanzo_cyber_org';
const STORAGE_API_KEY = 'hanzo_cyber_api_base';

export interface CyberConnectionSettings {
  apiBase: string;
  token: string;
  org: string;
}

export class CyberApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'CyberApiError';
    this.status = status;
  }
}

function safeStorageGet(key: string): string {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return (window.localStorage.getItem(key) ?? '').trim();
    }
  } catch {
    // ignore storage restriction
  }
  return '';
}

function safeStorageSet(key: string, value: string): void {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      if (value.trim()) {
        window.localStorage.setItem(key, value.trim());
      } else {
        window.localStorage.removeItem(key);
      }
    }
  } catch {
    // ignore storage restriction
  }
}

export function resolveApiBase(override?: string): string {
  const fromOverride = override?.trim();
  if (fromOverride) return fromOverride.replace(/\/+$/, '');

  const stored = safeStorageGet(STORAGE_API_KEY);
  if (stored) return stored.replace(/\/+$/, '');

  if (typeof window !== 'undefined') {
    const cfgBase = window.__HANZO_CYBER_CONFIG__?.apiBase?.trim();
    if (cfgBase) return cfgBase.replace(/\/+$/, '');
  }

  return '';
}

export function readConnectionSettings(): CyberConnectionSettings {
  return {
    apiBase: resolveApiBase(),
    token: safeStorageGet(STORAGE_TOKEN_KEY),
    org: safeStorageGet(STORAGE_ORG_KEY),
  };
}

export function writeConnectionSettings(next: Partial<CyberConnectionSettings>): void {
  if (next.apiBase !== undefined) safeStorageSet(STORAGE_API_KEY, next.apiBase);
  if (next.token !== undefined) safeStorageSet(STORAGE_TOKEN_KEY, next.token);
  if (next.org !== undefined) safeStorageSet(STORAGE_ORG_KEY, next.org);
}

export function buildCyberHeaders(opts?: {
  json?: boolean;
  token?: string;
  org?: string;
}): Record<string, string> {
  const json = opts?.json ?? true;
  const token = (opts?.token ?? safeStorageGet(STORAGE_TOKEN_KEY)).trim();
  const orgId = (opts?.org ?? safeStorageGet(STORAGE_ORG_KEY)).trim();
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (orgId) headers['X-Org-Id'] = orgId;
  if (json) headers['Content-Type'] = 'application/json';
  return headers;
}

export function buildQueryString(params: Record<string, string | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v && v.trim()) sp.set(k, v.trim());
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const hasBody = init.body !== undefined;
  const base = resolveApiBase();
  const url = `${base}/v1/cyber${path}`;
  const res = await fetch(url, {
    ...init,
    credentials: base ? 'omit' : 'same-origin',
    headers: {
      ...buildCyberHeaders({ json: hasBody }),
      ...(init.headers as Record<string, string> | undefined),
    },
  });
  const text = await res.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }
  if (!res.ok) {
    const errObj = parsed as { error?: { message?: string } | string; message?: string } | null;
    const msg =
      (typeof errObj?.error === 'object' ? errObj?.error?.message : errObj?.error) ||
      errObj?.message ||
      `Request failed (${res.status})`;
    throw new CyberApiError(res.status, msg);
  }
  return parsed as T;
}

export const cyberApi = {
  dashboard: (engagementId?: string) =>
    request<CyberDashboard>(`/dashboard${buildQueryString({ engagementId })}`),

  listEngagements: () =>
    request<{ data: CyberEngagement[] }>('/engagements').then((r) => r.data ?? []),

  createEngagement: (input: {
    name: string;
    target: string;
    scope?: string[];
    mode?: string;
    synthetic?: boolean;
  }) =>
    request<CyberEngagement>('/engagements', {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  seedDemo: () =>
    request<CyberSeedDemoResponse>('/engagements/seed-demo', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  listTasks: (engagementId?: string) =>
    request<{ data: CyberTask[] }>(`/tasks${buildQueryString({ engagementId })}`).then(
      (r) => r.data ?? [],
    ),

  createTask: (input: { engagementId: string; title: string; goal?: string; phase?: string }) =>
    request<CyberTask>('/tasks', {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  getTaskGraph: (taskId: string) =>
    request<CyberTaskGraph>(`/tasks/${encodeURIComponent(taskId)}/graph`),

  addGraphNode: (
    taskId: string,
    input: {
      kind: CyberNodeKind;
      label: string;
      detail?: string;
      status?: string;
      severity?: string;
      parentId?: string;
    },
  ) =>
    request<CyberGraphNode>(`/tasks/${encodeURIComponent(taskId)}/nodes`, {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  listFindings: (filter?: { engagementId?: string; severity?: string; status?: string }) =>
    request<{ data: CyberFinding[] }>(
      `/findings${buildQueryString({
        engagementId: filter?.engagementId,
        severity: filter?.severity,
        status: filter?.status,
      })}`,
    ).then((r) => r.data ?? []),

  createFinding: (input: {
    engagementId: string;
    taskId?: string;
    title: string;
    severity?: CyberSeverity;
    category?: string;
    cwe?: string;
    mitreTechnique?: string;
    mitreTactic?: string;
    target?: string;
    evidenceQuote?: string;
    trafficId?: string;
    remediation?: string;
  }) =>
    request<CyberFinding>('/findings', {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  verifyFinding: (id: string, input?: { trafficId?: string; evidenceQuote?: string }) =>
    request<CyberFinding>(`/findings/${encodeURIComponent(id)}/verify`, {
      method: 'POST',
      body: JSON.stringify(input ?? {}),
    }),

  listTraffic: (filter?: { engagementId?: string; host?: string }) =>
    request<{ data: CyberTrafficRecord[] }>(
      `/traffic${buildQueryString({ engagementId: filter?.engagementId, host: filter?.host })}`,
    ).then((r) => r.data ?? []),

  recordTraffic: (input: {
    engagementId: string;
    taskId?: string;
    method?: string;
    url: string;
    host?: string;
    statusCode?: number;
    requestHeaders?: string;
    requestBody?: string;
    responseHeaders?: string;
    responseBody?: string;
    latencyMs?: number;
  }) =>
    request<CyberTrafficRecord>('/traffic', {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  listApprovals: (filter?: { engagementId?: string; status?: string }) =>
    request<{ data: CyberApproval[] }>(
      `/approvals${buildQueryString({ engagementId: filter?.engagementId, status: filter?.status })}`,
    ).then((r) => r.data ?? []),

  decideApproval: (id: string, decision: 'approved' | 'denied' | 'always_allow') =>
    request<CyberApproval>(`/approvals/${encodeURIComponent(id)}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision }),
    }),

  listRules: (engagementId?: string) =>
    request<{ data: CyberInterceptRule[] }>(
      `/intercept/rules${buildQueryString({ engagementId })}`,
    ).then((r) => r.data ?? []),

  createRule: (input: {
    engagementId?: string;
    name: string;
    matchHost?: string;
    matchPath?: string;
    action?: CyberRuleAction;
  }) =>
    request<CyberInterceptRule>('/intercept/rules', {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  deleteRule: (id: string) =>
    request<{ deleted: boolean; id: string }>(`/intercept/rules/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  attackMatrix: (engagementId?: string) =>
    request<CyberAttackMatrix>(`/attack${buildQueryString({ engagementId })}`),

  courseOfAction: (engagementId?: string) =>
    request<{ data: CyberCoaItem[] }>(`/coa${buildQueryString({ engagementId })}`).then(
      (r) => r.data ?? [],
    ),

  hardening: (engagementId?: string) =>
    request<CyberHardening>(`/hardening${buildQueryString({ engagementId })}`),

  listChatMessages: async (filter?: {
    engagementId?: string;
    taskId?: string;
  }): Promise<CyberChatMessage[]> => {
    try {
      const res = await request<{ data?: CyberChatMessage[] }>(
        `/chat${buildQueryString({
          engagementId: filter?.engagementId,
          taskId: filter?.taskId,
        })}`,
      );
      return res.data ?? [];
    } catch (err) {
      if (err instanceof CyberApiError && err.status === 404) return [];
      throw err;
    }
  },

  sendChatMessage: (input: {
    engagementId: string;
    taskId?: string;
    message: string;
    model?: string;
  }) =>
    request<{
      operator?: CyberChatMessage;
      assistant?: CyberChatMessage;
      offline?: boolean;
    }>('/chat', {
      method: 'POST',
      body: JSON.stringify({
        engagementId: input.engagementId,
        taskId: input.taskId,
        message: input.message,
        model: input.model,
      }),
    }),

  doctor: async (): Promise<CyberDoctorReport> => {
    const [health, tools] = await Promise.all([
      request<{
        status: string;
        backend: string;
        mode: string;
        routerReady: boolean;
        sandboxReady: boolean;
        probeReady?: boolean;
      }>('/health').catch(() => null),
      request<{ total: number; byGroup: Record<string, number> }>('/tools').catch(() => null),
    ]);

    const tokenConfigured = Boolean(safeStorageGet(STORAGE_TOKEN_KEY));
    const checks: CyberDoctorReport['checks'] = [
      {
        id: 'control-api',
        name: 'Control plane (/v1/cyber/health)',
        status: health?.status === 'ok' ? 'pass' : 'fail',
        detail: health
          ? `${health.backend} (${health.mode} mode) is accepting requests.`
          : 'Control plane health endpoint is unreachable.',
      },
      {
        id: 'enso-router',
        name: 'Enso / Hanzo Router inference',
        status: health?.routerReady ? 'pass' : 'warn',
        detail: health?.routerReady
          ? 'Live Hanzo Router credentials configured for Zen models.'
          : 'Running with deterministic offline fallback until HANZO_API_KEY is configured.',
      },
      {
        id: 'hanzo-sandbox',
        name: 'Hanzo microVM sandbox',
        status: health?.sandboxReady ? 'pass' : 'warn',
        detail: health?.sandboxReady
          ? 'Remote /v1/sandbox microVM isolation configured.'
          : 'Using local scoped execution; configure HANZO_SANDBOX_URL for remote microVM isolation.',
      },
      {
        id: 'iam-session',
        name: 'Hanzo IAM bearer session',
        status: tokenConfigured || health?.mode === 'standalone' ? 'pass' : 'warn',
        detail: tokenConfigured
          ? 'Bearer token configured for authenticated API requests.'
          : 'Using same-origin standalone session; set a Hanzo IAM bearer token for cloud access.',
      },
    ];

    return {
      status: checks.some((c) => c.status === 'fail') ? 'degraded' : 'ready',
      version: '1.0.0-beta.2',
      runtime: health?.backend || 'Go + zap-proto/zip',
      probeAvailable: health?.probeReady ?? false,
      sandboxMode: health?.sandboxReady ? 'Hanzo microVM (/v1/sandbox)' : 'Local scoped runtime',
      mcpToolCount: tools?.total ?? 0,
      iamConfigured: tokenConfigured,
      ensoEndpoint:
        (typeof window !== 'undefined' && window.__HANZO_CYBER_CONFIG__?.ensoHost) ||
        'https://api.hanzo.ai',
      checks,
    };
  },
};
