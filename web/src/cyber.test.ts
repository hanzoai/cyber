import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { buildCyberHeaders, buildQueryString, resolveApiBase } from './api.ts';
import {
  CYBER_TABS,
  cyberPath,
  formatLabel,
  parseCyberTab,
  severityOrder,
  sortFindingsBySeverity,
  summarizeDoctorStatus,
  verifyQuoteAgainstTraffic,
  type CyberFinding,
  type CyberTrafficRecord,
} from './types.ts';

describe('cyber routing and tab parsing', () => {
  test('parses /cyber, bare paths, and every subtab cleanly', () => {
    assert.equal(parseCyberTab('/cyber'), 'overview');
    assert.equal(parseCyberTab('/cyber/'), 'overview');
    assert.equal(parseCyberTab('/'), 'overview');
    for (const tab of CYBER_TABS) {
      assert.equal(parseCyberTab(cyberPath(tab)), tab);
      assert.equal(parseCyberTab(`/${tab}`), tab);
    }
    assert.equal(parseCyberTab('/cyber', '?tab=approvals'), 'approvals');
    assert.equal(parseCyberTab('/cyber', '?tab=system'), 'system');
    assert.equal(parseCyberTab('/cyber/unknown'), 'overview');
  });

  test('orders severities monotonically from critical to info', () => {
    assert.ok(severityOrder('critical') > severityOrder('high'));
    assert.ok(severityOrder('high') > severityOrder('medium'));
    assert.ok(severityOrder('medium') > severityOrder('low'));
    assert.ok(severityOrder('low') > severityOrder('info'));
  });

  test('formats labels into sentence case cleanly', () => {
    assert.equal(formatLabel('require_approval'), 'Require approval');
    assert.equal(formatLabel('always_allow'), 'Always allow');
    assert.equal(formatLabel('CRITICAL'), 'Critical');
    assert.equal(formatLabel(''), '—');
  });
});

describe('verbatim proof verification and finding sorting', () => {
  const sampleTraffic: CyberTrafficRecord = {
    id: 'tr_1',
    engagementId: 'eng_1',
    method: 'GET',
    url: 'https://enclave.mdtf.test/api/debug',
    host: 'enclave.mdtf.test',
    statusCode: 200,
    requestHeaders: 'GET /api/debug HTTP/1.1\nHost: enclave.mdtf.test',
    requestBody: '',
    responseHeaders: 'HTTP/1.1 200 OK\nX-Debug-Mode: enabled',
    responseBody: '{"role":"operator","build":"enclave-42"}',
    latencyMs: 18,
    createdAt: 1700000000000,
  };

  test('verifies exact verbatim quotes against bound HTTP traffic', () => {
    assert.equal(verifyQuoteAgainstTraffic('"build":"enclave-42"', sampleTraffic), true);
    assert.equal(verifyQuoteAgainstTraffic('X-Debug-Mode: enabled', sampleTraffic), true);
    assert.equal(verifyQuoteAgainstTraffic('"build":"fabricated"', sampleTraffic), false);
    assert.equal(verifyQuoteAgainstTraffic('', sampleTraffic), false);
    assert.equal(verifyQuoteAgainstTraffic('"build":"enclave-42"', null), false);
  });

  test('filters and sorts findings by severity descending', () => {
    const items: CyberFinding[] = [
      {
        id: 'f1',
        engagementId: 'e1',
        title: 'Low info leak',
        severity: 'low',
        category: 'info',
        status: 'open',
        target: 'https://a.test',
        verified: false,
        createdAt: 1,
        updatedAt: 1,
      },
      {
        id: 'f2',
        engagementId: 'e1',
        title: 'Critical auth bypass',
        severity: 'critical',
        category: 'auth',
        status: 'verified',
        target: 'https://a.test',
        verified: true,
        createdAt: 2,
        updatedAt: 2,
      },
      {
        id: 'f3',
        engagementId: 'e1',
        title: 'High SSRF',
        severity: 'high',
        category: 'ssrf',
        status: 'open',
        target: 'https://a.test',
        verified: false,
        createdAt: 3,
        updatedAt: 3,
      },
    ];

    const sorted = sortFindingsBySeverity(items);
    assert.deepEqual(
      sorted.map((f) => f.id),
      ['f2', 'f3', 'f1'],
    );
    const onlyHigh = sortFindingsBySeverity(items, 'high');
    assert.deepEqual(
      onlyHigh.map((f) => f.id),
      ['f3'],
    );
  });
});

describe('API client headers, query serialization, and doctor status', () => {
  test('builds Hanzo IAM bearer + org headers and omits empty values', () => {
    const withAuth = buildCyberHeaders({
      json: true,
      token: 'hz_iam_token_123',
      org: 'hanzo',
    });
    assert.equal(withAuth.Authorization, 'Bearer hz_iam_token_123');
    assert.equal(withAuth['X-Org-Id'], 'hanzo');
    assert.equal(withAuth['Content-Type'], 'application/json');
    assert.equal(withAuth.Accept, 'application/json');

    const localOnly = buildCyberHeaders({ json: false, token: '', org: '' });
    assert.equal(localOnly.Authorization, undefined);
    assert.equal(localOnly['X-Org-Id'], undefined);
    assert.equal(localOnly['Content-Type'], undefined);
  });

  test('normalizes API base URL and query string', () => {
    assert.equal(resolveApiBase('https://api.hanzo.ai///'), 'https://api.hanzo.ai');
    assert.equal(resolveApiBase(''), '');
    assert.equal(
      buildQueryString({ engagementId: 'eng_1', severity: '', host: 'a.test' }),
      '?engagementId=eng_1&host=a.test',
    );
    assert.equal(buildQueryString({ engagementId: undefined }), '');
  });

  test('summarizes doctor readiness fail-closed on any failed check', () => {
    assert.deepEqual(
      summarizeDoctorStatus([
        { id: '1', name: 'Go runtime', status: 'pass', detail: 'ok' },
        { id: '2', name: 'IAM token', status: 'warn', detail: 'optional' },
      ]),
      { status: 'ready', passed: 1, warned: 1, failed: 0 },
    );
    assert.deepEqual(
      summarizeDoctorStatus([
        { id: '1', name: 'Go runtime', status: 'pass', detail: 'ok' },
        { id: '2', name: 'Probe binary', status: 'fail', detail: 'missing' },
      ]),
      { status: 'degraded', passed: 1, warned: 0, failed: 1 },
    );
  });
});
