import { XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { AlertTriangle, ShieldAlert } from 'lucide-react';
import { MetricCard, Pill, SectionHeader } from '../components/Primitives.tsx';
import {
  formatLabel,
  type CyberApproval,
  type CyberDashboard,
  type CyberEngagement,
  type CyberFinding,
  type CyberInterceptRule,
  type CyberTab,
  type CyberTrafficRecord,
} from '../types.ts';

export function OverviewView({
  dashboard,
  activeEngagement,
  engagementsCount,
  findings,
  approvals,
  traffic,
  rules,
  busy,
  onSelectFinding,
  onDecideApproval,
  onGoTab,
}: {
  dashboard: CyberDashboard | null;
  activeEngagement: CyberEngagement | null;
  engagementsCount: number;
  findings: readonly CyberFinding[];
  approvals: readonly CyberApproval[];
  traffic: readonly CyberTrafficRecord[];
  rules: readonly CyberInterceptRule[];
  busy: string | null;
  onSelectFinding: (id: string) => void;
  onDecideApproval: (id: string, decision: 'approved' | 'denied' | 'always_allow') => Promise<void>;
  onGoTab: (tab: CyberTab) => void;
}) {
  return (
    <YStack gap="$4">
      <XStack gap="$3" flexWrap="wrap">
        <MetricCard
          label="Engagements"
          value={dashboard?.engagements ?? engagementsCount}
          sub={activeEngagement ? `${formatLabel(activeEngagement.mode)} · ${activeEngagement.target}` : 'Enclave'}
        />
        <MetricCard
          label="Findings"
          value={dashboard?.findingsTotal ?? findings.length}
          sub={`${dashboard?.critical ?? 0} critical · ${dashboard?.high ?? 0} high · ${dashboard?.medium ?? 0} medium`}
        />
        <MetricCard
          label="Verbatim verified"
          value={`${dashboard?.verificationRate ?? 0}%`}
          sub={`${dashboard?.findingsVerified ?? 0}/${dashboard?.findingsTotal ?? 0} bound to HTTP proof`}
        />
        <MetricCard
          label="Pending Kai gates"
          value={dashboard?.pendingApprovals ?? 0}
          sub={`${dashboard?.rulesCount ?? rules.length} scope rules active`}
        />
        <MetricCard
          label="Captured traffic"
          value={dashboard?.trafficCount ?? traffic.length}
          sub="HTTP proof corpus"
        />
      </XStack>

      {activeEngagement ? (
        <XStack
          p="$3"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          justify="space-between"
          items="center"
          gap="$2"
          flexWrap="wrap"
        >
          <XStack items="center" gap="$2" flexWrap="wrap">
            <Text fontSize="$2" fontWeight="600" color="$ink">
              Authorized scope
            </Text>
            {(activeEngagement.scope.length > 0
              ? activeEngagement.scope
              : [activeEngagement.target]
            ).map((host) => (
              <Pill key={host} label={host} />
            ))}
          </XStack>
          <Pill
            label={activeEngagement.synthetic ? 'Synthetic lab' : formatLabel(activeEngagement.status)}
            strong={activeEngagement.synthetic}
          />
        </XStack>
      ) : null}

      <XStack gap="$4" flexWrap="wrap" items="flex-start">
        <YStack
          flex={1}
          minW={300}
          p="$3.5"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          gap="$2.5"
        >
          <SectionHeader
            icon={<AlertTriangle size={15} aria-hidden />}
            title="Priority findings"
            right={
              <Button size="sm" variant="ghost" onClick={() => onGoTab('findings')}>
                All findings
              </Button>
            }
          />
          {findings.length === 0 ? (
            <Text fontSize="$2" color="$soft">
              No findings recorded for this engagement yet.
            </Text>
          ) : (
            findings.slice(0, 5).map((f) => (
              <XStack
                key={f.id}
                render="button"
                onClick={() => {
                  onSelectFinding(f.id);
                  onGoTab('findings');
                }}
                p="$2.5"
                rounded="$2"
                borderWidth={1}
                borderColor="$edge"
                bg="$background"
                hoverStyle={{ bg: '$hover' }}
                justify="space-between"
                items="center"
                gap="$2"
                cursor="pointer"
              >
                <YStack flex={1} minW={0} gap="$0.5">
                  <Text fontSize="$2" fontWeight="600" color="$ink" numberOfLines={1}>
                    {f.title}
                  </Text>
                  <Text fontSize="$1" fontFamily="$mono" color="$soft" numberOfLines={1}>
                    {f.target} · {f.mitreTechnique || f.cwe || f.category}
                  </Text>
                </YStack>
                <XStack gap="$1.5" items="center" shrink={0}>
                  <Pill label={formatLabel(f.severity)} strong={f.severity === 'critical'} />
                  <Pill label={f.verified ? 'Verified' : 'Unverified'} strong={f.verified} />
                </XStack>
              </XStack>
            ))
          )}
        </YStack>

        <YStack
          flex={1}
          minW={300}
          p="$3.5"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          gap="$2.5"
        >
          <SectionHeader
            icon={<ShieldAlert size={15} aria-hidden />}
            title="Kai risk gate queue"
            right={
              <Button size="sm" variant="ghost" onClick={() => onGoTab('approvals')}>
                Manage gates
              </Button>
            }
          />
          {approvals.length === 0 ? (
            <Text fontSize="$2" color="$soft">
              No Kai approval gates queued.
            </Text>
          ) : (
            approvals.slice(0, 4).map((a) => (
              <YStack
                key={a.id}
                p="$2.5"
                rounded="$2"
                borderWidth={1}
                borderColor="$edge"
                bg="$background"
                gap="$1.5"
              >
                <XStack justify="space-between" items="center" gap="$2">
                  <Text fontSize="$2" fontWeight="600" color="$ink" numberOfLines={1} flex={1}>
                    {a.action}
                  </Text>
                  <Pill label={`Risk ${a.riskScore}/100`} strong={a.riskScore >= 65} />
                </XStack>
                <Text fontSize="$1" fontFamily="$mono" color="$soft" numberOfLines={2}>
                  {a.target} · {a.tool} · {formatLabel(a.status)}
                </Text>
                {a.status === 'pending' ? (
                  <XStack gap="$2" pt="$1">
                    <Button
                      size="sm"
                      disabled={busy === `decide-${a.id}`}
                      onClick={() => void onDecideApproval(a.id, 'approved')}
                    >
                      Approve
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy === `decide-${a.id}`}
                      onClick={() => void onDecideApproval(a.id, 'denied')}
                    >
                      Deny
                    </Button>
                  </XStack>
                ) : null}
              </YStack>
            ))
          )}
        </YStack>
      </XStack>
    </YStack>
  );
}
