import { useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { ShieldCheck, Trash2 } from 'lucide-react';
import { EmptyNotice, Pill, SectionHeader } from '../components/Primitives.tsx';
import {
  formatLabel,
  formatTime,
  type CyberApproval,
  type CyberInterceptRule,
  type CyberRuleAction,
} from '../types.ts';

export function ApprovalsView({
  approvals,
  rules,
  busy,
  onDecideApproval,
  onCreateRule,
  onDeleteRule,
}: {
  approvals: readonly CyberApproval[];
  rules: readonly CyberInterceptRule[];
  busy: string | null;
  onDecideApproval: (id: string, decision: 'approved' | 'denied' | 'always_allow') => Promise<void>;
  onCreateRule: (input: {
    name: string;
    matchHost: string;
    matchPath: string;
    action: CyberRuleAction;
  }) => Promise<void>;
  onDeleteRule: (id: string) => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [matchHost, setMatchHost] = useState('*.mdtf.test');
  const [matchPath, setMatchPath] = useState('/*');
  const [action, setAction] = useState<CyberRuleAction>('require_approval');

  const handleAddRule = async () => {
    if (!name.trim()) return;
    await onCreateRule({
      name: name.trim(),
      matchHost: matchHost.trim() || '*',
      matchPath: matchPath.trim() || '/*',
      action,
    });
    setName('');
  };

  return (
    <YStack gap="$4">
      <YStack gap="$2">
        <SectionHeader
          icon={<ShieldCheck size={16} aria-hidden />}
          title="Kai risk-gated action approvals"
        />
        {approvals.length === 0 ? (
          <EmptyNotice
            title="No approvals queued"
            detail="High-risk actions intercepted by Kai appear here before any worker executes them."
          />
        ) : (
          approvals.map((a) => (
            <YStack
              key={a.id}
              p="$3.5"
              rounded="$3"
              borderWidth={1}
              borderColor="$edge"
              bg="var(--card)"
              gap="$2"
            >
              <XStack justify="space-between" items="center" flexWrap="wrap" gap="$2">
                <Text fontSize="$3" fontWeight="600" color="$ink">
                  {a.action}
                </Text>
                <XStack gap="$1.5">
                  <Pill
                    label={`Kai risk ${a.riskScore}/100 · ${formatLabel(a.riskLevel)}`}
                    strong={a.riskScore >= 65}
                  />
                  <Pill label={formatLabel(a.status)} strong={a.status === 'pending'} />
                </XStack>
              </XStack>
              <Text fontSize="$2" fontFamily="$mono" color="$soft">
                Target: {a.target} · Tool: {a.tool}
              </Text>
              <Text fontSize="$2" color="$soft">
                {a.kaiRationale}
              </Text>
              {a.status === 'pending' ? (
                <XStack gap="$2" pt="$1" flexWrap="wrap">
                  <Button
                    size="sm"
                    disabled={busy === `decide-${a.id}`}
                    onClick={() => void onDecideApproval(a.id, 'approved')}
                  >
                    Approve once
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy === `decide-${a.id}`}
                    onClick={() => void onDecideApproval(a.id, 'always_allow')}
                  >
                    Always allow target
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
              ) : (
                <Text fontSize="$1" fontFamily="$mono" color="$soft">
                  Decided by {a.decidedBy || 'operator'} at {formatTime(a.decidedAt ?? 0)}
                </Text>
              )}
            </YStack>
          ))
        )}
      </YStack>

      <YStack p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$3">
        <Text fontSize="$3" fontWeight="600" color="$ink">
          Rules of engagement · Scope & intercept guardrails
        </Text>
        <XStack gap="$2" flexWrap="wrap">
          <Input
            flex={1.5}
            minW={180}
            placeholder="Rule name"
            value={name}
            onChangeText={setName}
          />
          <Input
            flex={1}
            minW={140}
            placeholder="Match host"
            value={matchHost}
            onChangeText={setMatchHost}
          />
          <Input
            flex={1}
            minW={120}
            placeholder="Match path"
            value={matchPath}
            onChangeText={setMatchPath}
          />
          <XStack items="center" gap="$1" flexWrap="wrap">
            {(
              [
                ['require_approval', 'Require approval'],
                ['allow', 'Allow'],
                ['block', 'Block'],
                ['tag', 'Tag'],
              ] as const
            ).map(([val, label]) => (
              <Button
                key={val}
                size="sm"
                variant={action === val ? 'default' : 'outline'}
                onClick={() => setAction(val)}
              >
                {label}
              </Button>
            ))}
          </XStack>
          <Button
            size="sm"
            disabled={busy === 'create-rule' || !name.trim()}
            onClick={() => void handleAddRule()}
          >
            Add rule
          </Button>
        </XStack>

        <YStack gap="$2">
          {rules.length === 0 ? (
            <Text fontSize="$2" color="$soft">
              No custom intercept rules configured; default scope enforcement remains active.
            </Text>
          ) : (
            rules.map((r) => (
              <XStack
                key={r.id}
                p="$2.5"
                rounded="$2"
                borderWidth={1}
                borderColor="$edge"
                bg="$background"
                justify="space-between"
                items="center"
                gap="$2"
              >
                <YStack flex={1} minW={0}>
                  <Text fontSize="$2" fontWeight="600" color="$ink">
                    {r.name}
                  </Text>
                  <Text fontSize="$1" fontFamily="$mono" color="$soft">
                    {r.matchHost} {r.matchPath}
                  </Text>
                </YStack>
                <XStack items="center" gap="$2">
                  <Pill
                    label={formatLabel(r.action)}
                    strong={r.action === 'block' || r.action === 'require_approval'}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy === `del-rule-${r.id}`}
                    onClick={() => void onDeleteRule(r.id)}
                  >
                    <Trash2 size={14} aria-hidden />
                  </Button>
                </XStack>
              </XStack>
            ))
          )}
        </YStack>
      </YStack>
    </YStack>
  );
}
