import { XStack, YStack } from '@hanzo/gui';
import { Text } from '@hanzo/ui';
import { Crosshair, ListChecks } from 'lucide-react';
import { EmptyNotice, Pill, SectionHeader } from '../components/Primitives.tsx';
import { formatLabel, type CyberAttackMatrix, type CyberCoaItem } from '../types.ts';

export function AttackView({ attack }: { attack: CyberAttackMatrix | null }) {
  const techniques = attack?.techniques ?? [];
  return (
    <YStack gap="$3">
      <SectionHeader
        icon={<Crosshair size={16} aria-hidden />}
        title="MITRE ATT&CK technique coverage"
      />
      {techniques.length === 0 ? (
        <EmptyNotice
          title="No ATT&CK techniques mapped yet"
          detail="Findings tagged with MITRE ATT&CK technique IDs populate tactic coverage automatically."
        />
      ) : (
        <XStack gap="$3" flexWrap="wrap">
          {techniques.map((tech) => (
            <YStack
              key={tech.techniqueId}
              minW={240}
              flex={1}
              p="$3.5"
              rounded="$3"
              borderWidth={1}
              borderColor="$edge"
              bg="var(--card)"
              gap="$1.5"
            >
              <XStack justify="space-between" items="center" gap="$2">
                <Pill label={tech.techniqueId} strong />
                <Pill label={formatLabel(tech.maxSeverity)} />
              </XStack>
              <Text fontSize="$3" fontWeight="600" color="$ink">
                {tech.name}
              </Text>
              <Text fontSize="$1" fontFamily="$mono" color="$soft">
                Tactic: {tech.tactic} · {tech.verifiedCount}/{tech.findingCount} verified
              </Text>
            </YStack>
          ))}
        </XStack>
      )}
    </YStack>
  );
}

export function CoaView({ coa }: { coa: readonly CyberCoaItem[] }) {
  return (
    <YStack gap="$3">
      <SectionHeader
        icon={<ListChecks size={16} aria-hidden />}
        title="Prioritized courses of action"
      />
      {coa.length === 0 ? (
        <EmptyNotice
          title="No courses of action generated"
          detail="Once findings are recorded or verified, Hanzo Cyber synthesizes prioritized remediation actions."
        />
      ) : (
        coa.map((item) => (
          <YStack
            key={item.id}
            p="$3.5"
            rounded="$3"
            borderWidth={1}
            borderColor="$edge"
            bg="var(--card)"
            gap="$1.5"
          >
            <XStack justify="space-between" items="center" flexWrap="wrap" gap="$2">
              <Text fontSize="$3" fontWeight="600" color="$ink">
                {item.title}
              </Text>
              <XStack gap="$1.5">
                <Pill label={item.priority} strong={item.priority === 'P0'} />
                <Pill label={`-${item.riskReduction}% risk`} />
                <Pill label={`Effort: ${formatLabel(item.effort)}`} />
              </XStack>
            </XStack>
            <Text fontSize="$2" color="$soft">
              {item.summary}
            </Text>
          </YStack>
        ))
      )}
    </YStack>
  );
}
