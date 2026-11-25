import type { ReactNode } from 'react';
import { XStack, YStack } from '@hanzo/gui';
import { Text } from '@hanzo/ui';

export function MetricCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <YStack
      flex={1}
      minW={148}
      p="$3"
      rounded="$3"
      borderWidth={1}
      borderColor="$edge"
      bg="var(--card)"
      gap="$1"
    >
      <Text fontSize="$1" fontFamily="$mono" color="$soft">
        {label}
      </Text>
      <Text fontSize="$6" fontWeight="600" color="$ink" fontFamily="$mono">
        {value}
      </Text>
      {sub ? (
        <Text fontSize="$1" color="$soft" numberOfLines={1}>
          {sub}
        </Text>
      ) : null}
    </YStack>
  );
}

export function Pill({ label, strong = false }: { label: string; strong?: boolean }) {
  return (
    <XStack
      px="$2"
      py="$0.5"
      rounded="$2"
      borderWidth={1}
      borderColor={strong ? '$ink' : '$edge'}
      bg={strong ? '$raised' : 'var(--card)'}
      items="center"
      shrink={0}
    >
      <Text
        fontSize="$1"
        fontFamily="$mono"
        fontWeight={strong ? '600' : '500'}
        color={strong ? '$ink' : '$soft'}
      >
        {label}
      </Text>
    </XStack>
  );
}

export function SectionHeader({
  icon,
  title,
  right,
}: {
  icon?: ReactNode;
  title: string;
  right?: ReactNode;
}) {
  return (
    <XStack items="center" justify="space-between" gap="$2" flexWrap="wrap">
      <XStack items="center" gap="$2">
        {icon}
        <Text fontSize="$3" fontWeight="600" color="$ink">
          {title}
        </Text>
      </XStack>
      {right}
    </XStack>
  );
}

export function EmptyNotice({
  title,
  detail,
  action,
}: {
  title: string;
  detail: string;
  action?: ReactNode;
}) {
  return (
    <YStack
      p="$5"
      rounded="$3"
      borderWidth={1}
      borderColor="$edge"
      bg="var(--card)"
      gap="$2"
      items="flex-start"
    >
      <Text fontSize="$3" fontWeight="600" color="$ink">
        {title}
      </Text>
      <Text fontSize="$2" color="$soft" maxW={560}>
        {detail}
      </Text>
      {action}
    </YStack>
  );
}
