import { useMemo, useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Text } from '@hanzo/ui';
import { Activity } from 'lucide-react';
import { EmptyNotice, Pill, SectionHeader } from '../components/Primitives.tsx';
import type { CyberTrafficRecord } from '../types.ts';

export function TrafficView({
  traffic,
  selectedTrafficId,
  onSelectTraffic,
}: {
  traffic: readonly CyberTrafficRecord[];
  selectedTrafficId: string;
  onSelectTraffic: (id: string) => void;
}) {
  const [filter, setFilter] = useState('');

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return traffic;
    return traffic.filter(
      (t) =>
        t.url.toLowerCase().includes(q) ||
        t.host.toLowerCase().includes(q) ||
        t.method.toLowerCase().includes(q) ||
        String(t.statusCode).includes(q),
    );
  }, [traffic, filter]);

  const selected = useMemo(
    () => visible.find((t) => t.id === selectedTrafficId) ?? visible[0] ?? null,
    [visible, selectedTrafficId],
  );

  return (
    <YStack gap="$3">
      <SectionHeader
        icon={<Activity size={15} aria-hidden />}
        title={`Captured HTTP exchanges (${visible.length})`}
        right={
          <Input
            minW={220}
            placeholder="Filter by host, path, method, status"
            value={filter}
            onChangeText={setFilter}
          />
        }
      />

      {visible.length === 0 ? (
        <EmptyNotice
          title="No captured traffic exchanges"
          detail="Scoped HTTP exchanges recorded during assessment appear here for verbatim proof binding."
        />
      ) : (
        <XStack gap="$3" flexWrap="wrap" items="flex-start">
          <YStack flex={1} minW={280} gap="$2">
            {visible.map((tr) => {
              const active = selected?.id === tr.id;
              return (
                <YStack
                  key={tr.id}
                  render="button"
                  onClick={() => onSelectTraffic(tr.id)}
                  p="$2.5"
                  rounded="$3"
                  borderWidth={1}
                  borderColor={active ? '$ink' : '$edge'}
                  bg={active ? '$raised' : 'var(--card)'}
                  hoverStyle={{ bg: '$hover' }}
                  gap="$1"
                  cursor="pointer"
                >
                  <XStack justify="space-between" items="center" width="100%">
                    <Pill label={`${tr.method} · ${tr.statusCode}`} strong />
                    <Text fontSize="$1" fontFamily="$mono" color="$soft">
                      {tr.latencyMs}ms
                    </Text>
                  </XStack>
                  <Text fontSize="$2" fontFamily="$mono" color="$ink" numberOfLines={1}>
                    {tr.url}
                  </Text>
                </YStack>
              );
            })}
          </YStack>

          {selected ? (
            <YStack
              flex={1.5}
              minW={340}
              p="$4"
              rounded="$3"
              borderWidth={1}
              borderColor="$edge"
              bg="var(--card)"
              gap="$3"
            >
              <Text fontSize="$3" fontWeight="600" fontFamily="$mono" color="$ink">
                {selected.method} {selected.url}
              </Text>
              <YStack p="$3" rounded="$2" borderWidth={1} borderColor="$edge" bg="$background" gap="$1">
                <Text fontSize="$1" fontFamily="$mono" color="$soft">
                  Request
                </Text>
                <Text fontSize="$1" fontFamily="$mono" color="$ink">
                  {selected.requestHeaders || '(no request headers)'}
                  {selected.requestBody ? `\n\n${selected.requestBody}` : ''}
                </Text>
              </YStack>
              <YStack p="$3" rounded="$2" borderWidth={1} borderColor="$edge" bg="$background" gap="$1">
                <Text fontSize="$1" fontFamily="$mono" color="$soft">
                  Response ({selected.statusCode})
                </Text>
                <Text fontSize="$1" fontFamily="$mono" color="$ink">
                  {selected.responseHeaders || '(no response headers)'}
                  {selected.responseBody ? `\n\n${selected.responseBody}` : ''}
                </Text>
              </YStack>
            </YStack>
          ) : null}
        </XStack>
      )}
    </YStack>
  );
}
