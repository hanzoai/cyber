import { useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { MessageSquare, Play, Send } from 'lucide-react';
import { EmptyNotice, Pill, SectionHeader } from '../components/Primitives.tsx';
import { formatTime, type CyberChatMessage, type CyberTask } from '../types.ts';

const ZEN_MODELS = [
  'enso-auto',
  'zen-coder-32b',
  'zen-3-pro',
] as const;

export function ChatView({
  tasks,
  selectedTaskId,
  messages,
  busy,
  onSelectTask,
  onSendMessage,
}: {
  tasks: readonly CyberTask[];
  selectedTaskId: string;
  messages: readonly CyberChatMessage[];
  busy: string | null;
  onSelectTask: (taskId: string) => Promise<void>;
  onSendMessage: (input: { message: string; model: string; runRound: boolean }) => Promise<void>;
}) {
  const [draft, setDraft] = useState('');
  const [model, setModel] = useState<string>(ZEN_MODELS[0]);

  const send = async (runRound: boolean) => {
    const text = draft.trim();
    if (!text) return;
    setDraft('');
    await onSendMessage({ message: text, model, runRound });
  };

  return (
    <YStack gap="$3">
      <SectionHeader
        icon={<MessageSquare size={16} aria-hidden />}
        title="Enso & Zen cyber chat"
        right={
          <XStack items="center" gap="$1.5" flexWrap="wrap">
            {ZEN_MODELS.map((m) => (
              <Button
                key={m}
                size="sm"
                variant={model === m ? 'default' : 'outline'}
                onClick={() => setModel(m)}
              >
                {m}
              </Button>
            ))}
          </XStack>
        }
      />

      <XStack gap="$3" flexWrap="wrap" items="flex-start">
        <YStack flex={1.8} minW={320} p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$3">
          <XStack justify="space-between" items="center" gap="$2" flexWrap="wrap">
            <Text fontSize="$2" fontFamily="$mono" color="$soft">
              Routed via Enso · replies remain scoped inside the active engagement
            </Text>
            <Pill label={model} strong />
          </XStack>

          <YStack gap="$2" minH={260}>
            {messages.length === 0 ? (
              <EmptyNotice
                title="No operator messages yet"
                detail="Guidance sent here is routed through Enso to Zen models and recorded as an inspectable graph hint on the active task."
              />
            ) : (
              messages.map((m) => (
                <YStack
                  key={m.id}
                  p="$3"
                  rounded="$3"
                  borderWidth={1}
                  borderColor={m.role === 'operator' ? '$ink' : '$edge'}
                  bg={m.role === 'operator' ? '$raised' : '$background'}
                  gap="$1"
                >
                  <XStack justify="space-between" items="center" gap="$2">
                    <Text fontSize="$1" fontFamily="$mono" fontWeight="600" color="$ink">
                      {m.role === 'operator' ? 'Operator' : m.model ? `Zen (${m.model})` : 'Hanzo Cyber'}
                    </Text>
                    <Text fontSize="$1" fontFamily="$mono" color="$soft">
                      {formatTime(m.createdAt)}
                    </Text>
                  </XStack>
                  <Text fontSize="$2" color="$ink">
                    {m.content}
                  </Text>
                </YStack>
              ))
            )}
          </YStack>

          <XStack gap="$2" items="center" flexWrap="wrap">
            <Input
              flex={1}
              minW={220}
              placeholder="Ask Zen about findings, verification proofs, or next scoped probe…"
              value={draft}
              onChangeText={setDraft}
            />
            <Button
              size="sm"
              disabled={busy === 'chat' || !draft.trim()}
              onClick={() => void send(false)}
            >
              <Send size={14} aria-hidden />
              Send
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy === 'chat' || !draft.trim()}
              onClick={() => void send(true)}
            >
              <Play size={14} aria-hidden />
              Send & run round
            </Button>
          </XStack>
        </YStack>

        <YStack flex={0.9} minW={240} p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$2">
          <Text fontSize="$2" fontWeight="600" color="$ink">
            Task threads
          </Text>
          {tasks.length === 0 ? (
            <Text fontSize="$2" color="$soft">
              No task threads in this engagement yet.
            </Text>
          ) : (
            tasks.map((t) => {
              const active = t.id === selectedTaskId;
              return (
                <YStack
                  key={t.id}
                  render="button"
                  onClick={() => void onSelectTask(t.id)}
                  p="$2.5"
                  rounded="$2"
                  borderWidth={1}
                  borderColor={active ? '$ink' : '$edge'}
                  bg={active ? '$raised' : '$background'}
                  hoverStyle={{ bg: '$hover' }}
                  gap="$0.5"
                  cursor="pointer"
                >
                  <Text fontSize="$2" fontWeight="600" color="$ink" numberOfLines={1}>
                    {t.title}
                  </Text>
                  <Text fontSize="$1" fontFamily="$mono" color="$soft" numberOfLines={1}>
                    {t.phase || t.status}
                  </Text>
                </YStack>
              );
            })
          )}
        </YStack>
      </XStack>
    </YStack>
  );
}
