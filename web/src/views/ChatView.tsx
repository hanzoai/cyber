import { useEffect, useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { MessageSquare, Play, Send, Settings2 } from 'lucide-react';
import { EmptyNotice, Pill, SectionHeader } from '../components/Primitives.tsx';
import {
  formatLabel,
  formatTime,
  type CyberChatMessage,
  type CyberLLMConfig,
  type CyberModelInfo,
  type CyberTask,
  type CyberToolRun,
} from '../types.ts';

const FALLBACK_CLOUD_MODELS = ['enso-auto', 'zen-coder', 'zen-max'] as const;

export function ChatView({
  tasks,
  selectedTaskId,
  messages,
  llmConfig,
  models,
  lastToolRuns,
  busy,
  onSelectTask,
  onSendMessage,
  onOpenSettings,
}: {
  tasks: readonly CyberTask[];
  selectedTaskId: string;
  messages: readonly CyberChatMessage[];
  llmConfig: CyberLLMConfig | null;
  models: readonly CyberModelInfo[];
  lastToolRuns: readonly CyberToolRun[];
  busy: string | null;
  onSelectTask: (taskId: string) => Promise<void>;
  onSendMessage: (input: { message: string; model: string; runRound: boolean }) => Promise<void>;
  onOpenSettings: () => void;
}) {
  const [draft, setDraft] = useState('');
  const [model, setModel] = useState<string>(llmConfig?.model || FALLBACK_CLOUD_MODELS[0]);

  useEffect(() => {
    if (llmConfig?.model) {
      setModel(llmConfig.model);
    }
  }, [llmConfig?.model]);

  const quickModels =
    models.length > 0
      ? models.slice(0, 6).map((m) => m.id)
      : llmConfig?.model
        ? [llmConfig.model, ...FALLBACK_CLOUD_MODELS.filter((m) => m !== llmConfig.model)]
        : [...FALLBACK_CLOUD_MODELS];

  const providerLabel =
    llmConfig?.provider === 'local_private'
      ? `Local private (${llmConfig.baseUrl})`
      : llmConfig?.provider === 'hanzo_cloud'
        ? 'Hanzo Cloud AI (api.hanzo.ai)'
        : 'Offline deterministic';

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
        title="Autonomous cyber chat (Local private LLM & Hanzo Cloud AI)"
        right={
          <XStack items="center" gap="$1.5" flexWrap="wrap">
            {quickModels.map((m) => (
              <Button
                key={m}
                size="sm"
                variant={model === m ? 'default' : 'outline'}
                onClick={() => setModel(m)}
              >
                {m}
              </Button>
            ))}
            <Button size="sm" variant="ghost" onClick={onOpenSettings}>
              <Settings2 size={14} aria-hidden />
              Switch AI
            </Button>
          </XStack>
        }
      />

      <XStack gap="$3" flexWrap="wrap" items="flex-start">
        <YStack
          flex={1.8}
          minW={320}
          p="$3.5"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          gap="$3"
        >
          <XStack justify="space-between" items="center" gap="$2" flexWrap="wrap">
            <Text fontSize="$2" fontFamily="$mono" color="$soft">
              Provider: {providerLabel} · replies and tool calls remain scoped inside the active engagement
            </Text>
            <XStack gap="$1.5" items="center">
              <Pill label={llmConfig?.ready ? 'Live AI' : 'Offline grounded'} strong={Boolean(llmConfig?.ready)} />
              <Pill label={model} strong />
            </XStack>
          </XStack>

          <YStack gap="$2" minH={260}>
            {messages.length === 0 ? (
              <EmptyNotice
                title="No operator messages yet"
                detail="Use Send for grounded Q&A or Send & run round to execute bounded Kai-gated tool calls (cyber-probe, HTTP capture, TLS/DNS audit, verbatim finding verification) with either your local private LLM or Hanzo Cloud AI."
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
                      {m.role === 'operator' ? 'Operator' : m.model ? `AI (${m.model})` : 'Hanzo Cyber'}
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

          {lastToolRuns.length > 0 ? (
            <YStack p="$2.5" rounded="$2" borderWidth={1} borderColor="$edge" bg="$background" gap="$1.5">
              <Text fontSize="$1" fontFamily="$mono" fontWeight="600" color="$ink">
                Latest agentic tool runs ({lastToolRuns.length})
              </Text>
              {lastToolRuns.map((r) => (
                <XStack key={r.id} justify="space-between" items="center" gap="$2" flexWrap="wrap">
                  <Text fontSize="$1" fontFamily="$mono" color="$soft" flex={1}>
                    {r.runtime} · risk {r.riskScore}/100 ({r.riskLevel}) — {r.rationale}
                  </Text>
                  <Pill label={formatLabel(r.status)} strong={r.status !== 'completed'} />
                </XStack>
              ))}
            </YStack>
          ) : null}

          <XStack gap="$2" items="center" flexWrap="wrap">
            <Input
              flex={1}
              minW={220}
              placeholder="Ask AI or run a scoped verification round (e.g. probe ports, audit TLS, verify finding)…"
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

        <YStack
          flex={0.9}
          minW={240}
          p="$3.5"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          gap="$2"
        >
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
