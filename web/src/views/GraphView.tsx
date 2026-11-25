import { useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { GitFork } from 'lucide-react';
import { CyberGraph } from '../components/CyberGraph.tsx';
import { Pill, SectionHeader } from '../components/Primitives.tsx';
import {
  formatLabel,
  type CyberGraphNode,
  type CyberNodeKind,
  type CyberTask,
  type CyberTaskGraph,
} from '../types.ts';

export function GraphView({
  tasks,
  selectedTaskId,
  graph,
  selectedNode,
  busy,
  onSelectTask,
  onSelectNode,
  onAddNode,
}: {
  tasks: readonly CyberTask[];
  selectedTaskId: string;
  graph: CyberTaskGraph | null;
  selectedNode: CyberGraphNode | null;
  busy: string | null;
  onSelectTask: (taskId: string) => Promise<void>;
  onSelectNode: (node: CyberGraphNode) => void;
  onAddNode: (input: { kind: CyberNodeKind; label: string; detail: string }) => Promise<void>;
}) {
  const [kind, setKind] = useState<CyberNodeKind>('hint');
  const [label, setLabel] = useState('');
  const [detail, setDetail] = useState('');

  const handleSubmit = async () => {
    if (!label.trim()) return;
    await onAddNode({ kind, label: label.trim(), detail: detail.trim() });
    setLabel('');
    setDetail('');
  };

  return (
    <YStack gap="$3">
      <SectionHeader
        icon={<GitFork size={16} aria-hidden />}
        title="Autonomous reasoning graph (Goal → Intent → Finding → Kai gate)"
        right={
          tasks.length > 0 ? (
            <XStack items="center" gap="$1.5" flexWrap="wrap">
              {tasks.map((t) => (
                <Button
                  key={t.id}
                  size="sm"
                  variant={t.id === selectedTaskId ? 'default' : 'outline'}
                  onClick={() => void onSelectTask(t.id)}
                >
                  {t.title}
                </Button>
              ))}
            </XStack>
          ) : null
        }
      />

      <CyberGraph
        nodes={graph?.nodes ?? []}
        selectedId={selectedNode?.id ?? null}
        onSelect={onSelectNode}
      />

      <XStack gap="$3" flexWrap="wrap" items="flex-start">
        <YStack
          flex={1}
          minW={280}
          p="$3.5"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          gap="$1.5"
        >
          <Text fontSize="$2" fontFamily="$mono" color="$soft">
            Node inspector
          </Text>
          {selectedNode ? (
            <>
              <XStack items="center" gap="$2" flexWrap="wrap">
                <Pill label={formatLabel(selectedNode.kind)} strong />
                <Pill label={formatLabel(selectedNode.status)} />
                {selectedNode.severity ? <Pill label={formatLabel(selectedNode.severity)} strong /> : null}
              </XStack>
              <Text fontSize="$3" fontWeight="600" color="$ink">
                {selectedNode.label}
              </Text>
              <Text fontSize="$2" color="$soft">
                {selectedNode.detail || 'No additional detail recorded.'}
              </Text>
            </>
          ) : (
            <Text fontSize="$2" color="$soft">
              Select any node in the graph to inspect its reasoning trace.
            </Text>
          )}
        </YStack>

        <YStack
          flex={1}
          minW={280}
          p="$3.5"
          rounded="$3"
          borderWidth={1}
          borderColor="$edge"
          bg="var(--card)"
          gap="$2"
        >
          <Text fontSize="$2" fontFamily="$mono" color="$soft">
            Inject operator hint or intent
          </Text>
          <XStack gap="$2">
            {(['intent', 'hint', 'action'] as const).map((k) => (
              <Button
                key={k}
                size="sm"
                variant={kind === k ? 'default' : 'outline'}
                onClick={() => setKind(k)}
              >
                {formatLabel(k)}
              </Button>
            ))}
          </XStack>
          <Input placeholder="Node label" value={label} onChangeText={setLabel} />
          <Input
            placeholder="Operator guidance or hypothesis detail"
            value={detail}
            onChangeText={setDetail}
          />
          <Button
            size="sm"
            disabled={busy === 'add-node' || !selectedTaskId || !label.trim()}
            onClick={() => void handleSubmit()}
          >
            Append to selected node
          </Button>
        </YStack>
      </XStack>
    </YStack>
  );
}
