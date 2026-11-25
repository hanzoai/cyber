import { useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { CheckCircle2, Plus } from 'lucide-react';
import { EmptyNotice, Pill } from '../components/Primitives.tsx';
import {
  formatLabel,
  verifyQuoteAgainstTraffic,
  type CyberFinding,
  type CyberSeverity,
  type CyberTrafficRecord,
} from '../types.ts';

export function FindingsView({
  findings,
  severityFilter,
  selectedFinding,
  boundTraffic,
  busy,
  onSeverityFilter,
  onSelectFinding,
  onCreateFinding,
  onVerifyFinding,
}: {
  findings: readonly CyberFinding[];
  severityFilter: string;
  selectedFinding: CyberFinding | null;
  boundTraffic: CyberTrafficRecord | null;
  busy: string | null;
  onSeverityFilter: (sev: string) => void;
  onSelectFinding: (id: string) => void;
  onCreateFinding: (input: {
    title: string;
    severity: CyberSeverity;
    target: string;
    evidenceQuote: string;
  }) => Promise<void>;
  onVerifyFinding: (finding: CyberFinding) => Promise<void>;
}) {
  const [showForm, setShowForm] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<CyberSeverity>('high');
  const [target, setTarget] = useState('');
  const [quote, setQuote] = useState('');

  const localQuoteMatch = selectedFinding
    ? verifyQuoteAgainstTraffic(selectedFinding.evidenceQuote, boundTraffic)
    : false;

  const handleSave = async () => {
    if (!title.trim()) return;
    await onCreateFinding({
      title: title.trim(),
      severity,
      target: target.trim(),
      evidenceQuote: quote.trim(),
    });
    setTitle('');
    setTarget('');
    setQuote('');
    setShowForm(false);
  };

  return (
    <YStack gap="$3">
      <XStack items="center" justify="space-between" flexWrap="wrap" gap="$2">
        <XStack gap="$1.5" flexWrap="wrap">
          {['', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <Button
              key={sev || 'all'}
              size="sm"
              variant={severityFilter === sev ? 'default' : 'outline'}
              onClick={() => onSeverityFilter(sev)}
            >
              {sev ? formatLabel(sev) : 'All'}
            </Button>
          ))}
        </XStack>
        <Button size="sm" variant="outline" onClick={() => setShowForm((v) => !v)}>
          <Plus size={14} aria-hidden />
          Record finding
        </Button>
      </XStack>

      {showForm ? (
        <YStack p="$3" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$2">
          <XStack gap="$2" flexWrap="wrap">
            <Input
              flex={2}
              minW={220}
              placeholder="Finding title"
              value={title}
              onChangeText={setTitle}
            />
            <XStack items="center" gap="$1">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                <Button
                  key={sev}
                  size="sm"
                  variant={severity === sev ? 'default' : 'outline'}
                  onClick={() => setSeverity(sev)}
                >
                  {formatLabel(sev)}
                </Button>
              ))}
            </XStack>
          </XStack>
          <XStack gap="$2" flexWrap="wrap">
            <Input
              flex={1}
              minW={200}
              placeholder="Affected endpoint URL"
              value={target}
              onChangeText={setTarget}
            />
            <Input
              flex={1}
              minW={220}
              placeholder="Exact verbatim quote from HTTP response"
              value={quote}
              onChangeText={setQuote}
            />
          </XStack>
          <XStack gap="$2">
            <Button
              size="sm"
              disabled={busy === 'create-finding' || !title.trim()}
              onClick={() => void handleSave()}
            >
              Save finding
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowForm(false)}>
              Cancel
            </Button>
          </XStack>
        </YStack>
      ) : null}

      {findings.length === 0 ? (
        <EmptyNotice
          title="No findings match this filter"
          detail="Record a finding bound to captured HTTP traffic or clear the severity filter."
        />
      ) : (
        <XStack gap="$3" flexWrap="wrap" items="flex-start">
          <YStack flex={1} minW={300} gap="$2">
            {findings.map((f) => {
              const active = selectedFinding?.id === f.id;
              return (
                <YStack
                  key={f.id}
                  render="button"
                  onClick={() => onSelectFinding(f.id)}
                  p="$3"
                  rounded="$3"
                  borderWidth={1}
                  borderColor={active ? '$ink' : '$edge'}
                  bg={active ? '$raised' : 'var(--card)'}
                  hoverStyle={{ bg: '$hover' }}
                  gap="$1.5"
                  cursor="pointer"
                >
                  <XStack justify="space-between" items="center" width="100%" gap="$2">
                    <Text fontSize="$3" fontWeight="600" color="$ink" numberOfLines={1} flex={1}>
                      {f.title}
                    </Text>
                    <Pill label={formatLabel(f.severity)} strong={f.severity === 'critical'} />
                  </XStack>
                  <XStack items="center" gap="$2" flexWrap="wrap">
                    <Pill label={f.verified ? 'Verbatim verified' : 'Unverified'} strong={f.verified} />
                    {f.cwe ? <Pill label={f.cwe} /> : null}
                    {f.mitreTechnique ? <Pill label={f.mitreTechnique} /> : null}
                  </XStack>
                </YStack>
              );
            })}
          </YStack>

          {selectedFinding ? (
            <YStack
              flex={1.3}
              minW={340}
              p="$4"
              rounded="$3"
              borderWidth={1}
              borderColor="$edge"
              bg="var(--card)"
              gap="$3"
            >
              <XStack justify="space-between" items="flex-start" gap="$2">
                <YStack gap="$1" flex={1}>
                  <Text fontSize="$4" fontWeight="600" color="$ink">
                    {selectedFinding.title}
                  </Text>
                  <Text fontSize="$2" fontFamily="$mono" color="$soft">
                    {selectedFinding.target}
                  </Text>
                </YStack>
                <Button
                  size="sm"
                  disabled={busy === `verify-${selectedFinding.id}` || !selectedFinding.trafficId}
                  onClick={() => void onVerifyFinding(selectedFinding)}
                >
                  <CheckCircle2 size={14} aria-hidden />
                  {busy === `verify-${selectedFinding.id}` ? 'Verifying…' : 'Verify proof'}
                </Button>
              </XStack>

              <XStack gap="$2" flexWrap="wrap">
                <Pill label={formatLabel(selectedFinding.severity)} strong />
                <Pill label={formatLabel(selectedFinding.status)} />
                {selectedFinding.cwe ? <Pill label={selectedFinding.cwe} /> : null}
                {selectedFinding.mitreTechnique ? (
                  <Pill
                    label={`${selectedFinding.mitreTechnique}${selectedFinding.mitreTactic ? ` · ${selectedFinding.mitreTactic}` : ''}`}
                  />
                ) : null}
              </XStack>

              <YStack p="$3" rounded="$2" borderWidth={1} borderColor="$edge" bg="$background" gap="$1">
                <XStack justify="space-between" items="center" gap="$2">
                  <Text fontSize="$1" fontFamily="$mono" color="$soft">
                    Verbatim evidence quote
                  </Text>
                  <Pill
                    label={
                      selectedFinding.verified
                        ? 'Confirmed'
                        : localQuoteMatch
                          ? 'Substring matched'
                          : 'Pending verification'
                    }
                    strong={selectedFinding.verified || localQuoteMatch}
                  />
                </XStack>
                <Text fontSize="$2" fontFamily="$mono" color="$ink">
                  {selectedFinding.evidenceQuote || 'No verbatim quote bound yet.'}
                </Text>
                {selectedFinding.verificationNote ? (
                  <Text fontSize="$1" color="$soft">
                    {selectedFinding.verificationNote}
                  </Text>
                ) : null}
              </YStack>

              {boundTraffic ? (
                <YStack p="$3" rounded="$2" borderWidth={1} borderColor="$edge" bg="$background" gap="$1">
                  <Text fontSize="$1" fontFamily="$mono" color="$soft">
                    Bound HTTP exchange · {boundTraffic.method} {boundTraffic.url} ({boundTraffic.statusCode})
                  </Text>
                  <Text fontSize="$1" fontFamily="$mono" color="$ink">
                    {boundTraffic.responseBody}
                  </Text>
                </YStack>
              ) : null}

              <YStack gap="$1">
                <Text fontSize="$1" fontFamily="$mono" color="$soft">
                  Remediation
                </Text>
                <Text fontSize="$2" color="$ink">
                  {selectedFinding.remediation || 'No remediation recorded yet.'}
                </Text>
              </YStack>
            </YStack>
          ) : null}
        </XStack>
      )}
    </YStack>
  );
}
