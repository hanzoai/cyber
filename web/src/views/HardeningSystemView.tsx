import { useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { Cpu, Lock, RefreshCw } from 'lucide-react';
import { readConnectionSettings, writeConnectionSettings } from '../api.ts';
import { EmptyNotice, MetricCard, Pill, SectionHeader } from '../components/Primitives.tsx';
import {
  formatLabel,
  summarizeDoctorStatus,
  type CyberDoctorReport,
  type CyberHardening,
} from '../types.ts';

export function HardeningView({ hardening }: { hardening: CyberHardening | null }) {
  const checks = hardening?.checks ?? [];
  return (
    <YStack gap="$3">
      <SectionHeader
        icon={<Lock size={16} aria-hidden />}
        title="Enclave hardening & governance posture"
        right={<Pill label={`Score ${hardening?.score ?? 0}/100`} strong />}
      />
      {checks.length === 0 ? (
        <EmptyNotice
          title="No hardening checks evaluated"
          detail="Select or seed an engagement to compute enclave governance controls and verification readiness."
        />
      ) : (
        checks.map((chk) => (
          <XStack
            key={chk.id}
            p="$3"
            rounded="$3"
            borderWidth={1}
            borderColor="$edge"
            bg="var(--card)"
            justify="space-between"
            items="center"
            gap="$3"
          >
            <YStack flex={1} gap="$0.5">
              <Text fontSize="$3" fontWeight="600" color="$ink">
                {chk.control}
              </Text>
              <Text fontSize="$2" color="$soft">
                {chk.detail}
              </Text>
            </YStack>
            <Pill label={formatLabel(chk.status)} strong={chk.status !== 'pass'} />
          </XStack>
        ))
      )}
    </YStack>
  );
}

export function SystemView({
  doctor,
  loading,
  onRefreshDoctor,
  onReconnect,
}: {
  doctor: CyberDoctorReport | null;
  loading: boolean;
  onRefreshDoctor: () => Promise<void>;
  onReconnect: () => Promise<void>;
}) {
  const initial = readConnectionSettings();
  const [apiBase, setApiBase] = useState(initial.apiBase);
  const [org, setOrg] = useState(initial.org);
  const [token, setToken] = useState(initial.token);
  const [savedNotice, setSavedNotice] = useState(false);

  const summary = summarizeDoctorStatus(doctor?.checks ?? []);

  const handleSaveConnection = async () => {
    writeConnectionSettings({ apiBase, org, token });
    setSavedNotice(true);
    await onReconnect();
  };

  return (
    <YStack gap="$4">
      <SectionHeader
        icon={<Cpu size={16} aria-hidden />}
        title="System & doctor diagnostics"
        right={
          <Button size="sm" variant="outline" disabled={loading} onClick={() => void onRefreshDoctor()}>
            <RefreshCw size={14} aria-hidden />
            Run doctor
          </Button>
        }
      />

      <XStack gap="$3" flexWrap="wrap">
        <MetricCard
          label="Status"
          value={formatLabel(doctor?.status ?? summary.status)}
          sub={`${summary.passed} pass · ${summary.warned} warn · ${summary.failed} fail`}
        />
        <MetricCard
          label="Runtime"
          value={doctor?.version ?? '1.0.0'}
          sub={doctor?.runtime ?? 'Go + zap-proto/zip'}
        />
        <MetricCard
          label="Rust cyber-probe"
          value={doctor?.probeAvailable ? 'Available' : 'Missing'}
          sub={doctor?.sandboxMode ?? 'Hanzo microVM'}
        />
        <MetricCard
          label="MCP tools"
          value={doctor?.mcpToolCount ?? 19}
          sub={doctor?.ensoEndpoint ?? 'https://api.hanzo.ai'}
        />
      </XStack>

      <YStack p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$2.5">
        <Text fontSize="$3" fontWeight="600" color="$ink">
          Hanzo IAM & API connection
        </Text>
        <Text fontSize="$2" color="$soft">
          Leave API host empty to use same-origin cyber serve, or point to https://api.hanzo.ai with a Hanzo IAM bearer token.
        </Text>
        <XStack gap="$2" flexWrap="wrap">
          <Input
            flex={1.4}
            minW={220}
            placeholder="API base URL (blank for same-origin)"
            value={apiBase}
            onChangeText={(v) => {
              setApiBase(v);
              setSavedNotice(false);
            }}
          />
          <Input
            flex={1}
            minW={160}
            placeholder="Organization ID (X-Org-Id)"
            value={org}
            onChangeText={(v) => {
              setOrg(v);
              setSavedNotice(false);
            }}
          />
          <Input
            flex={1.4}
            minW={220}
            secureTextEntry
            placeholder="Hanzo IAM bearer token"
            value={token}
            onChangeText={(v) => {
              setToken(v);
              setSavedNotice(false);
            }}
          />
        </XStack>
        <XStack gap="$2" items="center">
          <Button size="sm" onClick={() => void handleSaveConnection()}>
            Save & reconnect
          </Button>
          {savedNotice ? (
            <Text fontSize="$1" fontFamily="$mono" color="$soft">
              Connection settings saved locally.
            </Text>
          ) : null}
        </XStack>
      </YStack>

      <YStack gap="$2">
        <Text fontSize="$3" fontWeight="600" color="$ink">
          Doctor checks
        </Text>
        {(doctor?.checks ?? []).map((chk) => (
          <XStack
            key={chk.id}
            p="$3"
            rounded="$3"
            borderWidth={1}
            borderColor="$edge"
            bg="var(--card)"
            justify="space-between"
            items="center"
            gap="$3"
          >
            <YStack flex={1} gap="$0.5">
              <Text fontSize="$2" fontWeight="600" color="$ink">
                {chk.name}
              </Text>
              <Text fontSize="$2" color="$soft">
                {chk.detail}
              </Text>
            </YStack>
            <Pill label={formatLabel(chk.status)} strong={chk.status !== 'pass'} />
          </XStack>
        ))}
      </YStack>
    </YStack>
  );
}
