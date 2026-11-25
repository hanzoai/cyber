import { useEffect, useState } from 'react';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import { Cpu, Lock, RefreshCw, Sparkles } from 'lucide-react';
import { readConnectionSettings, writeConnectionSettings } from '../api.ts';
import { EmptyNotice, MetricCard, Pill, SectionHeader } from '../components/Primitives.tsx';
import {
  formatLabel,
  summarizeDoctorStatus,
  type CyberDoctorReport,
  type CyberHardening,
  type CyberLLMConfig,
  type CyberLLMProvider,
  type CyberModelInfo,
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
  llmConfig,
  models,
  loading,
  busy,
  onRefreshDoctor,
  onReconnect,
  onUpdateLLM,
  onRefreshModels,
}: {
  doctor: CyberDoctorReport | null;
  llmConfig: CyberLLMConfig | null;
  models: readonly CyberModelInfo[];
  loading: boolean;
  busy: string | null;
  onRefreshDoctor: () => Promise<void>;
  onReconnect: () => Promise<void>;
  onUpdateLLM: (input: {
    provider: CyberLLMProvider;
    baseUrl?: string;
    model?: string;
    apiKey?: string;
    clearApiKey?: boolean;
  }) => Promise<void>;
  onRefreshModels: (provider?: string, baseUrl?: string) => Promise<void>;
}) {
  const initial = readConnectionSettings();
  const [apiBase, setApiBase] = useState(initial.apiBase);
  const [org, setOrg] = useState(initial.org);
  const [token, setToken] = useState(initial.token);
  const [savedNotice, setSavedNotice] = useState(false);

  const [provider, setProvider] = useState<CyberLLMProvider>(llmConfig?.provider ?? 'hanzo_cloud');
  const [llmBaseUrl, setLlmBaseUrl] = useState(llmConfig?.baseUrl ?? 'https://api.hanzo.ai/v1');
  const [llmModel, setLlmModel] = useState(llmConfig?.model ?? 'enso-auto');
  const [llmApiKey, setLlmApiKey] = useState('');
  const [llmSaved, setLlmSaved] = useState(false);

  useEffect(() => {
    if (llmConfig) {
      setProvider(llmConfig.provider);
      setLlmBaseUrl(llmConfig.baseUrl);
      setLlmModel(llmConfig.model);
    }
  }, [llmConfig]);

  const summary = summarizeDoctorStatus(doctor?.checks ?? []);

  const handleSaveConnection = async () => {
    writeConnectionSettings({ apiBase, org, token });
    setSavedNotice(true);
    await onReconnect();
  };

  const selectProviderPreset = (next: CyberLLMProvider, url?: string, model?: string) => {
    setProvider(next);
    setLlmSaved(false);
    if (url) {
      setLlmBaseUrl(url);
    } else if (next === 'hanzo_cloud') {
      setLlmBaseUrl('https://api.hanzo.ai/v1');
      if (!model) setLlmModel('enso-auto');
    } else if (next === 'local_private') {
      const detected = llmConfig?.localEndpoints?.find((e) => e.reachable);
      setLlmBaseUrl(detected?.baseUrl || 'http://127.0.0.1:11434/v1');
      if (detected?.models?.[0]) setLlmModel(detected.models[0]);
    }
    if (model) setLlmModel(model);
  };

  const handleSaveLLM = async () => {
    await onUpdateLLM({
      provider,
      baseUrl: llmBaseUrl.trim(),
      model: llmModel.trim(),
      apiKey: llmApiKey.trim() || undefined,
      clearApiKey: provider === 'local_private' && !llmApiKey.trim(),
    });
    setLlmApiKey('');
    setLlmSaved(true);
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
          value={doctor?.version ?? '1.0.0-beta.4'}
          sub={doctor?.runtime ?? 'Go + zap-proto/zip'}
        />
        <MetricCard
          label="Rust cyber-probe"
          value={doctor?.probeAvailable ? 'Available' : 'Missing'}
          sub={doctor?.sandboxMode ?? 'Local scoped runtime'}
        />
        <MetricCard
          label="AI provider"
          value={
            llmConfig?.provider === 'local_private'
              ? 'Local private'
              : llmConfig?.provider === 'hanzo_cloud'
                ? 'Hanzo Cloud'
                : 'Offline'
          }
          sub={llmConfig?.model || 'enso-auto'}
        />
      </XStack>

      {/* AI Model & Provider Configuration (Local Private LLM vs Hanzo Cloud AI) */}
      <YStack p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$3">
        <XStack justify="space-between" items="center" flexWrap="wrap" gap="$2">
          <XStack items="center" gap="$2">
            <Sparkles size={15} aria-hidden />
            <Text fontSize="$3" fontWeight="600" color="$ink">
              AI model & provider (Local private LLM or Hanzo Cloud AI)
            </Text>
          </XStack>
          <Pill label={llmConfig?.ready ? 'Live AI ready' : 'Offline fallback'} strong={Boolean(llmConfig?.ready)} />
        </XStack>

        <Text fontSize="$2" color="$soft">
          Choose a local private OpenAI-compatible server (Ollama, MLX, llama.cpp, LM Studio, or LAN hanzo-engine — zero API key, zero internet egress) or route through Hanzo Cloud AI (https://api.hanzo.ai/v1) for Enso & Zen models.
        </Text>

        <XStack gap="$2" flexWrap="wrap">
          <Button
            size="sm"
            variant={provider === 'local_private' ? 'default' : 'outline'}
            onClick={() => selectProviderPreset('local_private')}
          >
            Local private LLM (zero egress)
          </Button>
          <Button
            size="sm"
            variant={provider === 'hanzo_cloud' ? 'default' : 'outline'}
            onClick={() => selectProviderPreset('hanzo_cloud')}
          >
            Hanzo Cloud AI (api.hanzo.ai)
          </Button>
          <Button
            size="sm"
            variant={provider === 'offline_deterministic' ? 'default' : 'outline'}
            onClick={() => selectProviderPreset('offline_deterministic')}
          >
            Offline deterministic
          </Button>
        </XStack>

        {llmConfig?.localEndpoints && llmConfig.localEndpoints.some((e) => e.reachable) ? (
          <XStack gap="$1.5" items="center" flexWrap="wrap">
            <Text fontSize="$1" fontFamily="$mono" color="$soft">
              Detected local endpoints:
            </Text>
            {llmConfig.localEndpoints
              .filter((e) => e.reachable)
              .map((ep) => (
                <Button
                  key={ep.baseUrl}
                  size="sm"
                  variant="outline"
                  onClick={() => selectProviderPreset('local_private', ep.baseUrl, ep.models?.[0])}
                >
                  {ep.name} ({ep.baseUrl})
                </Button>
              ))}
          </XStack>
        ) : null}

        <XStack gap="$2" flexWrap="wrap">
          <Input
            flex={1.5}
            minW={220}
            placeholder="OpenAI-compatible base URL (e.g. http://127.0.0.1:11434/v1 or https://api.hanzo.ai/v1)"
            value={llmBaseUrl}
            onChangeText={(v) => {
              setLlmBaseUrl(v);
              setLlmSaved(false);
            }}
          />
          <Input
            flex={1}
            minW={180}
            placeholder="Model ID (e.g. enso-auto, zen-coder, qwen3:32b)"
            value={llmModel}
            onChangeText={(v) => {
              setLlmModel(v);
              setLlmSaved(false);
            }}
          />
          <Input
            flex={1.2}
            minW={200}
            secureTextEntry
            placeholder={
              provider === 'local_private'
                ? 'API key (optional for local private LLM)'
                : llmConfig?.apiKeyConfigured
                  ? 'Hanzo API key (configured — enter to rotate)'
                  : 'Hanzo API key (HANZO_API_KEY)'
            }
            value={llmApiKey}
            onChangeText={(v) => {
              setLlmApiKey(v);
              setLlmSaved(false);
            }}
          />
        </XStack>

        <XStack gap="$2" items="center" flexWrap="wrap">
          <Button size="sm" disabled={busy === 'llm'} onClick={() => void handleSaveLLM()}>
            {busy === 'llm' ? 'Applying…' : 'Apply AI provider'}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy === 'models'}
            onClick={() => void onRefreshModels(provider, llmBaseUrl)}
          >
            Discover models
          </Button>
          {llmSaved ? (
            <Text fontSize="$1" fontFamily="$mono" color="$soft">
              AI provider applied (API key kept in memory only, never persisted to disk).
            </Text>
          ) : null}
        </XStack>

        {models.length > 0 ? (
          <XStack gap="$1.5" flexWrap="wrap" items="center">
            <Text fontSize="$1" fontFamily="$mono" color="$soft">
              Live models ({models.length}):
            </Text>
            {models.slice(0, 12).map((m) => (
              <Button
                key={m.id}
                size="sm"
                variant={llmModel === m.id ? 'default' : 'outline'}
                onClick={() => setLlmModel(m.id)}
              >
                {m.id}
              </Button>
            ))}
          </XStack>
        ) : null}
      </YStack>

      <YStack p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$2.5">
        <Text fontSize="$3" fontWeight="600" color="$ink">
          Hanzo IAM & Control Plane API connection
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
