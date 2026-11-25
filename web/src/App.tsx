import { useCallback, useEffect, useMemo, useState } from 'react';
import { useScheme, write as writeAppearance } from '@hanzo/appearance';
import { Input, XStack, YStack } from '@hanzo/gui';
import { Button, Text } from '@hanzo/ui';
import {
  FlaskConical,
  Moon,
  Plus,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sun,
} from 'lucide-react';
import { CyberApiError, cyberApi, readConnectionSettings } from './api.ts';
import { Pill } from './components/Primitives.tsx';
import {
  CYBER_TABS,
  CYBER_TAB_LABELS,
  cyberPath,
  parseCyberTab,
  sortFindingsBySeverity,
  type CyberApproval,
  type CyberAttackMatrix,
  type CyberChatMessage,
  type CyberCoaItem,
  type CyberDashboard,
  type CyberDoctorReport,
  type CyberEngagement,
  type CyberFinding,
  type CyberGraphNode,
  type CyberHardening,
  type CyberInterceptRule,
  type CyberNodeKind,
  type CyberRuleAction,
  type CyberSeverity,
  type CyberTab,
  type CyberTask,
  type CyberTaskGraph,
  type CyberTrafficRecord,
} from './types.ts';
import { ApprovalsView } from './views/ApprovalsView.tsx';
import { AttackView, CoaView } from './views/AttackCoaView.tsx';
import { ChatView } from './views/ChatView.tsx';
import { FindingsView } from './views/FindingsView.tsx';
import { GraphView } from './views/GraphView.tsx';
import { HardeningView, SystemView } from './views/HardeningSystemView.tsx';
import { OverviewView } from './views/OverviewView.tsx';
import { TrafficView } from './views/TrafficView.tsx';

function readTabFromLocation(): CyberTab {
  if (typeof window === 'undefined') return 'overview';
  return parseCyberTab(window.location.pathname, window.location.search);
}

export function App() {
  const scheme = useScheme() === 'light' ? 'light' : 'dark';
  const [activeTab, setActiveTab] = useState<CyberTab>(readTabFromLocation);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [authNeeded, setAuthNeeded] = useState(false);

  const [dashboard, setDashboard] = useState<CyberDashboard | null>(null);
  const [engagements, setEngagements] = useState<CyberEngagement[]>([]);
  const [selectedEngId, setSelectedEngId] = useState('');
  const [tasks, setTasks] = useState<CyberTask[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [graph, setGraph] = useState<CyberTaskGraph | null>(null);
  const [selectedNode, setSelectedNode] = useState<CyberGraphNode | null>(null);

  const [findings, setFindings] = useState<CyberFinding[]>([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState('');

  const [traffic, setTraffic] = useState<CyberTrafficRecord[]>([]);
  const [selectedTrafficId, setSelectedTrafficId] = useState('');

  const [approvals, setApprovals] = useState<CyberApproval[]>([]);
  const [rules, setRules] = useState<CyberInterceptRule[]>([]);
  const [chatMessages, setChatMessages] = useState<CyberChatMessage[]>([]);
  const [attack, setAttack] = useState<CyberAttackMatrix | null>(null);
  const [coa, setCoa] = useState<CyberCoaItem[]>([]);
  const [hardening, setHardening] = useState<CyberHardening | null>(null);
  const [doctor, setDoctor] = useState<CyberDoctorReport | null>(null);

  // New engagement form
  const [showNewEng, setShowNewEng] = useState(false);
  const [newEngName, setNewEngName] = useState('');
  const [newEngTarget, setNewEngTarget] = useState('');
  const [newEngScope, setNewEngScope] = useState('');

  const goTab = useCallback((tab: CyberTab) => {
    setActiveTab(tab);
    if (typeof window !== 'undefined') {
      const next = cyberPath(tab);
      if (window.location.pathname !== next) {
        window.history.pushState(null, '', next);
      }
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onPop = () => setActiveTab(readTabFromLocation());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const refreshDoctor = useCallback(async () => {
    try {
      const rep = await cyberApi.doctor();
      setDoctor(rep);
    } catch {
      // keep previous doctor snapshot if backend is offline
    }
  }, []);

  const refresh = useCallback(
    async (engOverride?: string) => {
      setLoading(true);
      setError(null);
      setAuthNeeded(false);
      try {
        const [engList, docReport] = await Promise.all([
          cyberApi.listEngagements(),
          cyberApi.doctor(),
        ]);
        setEngagements(engList);
        setDoctor(docReport);

        const activeEng =
          engOverride !== undefined
            ? engOverride
            : selectedEngId && engList.some((e) => e.id === selectedEngId)
              ? selectedEngId
              : engList[0]?.id ?? '';
        if (activeEng !== selectedEngId) {
          setSelectedEngId(activeEng);
        }

        const [dash, tsks, fnds, trfs, aprs, rls, atk, coaList, hard] = await Promise.all([
          cyberApi.dashboard(activeEng || undefined),
          cyberApi.listTasks(activeEng || undefined),
          cyberApi.listFindings({ engagementId: activeEng || undefined }),
          cyberApi.listTraffic({ engagementId: activeEng || undefined }),
          cyberApi.listApprovals({ engagementId: activeEng || undefined }),
          cyberApi.listRules(activeEng || undefined),
          cyberApi.attackMatrix(activeEng || undefined),
          cyberApi.courseOfAction(activeEng || undefined),
          cyberApi.hardening(activeEng || undefined),
        ]);

        setDashboard(dash);
        setTasks(tsks);
        setFindings(fnds);
        setTraffic(trfs);
        setApprovals(aprs);
        setRules(rls);
        setAttack(atk);
        setCoa(coaList);
        setHardening(hard);

        const tId =
          selectedTaskId && tsks.some((t) => t.id === selectedTaskId)
            ? selectedTaskId
            : tsks[0]?.id ?? '';
        setSelectedTaskId(tId);
        if (tId) {
          const [g, msgs] = await Promise.all([
            cyberApi.getTaskGraph(tId),
            cyberApi.listChatMessages({ engagementId: activeEng || undefined, taskId: tId }),
          ]);
          setGraph(g);
          setSelectedNode((prev) =>
            prev && g.nodes.some((n) => n.id === prev.id) ? prev : g.nodes[0] ?? null,
          );
          setChatMessages(msgs);
        } else {
          setGraph(null);
          setSelectedNode(null);
          const msgs = activeEng
            ? await cyberApi.listChatMessages({ engagementId: activeEng })
            : [];
          setChatMessages(msgs);
        }

        if (fnds.length > 0 && !fnds.some((f) => f.id === selectedFindingId)) {
          setSelectedFindingId(fnds[0]!.id);
        }
        if (trfs.length > 0 && !trfs.some((tr) => tr.id === selectedTrafficId)) {
          setSelectedTrafficId(trfs[0]!.id);
        }
      } catch (err) {
        if (err instanceof CyberApiError && (err.status === 401 || err.status === 403)) {
          setAuthNeeded(true);
          setError(err.message);
        } else {
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        setLoading(false);
      }
    },
    [selectedEngId, selectedTaskId, selectedFindingId, selectedTrafficId],
  );

  useEffect(() => {
    void refresh();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const switchEngagement = async (engId: string) => {
    setSelectedEngId(engId);
    await refresh(engId);
  };

  const selectTask = async (taskId: string) => {
    setSelectedTaskId(taskId);
    try {
      const [g, msgs] = await Promise.all([
        cyberApi.getTaskGraph(taskId),
        cyberApi.listChatMessages({ engagementId: selectedEngId || undefined, taskId }),
      ]);
      setGraph(g);
      setSelectedNode(g.nodes[0] ?? null);
      setChatMessages(msgs);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleSeedDemo = async () => {
    setBusy('seed');
    setError(null);
    try {
      const res = await cyberApi.seedDemo();
      await refresh(res.engagement.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleCreateEngagement = async () => {
    if (!newEngName.trim() || !newEngTarget.trim()) return;
    setBusy('create-eng');
    setError(null);
    try {
      const scope = newEngScope
        .split(/[,\n]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const created = await cyberApi.createEngagement({
        name: newEngName.trim(),
        target: newEngTarget.trim(),
        scope: scope.length > 0 ? scope : [newEngTarget.trim()],
      });
      setNewEngName('');
      setNewEngTarget('');
      setNewEngScope('');
      setShowNewEng(false);
      await refresh(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleAddNode = async (input: { kind: CyberNodeKind; label: string; detail: string }) => {
    if (!selectedTaskId) return;
    setBusy('add-node');
    setError(null);
    try {
      await cyberApi.addGraphNode(selectedTaskId, {
        kind: input.kind,
        label: input.label,
        detail: input.detail,
        parentId: selectedNode?.id,
      });
      await selectTask(selectedTaskId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleCreateFinding = async (input: {
    title: string;
    severity: CyberSeverity;
    target: string;
    evidenceQuote: string;
  }) => {
    if (!selectedEngId) return;
    setBusy('create-finding');
    setError(null);
    try {
      const created = await cyberApi.createFinding({
        engagementId: selectedEngId,
        taskId: selectedTaskId || undefined,
        title: input.title,
        severity: input.severity,
        target: input.target || engagements.find((e) => e.id === selectedEngId)?.target || '',
        evidenceQuote: input.evidenceQuote || undefined,
        trafficId: traffic[0]?.id,
      });
      setSelectedFindingId(created.id);
      await refresh(selectedEngId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleVerifyFinding = async (finding: CyberFinding) => {
    setBusy(`verify-${finding.id}`);
    setError(null);
    try {
      await cyberApi.verifyFinding(finding.id);
      await refresh(selectedEngId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleDecideApproval = async (
    id: string,
    decision: 'approved' | 'denied' | 'always_allow',
  ) => {
    setBusy(`decide-${id}`);
    setError(null);
    try {
      await cyberApi.decideApproval(id, decision);
      await refresh(selectedEngId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleCreateRule = async (input: {
    name: string;
    matchHost: string;
    matchPath: string;
    action: CyberRuleAction;
  }) => {
    setBusy('create-rule');
    setError(null);
    try {
      await cyberApi.createRule({
        engagementId: selectedEngId || undefined,
        ...input,
      });
      await refresh(selectedEngId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleDeleteRule = async (id: string) => {
    setBusy(`del-rule-${id}`);
    setError(null);
    try {
      await cyberApi.deleteRule(id);
      await refresh(selectedEngId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const handleSendChat = async (input: { message: string; model: string; runRound: boolean }) => {
    if (!selectedEngId) return;
    setBusy('chat');
    setError(null);
    const localId = `local-${Date.now()}`;
    const localMsg: CyberChatMessage = {
      id: localId,
      engagementId: selectedEngId,
      taskId: selectedTaskId || undefined,
      role: 'operator',
      content: input.message,
      createdAt: Date.now(),
    };
    setChatMessages((prev) => [...prev, localMsg]);
    try {
      const res = await cyberApi.sendChatMessage({
        engagementId: selectedEngId,
        taskId: selectedTaskId || undefined,
        message: input.runRound ? `${input.message} (run next verification step)` : input.message,
        model: input.model,
      });
      if (res.operator && res.assistant) {
        setChatMessages((prev) => [
          ...prev.filter((m) => m.id !== localId),
          res.operator!,
          res.assistant!,
        ]);
      } else {
        const refreshed = await cyberApi.listChatMessages({
          engagementId: selectedEngId,
          taskId: selectedTaskId || undefined,
        });
        if (refreshed.length > 0) setChatMessages(refreshed);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const filteredFindings = useMemo(
    () => sortFindingsBySeverity(findings, severityFilter),
    [findings, severityFilter],
  );

  const selectedFinding = useMemo(
    () => filteredFindings.find((f) => f.id === selectedFindingId) ?? filteredFindings[0] ?? null,
    [filteredFindings, selectedFindingId],
  );

  const boundTraffic = useMemo(
    () =>
      selectedFinding?.trafficId
        ? traffic.find((t) => t.id === selectedFinding.trafficId) ?? null
        : null,
    [selectedFinding, traffic],
  );

  const activeEngagement = engagements.find((e) => e.id === selectedEngId) ?? null;
  const conn = readConnectionSettings();

  return (
    <YStack data-slot="cyber-console" flex={1} minH={0} height="100%" bg="$background">
      {/* Header bar */}
      <XStack
        data-slot="cyber-header"
        items="center"
        justify="space-between"
        px="$4"
        py="$3"
        borderBottomWidth={1}
        borderColor="$edge"
        gap="$3"
        flexWrap="wrap"
      >
        <XStack items="center" gap="$2.5" flexWrap="wrap">
          <Shield size={18} aria-hidden />
          <Text fontSize="$4" fontWeight="600" color="$ink">
            Hanzo Cyber
          </Text>
          <Pill label={dashboard?.org || conn.org || 'Local enclave'} strong />
          {activeEngagement ? (
            <Pill
              label={
                activeEngagement.synthetic
                  ? `${activeEngagement.name} · Synthetic`
                  : activeEngagement.name
              }
            />
          ) : null}
        </XStack>

        <XStack items="center" gap="$2" flexWrap="wrap">
          {engagements.length > 1 ? (
            <XStack items="center" gap="$1" flexWrap="wrap">
              {engagements.map((eng) => (
                <Button
                  key={eng.id}
                  size="sm"
                  variant={eng.id === selectedEngId ? 'default' : 'outline'}
                  onClick={() => void switchEngagement(eng.id)}
                >
                  {eng.name}
                </Button>
              ))}
            </XStack>
          ) : null}
          <Button size="sm" variant="outline" onClick={() => setShowNewEng((v) => !v)}>
            <Plus size={14} aria-hidden />
            New engagement
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy === 'seed'}
            onClick={() => void handleSeedDemo()}
          >
            <FlaskConical size={14} aria-hidden />
            {busy === 'seed' ? 'Seeding…' : 'Seed MDTF lab'}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => writeAppearance({ theme: scheme === 'dark' ? 'light' : 'dark' })}
          >
            {scheme === 'dark' ? <Sun size={14} aria-hidden /> : <Moon size={14} aria-hidden />}
          </Button>
          <Button size="sm" variant="ghost" disabled={loading} onClick={() => void refresh()}>
            <RefreshCw size={14} aria-hidden />
          </Button>
        </XStack>
      </XStack>

      {/* Navigation strip */}
      <XStack
        data-slot="cyber-tabs"
        px="$4"
        py="$2"
        gap="$1.5"
        borderBottomWidth={1}
        borderColor="$edge"
        overflowX="auto"
        shrink={0}
      >
        {CYBER_TABS.map((tab) => {
          const active = tab === activeTab;
          const badge =
            tab === 'findings' && dashboard?.findingsTotal
              ? ` (${dashboard.findingsTotal})`
              : tab === 'approvals' && dashboard?.pendingApprovals
                ? ` (${dashboard.pendingApprovals})`
                : '';
          return (
            <XStack
              key={tab}
              render="button"
              data-slot={`cyber-tab-${tab}`}
              aria-current={active ? 'page' : undefined}
              onClick={() => goTab(tab)}
              px="$2.5"
              py="$1.5"
              rounded="$2"
              bg={active ? '$raised' : 'transparent'}
              hoverStyle={{ bg: active ? '$raised' : '$hover' }}
              cursor="pointer"
              shrink={0}
            >
              <Text
                fontSize="$2"
                fontWeight={active ? '600' : '500'}
                color={active ? '$ink' : '$soft'}
              >
                {CYBER_TAB_LABELS[tab]}
                {badge}
              </Text>
            </XStack>
          );
        })}
      </XStack>

      {/* Main content area */}
      <YStack flex={1} minH={0} overflowY="auto" p="$4" gap="$4">
        {error ? (
          <XStack
            p="$3"
            rounded="$3"
            borderWidth={1}
            borderColor="$edge"
            bg="$raised"
            justify="space-between"
            items="center"
            gap="$2"
            flexWrap="wrap"
          >
            <Text fontSize="$2" color="$ink" fontFamily="$mono" flex={1}>
              {error}
            </Text>
            <XStack gap="$2">
              {authNeeded ? (
                <Button size="sm" onClick={() => goTab('system')}>
                  Configure Hanzo IAM
                </Button>
              ) : null}
              <Button size="sm" variant="ghost" onClick={() => setError(null)}>
                Dismiss
              </Button>
            </XStack>
          </XStack>
        ) : null}

        {showNewEng ? (
          <YStack p="$3.5" rounded="$3" borderWidth={1} borderColor="$edge" bg="var(--card)" gap="$2.5">
            <Text fontSize="$3" fontWeight="600" color="$ink">
              Create authorized engagement
            </Text>
            <XStack gap="$2" flexWrap="wrap">
              <Input
                flex={1}
                minW={200}
                placeholder="Engagement name (e.g. Tactical C2 enclave)"
                value={newEngName}
                onChangeText={setNewEngName}
              />
              <Input
                flex={1}
                minW={200}
                placeholder="Primary target host (e.g. enclave.example.test)"
                value={newEngTarget}
                onChangeText={setNewEngTarget}
              />
              <Input
                flex={1}
                minW={220}
                placeholder="Authorized scope hosts (comma-separated)"
                value={newEngScope}
                onChangeText={setNewEngScope}
              />
            </XStack>
            <XStack gap="$2">
              <Button
                size="sm"
                disabled={busy === 'create-eng' || !newEngName.trim() || !newEngTarget.trim()}
                onClick={() => void handleCreateEngagement()}
              >
                Create engagement
              </Button>
              <Button size="sm" variant="outline" onClick={() => setShowNewEng(false)}>
                Cancel
              </Button>
            </XStack>
          </YStack>
        ) : null}

        {activeTab === 'system' ? (
          <SystemView
            doctor={doctor}
            loading={loading}
            onRefreshDoctor={refreshDoctor}
            onReconnect={() => refresh()}
          />
        ) : !loading && engagements.length === 0 ? (
          <YStack
            p="$6"
            rounded="$4"
            borderWidth={1}
            borderColor="$edge"
            bg="var(--card)"
            gap="$3"
            items="flex-start"
          >
            <XStack items="center" gap="$2">
              <ShieldCheck size={18} aria-hidden />
              <Text fontSize="$4" fontWeight="600" color="$ink">
                No cyber engagements yet
              </Text>
            </XStack>
            <Text fontSize="$3" color="$soft" maxW={640}>
              Create an authorized engagement with explicit Rules of Engagement scope, load the
              synthetic MDTF Tactical Enclave lab dataset, or configure your Hanzo IAM connection
              in System & doctor.
            </Text>
            <XStack gap="$2" flexWrap="wrap">
              <Button size="sm" disabled={busy === 'seed'} onClick={() => void handleSeedDemo()}>
                <FlaskConical size={14} aria-hidden />
                Load synthetic MDTF lab
              </Button>
              <Button size="sm" variant="outline" onClick={() => setShowNewEng(true)}>
                <Plus size={14} aria-hidden />
                Create engagement
              </Button>
              <Button size="sm" variant="ghost" onClick={() => goTab('system')}>
                Open system & doctor
              </Button>
            </XStack>
          </YStack>
        ) : null}

        {activeTab === 'overview' && engagements.length > 0 ? (
          <OverviewView
            dashboard={dashboard}
            activeEngagement={activeEngagement}
            engagementsCount={engagements.length}
            findings={filteredFindings}
            approvals={approvals}
            traffic={traffic}
            rules={rules}
            busy={busy}
            onSelectFinding={setSelectedFindingId}
            onDecideApproval={handleDecideApproval}
            onGoTab={goTab}
          />
        ) : null}

        {activeTab === 'graph' && engagements.length > 0 ? (
          <GraphView
            tasks={tasks}
            selectedTaskId={selectedTaskId}
            graph={graph}
            selectedNode={selectedNode}
            busy={busy}
            onSelectTask={selectTask}
            onSelectNode={setSelectedNode}
            onAddNode={handleAddNode}
          />
        ) : null}

        {activeTab === 'findings' && engagements.length > 0 ? (
          <FindingsView
            findings={filteredFindings}
            severityFilter={severityFilter}
            selectedFinding={selectedFinding}
            boundTraffic={boundTraffic}
            busy={busy}
            onSeverityFilter={setSeverityFilter}
            onSelectFinding={setSelectedFindingId}
            onCreateFinding={handleCreateFinding}
            onVerifyFinding={handleVerifyFinding}
          />
        ) : null}

        {activeTab === 'approvals' && engagements.length > 0 ? (
          <ApprovalsView
            approvals={approvals}
            rules={rules}
            busy={busy}
            onDecideApproval={handleDecideApproval}
            onCreateRule={handleCreateRule}
            onDeleteRule={handleDeleteRule}
          />
        ) : null}

        {activeTab === 'traffic' && engagements.length > 0 ? (
          <TrafficView
            traffic={traffic}
            selectedTrafficId={selectedTrafficId}
            onSelectTraffic={setSelectedTrafficId}
          />
        ) : null}

        {activeTab === 'chat' && engagements.length > 0 ? (
          <ChatView
            tasks={tasks}
            selectedTaskId={selectedTaskId}
            messages={chatMessages}
            busy={busy}
            onSelectTask={selectTask}
            onSendMessage={handleSendChat}
          />
        ) : null}

        {activeTab === 'attack' && engagements.length > 0 ? (
          <AttackView attack={attack} />
        ) : null}

        {activeTab === 'coa' && engagements.length > 0 ? <CoaView coa={coa} /> : null}

        {activeTab === 'hardening' && engagements.length > 0 ? (
          <HardeningView hardening={hardening} />
        ) : null}
      </YStack>
    </YStack>
  );
}

export default App;
