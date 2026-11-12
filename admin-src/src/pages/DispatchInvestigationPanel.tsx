import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tabs, Tag, Tooltip, Typography, message } from 'antd';
import { apiGet, apiJsonPost, apiPut, unwrapData, unwrapList } from '../lib/api';
import DispatchMonitorStatus, { type DispatchMonitorStatusEntry } from './DispatchMonitorStatus';
import { UserEmailSelect } from './NodeAddressPage';
import '../styles/investigation.css';

type Settings = { enabled: boolean; lifecycle_enabled: boolean; scope: 'all' | 'multi_range'; revision: number; entry_window_minutes: number; global_window_minutes: number; global_max: number };
type Group = { id: number; root_id: number; parent_id: number; name: string; kind: string; host: string; monitor_id: number; manual_only: boolean; revision: number; reason: string; user_ids: string[]; no_pull_count: number; confirmed_at?: number; route_scope: 'business' | 'global'; lifecycle_role: 'ordinary' | 'stable' | 'whitelist' | 'review'; normal_since: number; normal_observed_at: number; pulled_count: number; policy: 'smart' | 'failover' | 'fixed' };
type GroupEdit = Group & { member_ids: string[] };
const canEditMembers = (g?: Group) => g?.route_scope === 'business' && (g.lifecycle_role === 'stable' || g.lifecycle_role === 'whitelist');
const parseMemberIDs = (value: string[] = []) => [...new Set(value.map(id => id.trim()).filter(Boolean))];
type Event = { id: number; root_id: number; group_id: number; kind: string; first_failure_at: number; created_at: number; payload: { before?: Group; pulled_ids?: number[]; unpulled_ids?: number[]; recent_ids?: number[]; older_ids?: number[]; recent_window_minutes?: number; partitions?: { name?: string; group_id: number; user_ids: number[]; kind: string; host: string; merged_into?: number }[]; evidence?: { controls?: Record<string, string[]>; mode?: string; cutoff_source?: string; warnings?: string[] }; reason?: string; host?: string; user_ids?: number[]; after?: any } };
type Monitor = DispatchMonitorStatusEntry & { id: number; host: string };
const endpoint = '/dns-failover/dispatch-investigation';
const stamp = (v: number) => v ? new Date(v * 1000).toLocaleString() : '—';
const kindName: Record<string, string> = { candidate: '卧底', recent: '120分钟', observation: '观察', confirmed: '实锤内鬼', filtered: '已筛选', bisected: '全部拉取 · 已二分', no_pulls: '无人拉取 · 已换入口', started: '开始观察', settings: '设置变更', edited: '人工编辑', confirmed_entry: '人工确认入口', manual_trigger: '人工立即触发' };
Object.assign(kindName, { recovered: '整组故障转移', stable_promoted: '进入稳定组', whitelist_promoted: '加入老实人', whitelist_failed_over: '老实人故障转移', whitelist_bisected: '老实人二次故障 · 已二分', whitelist_returned: '复核通过', global_released: '退出全站管理', members_admitted: '接收新增用户', members_moved: '人工移出成员' });
const policyNames = { smart: '智能筛选', failover: '仅故障转移', fixed: '固定下发' };
function memberRanges(ids: string[]) {
 const sorted = [...new Set(ids.filter(id => /^[1-9]\d*$/.test(id)))].map(BigInt).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
 const ranges: string[] = [];
 for (let i = 0; i < sorted.length; i++) { const first = sorted[i]; let last = first; while (i + 1 < sorted.length && sorted[i + 1] === last + 1n) last = sorted[++i]; ranges.push(first === last ? String(first) : `${first}-${last}`); }
 return ranges.join(', ');
}
const processStates: Record<string, [string, string]> = {
 '正常观察中': ['观察中', 'active'],
 '等待入口正常后开始观察': ['待入口恢复', 'waiting'],
 '等待入口恢复正常后重新观察': ['待入口恢复', 'waiting'],
 '等待新入口确认正常': ['待入口确认', 'waiting'],
 '新入口尚未确认正常，不按本轮失败筛选': ['待入口确认', 'waiting'],
 '等待连续超时满 10 分钟，或探针结果不一致': ['故障确认中', 'waiting'],
 '等待全部探针新鲜且一致超时': ['待探针确认', 'waiting'],
 '等待全部探针新鲜且一致检测失败': ['待故障确认', 'waiting'],
 '等待当前连续检测失败满 10 分钟，原观察数据保留': ['故障计时中', 'waiting'],
 '故障起点不明，保留本轮观察数据，可人工立即触发': ['可人工触发', 'paused'],
 '故障期间存在未知检测空档，可人工立即触发': ['可人工触发', 'paused'],
 '缺少贯穿当前故障确认窗口的独立正常对照入口': ['待正常对照', 'waiting'],
 '连续超时未满 10 分钟，保留本轮首次故障起点': ['超时计时中', 'waiting'],
 '故障起点不明，保留本轮观察数据，暂停处理': ['起点待核实', 'paused'],
 '故障检测记录不连续或与当前配置不一致': ['检测证据不完整', 'paused'],
 '故障期间存在 DNS、取消或未知检测错误，暂停处理': ['检测错误待核实', 'paused'],
 '缺少贯穿故障期间的独立正常对照入口，等待确认': ['待对照确认', 'waiting'],
 '同一原始组及其后代处于频率限制窗口': ['组内限频', 'paused'],
 '达到全局自动处理频率限制': ['全局限频', 'paused'],
 '不在当前生效范围，保留分组和地址，暂停自动处理': ['范围外暂停', 'paused'],
 '监控未启用、探针离线或数据过期': ['监控未就绪', 'paused'],
 '实际下发关系已变化，暂停自动处理': ['下发已变更', 'paused'],
 '下发规则发生变化，等待重新确认': ['待规则确认', 'waiting'],
 '故障起点早于有效观察期': ['等待新一轮', 'waiting'],
 '探针会话重置中': ['探针重置中', 'waiting'],
 '证据写入曾失败，请恢复正常后重新观察': ['记录异常', 'error'],
 '人工编辑后重新观察': ['重新观察', 'waiting'],
 '人工确认入口，重新观察': ['已人工确认', 'active'],
 '新成员加入，重新观察': ['重新观察', 'waiting'],
 '监控配置或会话变更，重新观察': ['重新观察', 'waiting'],
 '证据恢复后重新开始观察': ['重新观察', 'waiting'],
 '本轮无人拉取，成员不变，已更换入口': ['已换入口', 'waiting'],
 '本轮已完成筛选': ['已筛选', 'paused'],
 '老实人自动处理已关闭': ['已暂停', 'paused'],
 '整组已切换健康备用入口': ['已换入口', 'waiting'],
 '全站复核完成': ['复核通过', 'active'],
 '入口仍向组外用户下发，暂停独立稳定观察': ['待名单隔离', 'paused'],
 '稳定，等待全站白名单复核完成': ['稳定', 'active'],
};
function processState(g: Group, enabled?: boolean) {
 if (g.manual_only || g.user_ids.length <= 1) return { label: '仅人工', tone: 'paused', detail: '仅人工操作，不参与自动筛选或入口分配' };
 if (g.policy === 'fixed') return { label: '固定下发', tone: 'paused', detail: '仅监控，不自动更换入口或分组' };
 if (enabled === undefined) return { label: '—', tone: 'paused', detail: '等待设置加载' };
 if (!enabled) return { label: '已关闭', tone: 'paused', detail: '总开关已关闭，暂停自动处理' };
 if (g.reason.startsWith('正常观察中')) return { label: '观察中', tone: 'active', detail: g.reason };
 if (g.reason.startsWith('老实人，')) return { label: '持续监控', tone: 'active', detail: g.reason };
 if (g.reason.startsWith('稳定组')) return { label: '稳定', tone: 'active', detail: g.reason };
 const [label, tone] = processStates[g.reason] || (/^等待 \d+ 个同检测端口的健康未占用备用 IP$/.test(g.reason) ? ['待补 IP', 'waiting'] : g.reason.startsWith('本轮未修改：') ? ['处理受阻', 'error'] : ['待处理', 'waiting']);
 return { label, tone, detail: g.reason || '等待自动处理' };
}

export default function DispatchInvestigationPanel({ active = true }: { active?: boolean }) {
 const [form] = Form.useForm<Settings>(), [editForm] = Form.useForm<GroupEdit>();
 const editingMemberIDs = Form.useWatch('member_ids', editForm);
 const [settings, setSettings] = useState<Settings>(), [groups, setGroups] = useState<Group[]>([]), [events, setEvents] = useState<Event[]>([]);
 const [monitors, setMonitors] = useState<Monitor[]>([]), [error, setError] = useState(''), [workerError, setWorkerError] = useState('');
 const [saving, setSaving] = useState(false), [editing, setEditing] = useState<Group>(), [page, setPage] = useState(1), [total, setTotal] = useState(0);
 const [action, setAction] = useState<{ group: Group; kind: 'confirm' | 'trigger' }>(), [actionBusy, setActionBusy] = useState(false), [actionError, setActionError] = useState('');
 const [filter, setFilter] = useState('all'), [releasing, setReleasing] = useState<Group>(), [releaseIDs, setReleaseIDs] = useState('');
 const [section, setSection] = useState('ordinary'), [searches, setSearches] = useState<Record<string, string>>({});
 const editingMemberCount = canEditMembers(editing) ? parseMemberIDs(editingMemberIDs ?? editing?.user_ids).length : editing?.user_ids.length || 0;
 useEffect(() => { if (editing && editingMemberCount === 1) editForm.setFieldValue('manual_only', true); }, [editing, editingMemberCount]);
 const stageGroups = (role: string) => groups.filter(g => g.lifecycle_role === role);
 const ordinaryGroups = groups.filter(g => g.lifecycle_role !== 'stable' && g.lifecycle_role !== 'whitelist');
 const visibleGroups = ordinaryGroups.filter(g => filter === 'all' || (filter === 'manual' ? g.manual_only || g.user_ids.length <= 1 : g.user_ids.length > 1 && !g.manual_only));
 const openEditor = (g: Group) => { editForm.resetFields(); setEditing(g); editForm.setFieldsValue({ ...g, member_ids: [...g.user_ids], manual_only: g.manual_only || g.user_ids.length <= 1 }); };
 const generation = useRef(0), initialized = useRef(false), revision = useRef(0);
 const load = async () => {
  const seq = ++generation.current;
  try {
   const [res, monitorRes] = await Promise.all([apiGet(endpoint, { page }), apiGet('/dns-failover/dispatch-entries', { include_deleted: true })]);
   if (seq !== generation.current) return;
   const data = unwrapData(res), nextMonitors = unwrapList(monitorRes) as Monitor[];
   // Reject a stale group if ownership changed between the two responses.
   const currentMonitorKeys = new Set(nextMonitors.filter(m => !m.deleted).map(m => `${m.id}:${m.host}`));
   const isCurrent = (g: Group) => currentMonitorKeys.has(`${g.monitor_id}:${g.host}`);
   setSettings(data.settings); setGroups((data.groups || []).filter(isCurrent)); setEvents(data.events || []); setTotal(data.total || 0); setMonitors(nextMonitors); setError(''); setWorkerError(data.worker_error || '');
   setEditing(current => current && !isCurrent(current) ? undefined : current);
   if (!initialized.current) { form.setFieldsValue(data.settings); revision.current = data.settings.revision; initialized.current = true; }
  } catch (e: any) { if (seq === generation.current) setError(e.message || '读取失败'); }
 };
 useEffect(() => { if (!active) return; void load(); const timer = window.setInterval(() => void load(), 15000); return () => { generation.current++; clearInterval(timer); }; }, [active, page]);
 const save = async () => {
  try { const values = await form.validateFields(); setSaving(true); generation.current++; const data = unwrapData(await apiPut(endpoint, { ...values, revision: revision.current })); revision.current = data.settings.revision; setSettings(data.settings); form.setFieldsValue(data.settings); message.success('设置已保存'); await load(); }
  catch (e: any) { if (!e.errorFields) message.error(e.message || '保存失败'); } finally { setSaving(false); }
 };
 const saveEdit = async () => {
  if (!editing) return;
  try { const values = await editForm.validateFields(); setSaving(true); generation.current++; await apiPut(endpoint + '/groups', { id: editing.id, revision: editing.revision, name: values.name, host: values.host, manual_only: editingMemberCount <= 1 || values.manual_only, policy: values.policy, ...(canEditMembers(editing) ? { user_ids: parseMemberIDs(values.member_ids) } : {}) }); setEditing(undefined); message.success('分组已保存'); await load(); }
  catch (e: any) { if (!e.errorFields) message.error(e.message || '保存失败'); } finally { setSaving(false); }
 };
 const release = async () => {
  if (!releasing) return;
  const ids = [...new Set(releaseIDs.split(/[\s,，]+/).filter(Boolean))];
  if (!ids.length || ids.some(id => !releasing.user_ids.includes(id))) { message.error('请填写本组的具体用户 ID'); return; }
  setSaving(true);
  try { await apiJsonPost(endpoint + '/release', { id: releasing.id, revision: releasing.revision, user_ids: ids }); setReleasing(undefined); message.success('已恢复原业务下发'); await load(); }
  catch (e: any) { message.error(e.message || '操作失败'); } finally { setSaving(false); }
 };
 const runAction = async () => {
  if (!action || actionBusy) return;
  setActionBusy(true); setActionError(''); generation.current++;
  try {
   await apiJsonPost(endpoint + '/' + action.kind, { id: action.group.id, revision: action.group.revision });
   message.success(action.kind === 'confirm' ? '入口已确认，开始新一轮观察' : '本轮处理已完成'); setAction(undefined); await load();
  } catch (e: any) { setActionError(e.message || '操作失败，请刷新后重试'); }
  finally { setActionBusy(false); }
 };
 const renderGroupTable = (rows: Group[], maintenance = false, emptyText = '暂无分组') => (
  <Table<Group> className="forest-table investigation-groups" rowKey="id" size="small" dataSource={rows} pagination={{ pageSize: 15, showSizeChanger: false }} scroll={{ x: 1180 }} columns={[
   { title: '分组', width: 120, render: (_, g) => <div className="investigation-group-name"><span className={`investigation-kind-dot kind-${g.kind}`} /><strong>{g.name}</strong><span className="investigation-group-number">#{g.id}</span></div> },
   { title: '成员 / 已拉取', width: 95, align: 'right', render: (_, g) => <Tooltip title="当前有效成员 / 本轮成功下发人数"><span className="investigation-number">{g.user_ids.length.toLocaleString()} / {g.pulled_count || 0}</span></Tooltip> },
   { title: maintenance ? '成员 ID' : 'ID 范围', width: 160, render: (_, g) => { const ranges = memberRanges(g.user_ids); return ranges ? <Typography.Paragraph className="investigation-id-ranges" copyable={{ text: ranges }} ellipsis={{ rows: 2, tooltip: <div className="investigation-ranges-tooltip">{ranges}</div> }}>{ranges}</Typography.Paragraph> : '—'; } },
   { title: '下发入口', width: 164, render: (_, g) => <Typography.Text className="investigation-host" copyable>{g.host}</Typography.Text> },
   { title: '监控状态', width: 140, render: (_, g) => { if (error) return <Tag>状态读取失败</Tag>; const m = monitors.find(m => m.id === g.monitor_id && m.host === g.host); return m ? <DispatchMonitorStatus entry={m} /> : <Tag>状态待刷新</Tag>; } },
   { title: '自动处理', width: 110, render: (_, g) => { const state = processState(g, settings?.enabled); return <div className="investigation-process"><Tooltip title={state.detail}><span tabIndex={0} className={`investigation-process-state tone-${state.tone}`}>{state.label}</span></Tooltip>{g.no_pull_count > 0 && <span className="investigation-caption">未拉取 ×{g.no_pull_count}</span>}</div>; } },
   { title: '操作', width: 200, fixed: 'right', className: 'investigation-actions', render: (_, g) => <Space size={0}><Button type="link" disabled={saving || actionBusy} onClick={() => openEditor(g)}>编辑</Button>{!g.manual_only && g.policy !== 'fixed' && g.user_ids.length > 1 && <><Button type="link" disabled={!settings?.enabled || saving || actionBusy} onClick={() => { setActionError(''); setAction({ group: g, kind: 'confirm' }); }}>确认入口</Button><Button type="link" disabled={!settings?.enabled || saving || actionBusy} onClick={() => { setActionError(''); setAction({ group: g, kind: 'trigger' }); }}>立即触发</Button></>}</Space> },
  ]} expandable={{ columnWidth: 32, expandedRowRender: g => <div className="investigation-details"><div className="investigation-detail-meta"><span>类型：{g.lifecycle_role === 'stable' ? '稳定组' : g.lifecycle_role === 'whitelist' ? '老实人' : g.lifecycle_role === 'review' ? '老实人复核' : g.parent_id === 0 && g.kind === 'candidate' ? '初始入口' : kindName[g.kind]}</span><span>{g.route_scope === 'global' ? '全站下发' : '业务范围下发'}</span><span>策略：{policyNames[g.policy] || '智能筛选'}</span><span>原始组：#{g.root_id}</span>{g.parent_id > 0 && <span>父组：#{g.parent_id}</span>}</div>{g.normal_since > 0 && settings?.lifecycle_enabled && <div className="investigation-detail-reason">入口有效观察 {Math.max(0, ((g.normal_observed_at || g.normal_since) - g.normal_since) / 86400).toFixed(1)} 天 · {g.lifecycle_role === 'stable' ? '每人拉取A后再观察7天' : g.lifecycle_role === 'whitelist' ? '持续监控' : '每人成功拉取后观察3天'}</div>}{g.route_scope === 'global' && <Button size="small" style={{ marginBottom: 12 }} onClick={() => { setReleasing(g); setReleaseIDs(g.user_ids.join(', ')); }}>退出全站管理</Button>}{g.reason && <div className="investigation-detail-reason">处理说明：{g.reason}</div>}<div className="investigation-members"><span className="investigation-caption">成员 ID</span><Typography.Text copyable>{g.user_ids.join(', ')}</Typography.Text></div></div> }} locale={{ emptyText }} />
 );
 const renderMaintenance = (role: 'stable' | 'whitelist') => {
  const all = stageGroups(role), keyword = (searches[role] || '').trim().toLowerCase();
  const rows = all.filter(g => !keyword || g.name.toLowerCase().includes(keyword) || g.host.toLowerCase().includes(keyword) || String(g.id) === keyword || g.user_ids.includes(keyword));
  return <Card className="block-card" styles={{ body: { padding: 0 } }}>
   <div className="investigation-maintenance-toolbar">
    <Space wrap><Input aria-label={role === 'stable' ? '搜索稳定组' : '搜索老实人组'} placeholder="组名 / 入口 / 用户 ID" allowClear value={searches[role] || ''} onChange={e => setSearches(current => ({ ...current, [role]: e.target.value }))} className="investigation-maintenance-search" /><Typography.Text type="secondary">{rows.length} 个分组 · {rows.reduce((sum, g) => sum + g.user_ids.length, 0).toLocaleString()} 人</Typography.Text></Space>
    <Button onClick={() => void load()}>刷新</Button>
   </div>
   {renderGroupTable(rows, true, role === 'stable' ? '暂无稳定组' : '暂无老实人组')}
  </Card>;
 };
 return <div className="investigation-panel">
  <div className="investigation-heading"><Space size={10}><Typography.Text strong>谁是卧底</Typography.Text><span className={`investigation-switch-state${settings?.enabled ? ' is-on' : ''}`}>{settings?.enabled ? '运行中' : '已关闭'}</span></Space><span className="investigation-caption">{groups.length} 个分组</span></div>
  {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
  {workerError && <Alert type="error" showIcon message={workerError} style={{ marginBottom: 12 }} />}
  <Form form={form} layout="vertical" disabled={!settings || saving} className="investigation-settings">
   <Form.Item name="enabled" label="总开关" valuePropName="checked"><Switch aria-label="谁是卧底总开关" /></Form.Item>
   <Form.Item name="lifecycle_enabled" label="稳定与老实人" valuePropName="checked" tooltip="成功拉取原入口并观察3天后，进入稳定组、领取入口A；成功拉取A后再观察7天，进入老实人、领取入口B。按具体用户晋级，保留原节点下发范围。"><Switch aria-label="稳定与老实人" /></Form.Item>
   <Form.Item name="scope" label="生效范围" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'all', label: '全部入口组' }, { value: 'multi_range', label: '仅多ID范围组' }]} /></Form.Item>
   <Form.Item name="entry_window_minutes" label="单组间隔（分钟）" tooltip="同一原始组及其子组共享间隔，每个间隔最多处理一次" rules={[{ required: true }]}><InputNumber min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_window_minutes" label="全局窗口（分钟）" rules={[{ required: true }]}><InputNumber min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_max" label="窗口内最多次数" rules={[{ required: true }]}><InputNumber min={1} max={100} precision={0} /></Form.Item>
   <Space className="investigation-settings-actions"><Button type="primary" disabled={!settings} loading={saving} onClick={save}>保存</Button><Button onClick={() => { initialized.current = false; void load(); }}>刷新</Button></Space>
  </Form>
  <Tabs activeKey={section} onChange={setSection} className="investigation-maintenance-tabs" items={[
   { key: 'ordinary', label: `入口分组 (${ordinaryGroups.length})`, children: <Card className="block-card" styles={{ body: { padding: 0 } }}><div className="investigation-maintenance-toolbar"><Space><Select aria-label="分组分类" value={filter} onChange={setFilter} style={{ width: 140 }} options={[{ value: 'all', label: '全部分组' }, { value: 'ordinary', label: '多人自动组' }, { value: 'manual', label: '仅人工' }]} /><Typography.Text type="secondary">{visibleGroups.length} 个分组</Typography.Text></Space></div>{renderGroupTable(visibleGroups)}</Card> },
   { key: 'stable', label: `稳定组 (${stageGroups('stable').length})`, children: renderMaintenance('stable') },
   { key: 'whitelist', label: `老实人组 (${stageGroups('whitelist').length})`, children: renderMaintenance('whitelist') },
  ]} />
  <div className="investigation-history-heading"><Typography.Text strong>筛选历史</Typography.Text><span className="investigation-caption">{total} 条记录</span></div>
  <Table<Event> rowKey="id" size="small" dataSource={events} pagination={{ current: page, pageSize: 20, total, onChange: setPage, showSizeChanger: false }} scroll={{ x: 1100 }} columns={[
   { title: '时间', render: (_, e) => stamp(e.created_at) }, { title: '原始组 / 来源组', render: (_, e) => e.root_id ? `#${e.root_id} / #${e.group_id}` : '—' },
   { title: '结果', render: (_, e) => <Tag>{kindName[e.kind] || e.kind}</Tag> }, { title: '筛选截止', render: (_, e) => stamp(e.first_failure_at) },
   { title: '拉取 / 未拉取', render: (_, e) => e.payload.pulled_ids ? `${e.payload.pulled_ids.length} / ${e.payload.unpulled_ids?.length || 0}` : '—' },
   { title: '处理后入口', render: (_, e) => e.payload.partitions?.map((p, i) => <div key={i}>#{p.group_id} · {p.name || kindName[p.kind]} · {p.user_ids.length} 人 → {p.host}{p.merged_into ? '（归并）' : ''}</div>) || e.payload.host || '—' },
  ]} expandable={{ expandedRowRender: e => <div>{e.payload.evidence?.mode && <div>执行方式：{e.payload.evidence.mode === 'manual' ? '人工立即触发' : '自动触发'} · 截止依据：{({ established_incident: '已记录故障起点', first_observed_failure: '首次观察失败', manual_snapshot: '人工操作时点' } as Record<string, string>)[e.payload.evidence.cutoff_source || ''] || '—'}</div>}{e.payload.evidence?.warnings?.map((warning, i) => <div key={i}>{warning}</div>)}{e.payload.before && <div>原入口：{e.payload.before.host}</div>}{e.payload.user_ids && <div>相关用户 ID：{e.payload.user_ids.join(', ')}</div>}{e.payload.pulled_ids && <><div>已拉取 ID：{e.payload.pulled_ids.join(', ') || '无'}</div><div>未拉取 ID：{e.payload.unpulled_ids?.join(', ') || '无'}</div>{e.payload.recent_ids && <><div>120分钟内拉取 ID：{e.payload.recent_ids.join(', ') || '无'}</div><div>更早拉取 ID：{e.payload.older_ids?.join(', ') || '无'}</div></>}</>}{e.payload.evidence?.controls && Object.entries(e.payload.evidence.controls).map(([probe, hosts]) => <div key={probe}>探针 #{probe} · 正常对照：{hosts.join(', ')}</div>)}{e.payload.reason && <div>{e.payload.reason}</div>}</div> }} locale={{ emptyText: '暂无记录' }} />
  <Modal open={!!editing} title={editing?.lifecycle_role === 'stable' ? '编辑稳定组' : editing?.lifecycle_role === 'whitelist' ? '编辑老实人组' : '编辑分组'} width={canEditMembers(editing) ? 960 : 520} onCancel={() => setEditing(undefined)} onOk={saveEdit} confirmLoading={saving} okText="保存" destroyOnClose>
   <Form form={editForm} layout="vertical" className={canEditMembers(editing) ? 'investigation-maintenance-form' : undefined}>
    <div className="investigation-edit-fields">
     <Form.Item name="name" label="组名" rules={[{ required: true }]}><Input maxLength={200} /></Form.Item>
     <Form.Item name="host" label="下发地址" rules={[{ required: true }]}><Input /></Form.Item>
     <Form.Item name="policy" label="自动策略" rules={[{ required: true }]}><Select options={Object.entries(policyNames).map(([value, label]) => ({ value, label }))} /></Form.Item>
     <Form.Item name="manual_only" label="仅人工操作" valuePropName="checked"><Switch disabled={editingMemberCount <= 1} /></Form.Item>
    </div>
    {canEditMembers(editing) ? <div className="investigation-edit-members">
     <Form.Item name="member_ids" label={`用户成员（${editingMemberCount} 人）`} tooltip="按具体用户保存。移出后恢复原业务下发；新增成员从成功拉取新入口后重新计时。" rules={[{ validator: (_, value) => { const ids = parseMemberIDs(value); return ids.length > 0 && ids.length <= 20000 && ids.every(id => /^[1-9]\d*$/.test(id)) ? Promise.resolve() : Promise.reject(new Error('请选择1至20000个具体用户，不支持ID范围')); } }]}><UserEmailSelect key={editing?.id} /></Form.Item>
     <div className="investigation-edit-member-ids"><Typography.Text type="secondary">成员 ID</Typography.Text><Typography.Paragraph copyable={{ text: memberRanges(editingMemberIDs ?? editing?.user_ids ?? []) }} ellipsis={{ rows: 3, expandable: true, symbol: '展开' }}>{memberRanges(editingMemberIDs ?? editing?.user_ids ?? []) || '—'}</Typography.Paragraph></div>
    </div> : <Form.Item label="ID 范围"><Input.TextArea aria-label="ID 范围" readOnly value={editing ? memberRanges(editing.user_ids) || '—' : ''} autoSize={{ minRows: 2, maxRows: 5 }} /></Form.Item>}
   </Form>
  </Modal>
  <Modal open={!!releasing} title="退出全站管理" onCancel={() => setReleasing(undefined)} onOk={release} confirmLoading={saving} okText="恢复原业务下发" destroyOnClose>
   <Typography.Paragraph>选中的用户退出全站入口覆盖，恢复原业务规则及有效业务分组下发，之后可以使用原有规则指定入口。</Typography.Paragraph>
   <Input.TextArea aria-label="退出全站管理的用户ID" value={releaseIDs} onChange={e => setReleaseIDs(e.target.value)} autoSize={{ minRows: 3, maxRows: 8 }} />
  </Modal>
  <Modal open={!!action} title={action?.kind === 'confirm' ? '确认入口' : '立即触发'} onCancel={() => { if (!actionBusy) setAction(undefined); }} onOk={runAction} confirmLoading={actionBusy} cancelButtonProps={{ disabled: actionBusy }} closable={!actionBusy} maskClosable={!actionBusy} keyboard={!actionBusy} okText={action?.kind === 'confirm' ? '确认并开始观察' : '立即触发'} destroyOnClose>
   <Typography.Paragraph><strong>{action?.group.name}</strong> · #{action?.group.id}<br />入口：{action?.group.host}<br />成员：{action?.group.user_ids.length} 人</Typography.Paragraph>
   <Typography.Paragraph>{action?.kind === 'confirm' ? '确认当前入口进入新一轮观察，从本次确认后重新记录拉取与检测结果。成员和下发地址不变，不立即换 IP。此前记录不参与本轮筛选。' : action?.group.lifecycle_role === 'whitelist' ? '按白名单策略整组切换到健康入口。人工操作不累计独立故障次数，不伪造24小时第二次故障。' : '立即按当前轮次的拉取记录执行筛选、二分或换 IP。使用已记录的首次失败作为截止时间；没有失败记录时，以本次操作时点为截止时间。不等待自动故障确认、正常对照或自动限频。需要足够的健康备用 IP，处理成功后会改变相关用户的实际下发入口。'}</Typography.Paragraph>
   {actionError && <Alert type="error" showIcon message={actionError} />}
  </Modal>
 </div>;
}
