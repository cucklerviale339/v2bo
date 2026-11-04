import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tag, Tooltip, Typography, message } from 'antd';
import { apiGet, apiJsonPost, apiPut, unwrapData, unwrapList } from '../lib/api';
import DispatchMonitorStatus, { type DispatchMonitorStatusEntry } from './DispatchMonitorStatus';
import '../styles/investigation.css';

type Settings = { enabled: boolean; scope: 'all' | 'multi_range'; revision: number; entry_window_minutes: number; global_window_minutes: number; global_max: number };
type Group = { id: number; root_id: number; parent_id: number; name: string; kind: string; host: string; monitor_id: number; manual_only: boolean; revision: number; reason: string; user_ids: string[]; no_pull_count: number; confirmed_at?: number };
type Event = { id: number; root_id: number; group_id: number; kind: string; first_failure_at: number; created_at: number; payload: { before?: Group; pulled_ids?: number[]; unpulled_ids?: number[]; recent_ids?: number[]; older_ids?: number[]; recent_window_minutes?: number; partitions?: { group_id: number; user_ids: number[]; kind: string; host: string; merged_into?: number }[]; evidence?: { controls?: Record<string, string[]>; mode?: string; cutoff_source?: string; warnings?: string[] }; reason?: string; host?: string; user_ids?: number[]; after?: any } };
type Monitor = DispatchMonitorStatusEntry & { id: number; host: string };
const endpoint = '/dns-failover/dispatch-investigation';
const stamp = (v: number) => v ? new Date(v * 1000).toLocaleString() : '—';
const kindName: Record<string, string> = { candidate: '卧底', recent: '120分钟', observation: '观察', confirmed: '实锤内鬼', filtered: '已筛选', bisected: '全部拉取 · 已二分', no_pulls: '无人拉取 · 已换入口', started: '开始观察', settings: '设置变更', edited: '人工编辑', confirmed_entry: '人工确认入口', manual_trigger: '人工立即触发' };
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
};
function processState(g: Group, enabled?: boolean) {
 if (g.manual_only || g.user_ids.length <= 1) return { label: '仅人工', tone: 'paused', detail: '仅人工操作，不参与自动筛选或入口分配' };
 if (enabled === undefined) return { label: '—', tone: 'paused', detail: '等待设置加载' };
 if (!enabled) return { label: '已关闭', tone: 'paused', detail: '总开关已关闭，暂停自动处理' };
 const [label, tone] = processStates[g.reason] || (/^等待 \d+ 个同检测端口的健康未占用备用 IP$/.test(g.reason) ? ['待补 IP', 'waiting'] : g.reason.startsWith('本轮未修改：') ? ['处理受阻', 'error'] : ['待处理', 'waiting']);
 return { label, tone, detail: g.reason || '等待自动处理' };
}

export default function DispatchInvestigationPanel({ active = true }: { active?: boolean }) {
 const [form] = Form.useForm<Settings>(), [editForm] = Form.useForm<Group>();
 const [settings, setSettings] = useState<Settings>(), [groups, setGroups] = useState<Group[]>([]), [events, setEvents] = useState<Event[]>([]);
 const [monitors, setMonitors] = useState<Monitor[]>([]), [error, setError] = useState(''), [workerError, setWorkerError] = useState('');
 const [saving, setSaving] = useState(false), [editing, setEditing] = useState<Group>(), [page, setPage] = useState(1), [total, setTotal] = useState(0);
 const [action, setAction] = useState<{ group: Group; kind: 'confirm' | 'trigger' }>(), [actionBusy, setActionBusy] = useState(false), [actionError, setActionError] = useState('');
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
  try { const values = await editForm.validateFields(); setSaving(true); generation.current++; await apiPut(endpoint + '/groups', { id: editing.id, revision: editing.revision, name: values.name, host: values.host, manual_only: values.manual_only }); setEditing(undefined); message.success('分组已保存'); await load(); }
  catch (e: any) { if (!e.errorFields) message.error(e.message || '保存失败'); } finally { setSaving(false); }
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
 return <div className="investigation-panel">
  <div className="investigation-heading"><Space size={10}><Typography.Text strong>谁是卧底</Typography.Text><span className={`investigation-switch-state${settings?.enabled ? ' is-on' : ''}`}>{settings?.enabled ? '运行中' : '已关闭'}</span></Space><span className="investigation-caption">{groups.length} 个分组</span></div>
  {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
  {workerError && <Alert type="error" showIcon message={workerError} style={{ marginBottom: 12 }} />}
  <Form form={form} layout="vertical" disabled={!settings || saving} className="investigation-settings">
   <Form.Item name="enabled" label="总开关" valuePropName="checked"><Switch aria-label="谁是卧底总开关" /></Form.Item>
   <Form.Item name="scope" label="生效范围" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'all', label: '全部入口组' }, { value: 'multi_range', label: '仅多ID范围组' }]} /></Form.Item>
   <Form.Item name="entry_window_minutes" label="单组间隔（分钟）" tooltip="同一原始组及其子组共享间隔，每个间隔最多处理一次" rules={[{ required: true }]}><InputNumber min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_window_minutes" label="全局窗口（分钟）" rules={[{ required: true }]}><InputNumber min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_max" label="窗口内最多次数" rules={[{ required: true }]}><InputNumber min={1} max={100} precision={0} /></Form.Item>
   <Space className="investigation-settings-actions"><Button type="primary" disabled={!settings} loading={saving} onClick={save}>保存</Button><Button onClick={() => { initialized.current = false; void load(); }}>刷新</Button></Space>
  </Form>
  <Table<Group> className="investigation-groups" rowKey="id" size="small" dataSource={groups} pagination={{ pageSize: 15, showSizeChanger: false }} scroll={{ x: 1080 }} columns={[
   { title: '分组', width: 120, render: (_, g) => <div className="investigation-group-name"><span className={`investigation-kind-dot kind-${g.kind}`} /><strong>{g.name}</strong><span className="investigation-group-number">#{g.id}</span></div> },
   { title: '人数', width: 56, align: 'right', render: (_, g) => <span className="investigation-number">{g.user_ids.length.toLocaleString()}</span> },
   { title: 'ID 范围', width: 160, render: (_, g) => { const ranges = memberRanges(g.user_ids); return ranges ? <Typography.Paragraph className="investigation-id-ranges" copyable={{ text: ranges }} ellipsis={{ rows: 2, tooltip: <div className="investigation-ranges-tooltip">{ranges}</div> }}>{ranges}</Typography.Paragraph> : '—'; } },
   { title: '下发入口', width: 164, render: (_, g) => <Typography.Text className="investigation-host" copyable>{g.host}</Typography.Text> },
   { title: '监控状态', width: 140, render: (_, g) => { if (error) return <Tag>状态读取失败</Tag>; const m = monitors.find(m => m.id === g.monitor_id && m.host === g.host); return m ? <DispatchMonitorStatus entry={m} /> : <Tag>状态待刷新</Tag>; } },
   { title: '自动处理', width: 110, render: (_, g) => { const state = processState(g, settings?.enabled); return <div className="investigation-process"><Tooltip title={state.detail}><span tabIndex={0} className={`investigation-process-state tone-${state.tone}`}>{state.label}</span></Tooltip>{g.no_pull_count > 0 && <span className="investigation-caption">未拉取 ×{g.no_pull_count}</span>}</div>; } },
   { title: '操作', width: 200, fixed: 'right', className: 'investigation-actions', render: (_, g) => <Space size={0}><Button type="link" disabled={saving || actionBusy} onClick={() => { setEditing(g); editForm.setFieldsValue({ ...g, manual_only: g.manual_only || g.user_ids.length <= 1 }); }}>编辑</Button>{!g.manual_only && g.user_ids.length > 1 && <><Button type="link" disabled={!settings?.enabled || saving || actionBusy} onClick={() => { setActionError(''); setAction({ group: g, kind: 'confirm' }); }}>确认入口</Button><Button type="link" disabled={!settings?.enabled || saving || actionBusy} onClick={() => { setActionError(''); setAction({ group: g, kind: 'trigger' }); }}>立即触发</Button></>}</Space> },
  ]} expandable={{ columnWidth: 32, expandedRowRender: g => <div className="investigation-details"><div className="investigation-detail-meta"><span>类型：{g.parent_id === 0 && g.kind === 'candidate' ? '初始入口' : kindName[g.kind]}</span><span>原始组：#{g.root_id}</span>{g.parent_id > 0 && <span>父组：#{g.parent_id}</span>}</div>{g.reason && <div className="investigation-detail-reason">处理说明：{g.reason}</div>}<div className="investigation-members"><span className="investigation-caption">成员 ID</span><Typography.Text copyable>{g.user_ids.join(', ')}</Typography.Text></div></div> }} locale={{ emptyText: '暂无分组' }} />
  <div className="investigation-history-heading"><Typography.Text strong>筛选历史</Typography.Text><span className="investigation-caption">{total} 条记录</span></div>
  <Table<Event> rowKey="id" size="small" dataSource={events} pagination={{ current: page, pageSize: 20, total, onChange: setPage, showSizeChanger: false }} scroll={{ x: 1100 }} columns={[
   { title: '时间', render: (_, e) => stamp(e.created_at) }, { title: '原始组 / 来源组', render: (_, e) => e.root_id ? `#${e.root_id} / #${e.group_id}` : '—' },
   { title: '结果', render: (_, e) => <Tag>{kindName[e.kind] || e.kind}</Tag> }, { title: '筛选截止', render: (_, e) => stamp(e.first_failure_at) },
   { title: '拉取 / 未拉取', render: (_, e) => e.payload.pulled_ids ? `${e.payload.pulled_ids.length} / ${e.payload.unpulled_ids?.length || 0}` : '—' },
   { title: '处理后入口', render: (_, e) => e.payload.partitions?.map((p, i) => <div key={i}>#{p.group_id} · {kindName[p.kind]} · {p.user_ids.length} 人 → {p.host}{p.merged_into ? '（归并）' : ''}</div>) || e.payload.host || '—' },
  ]} expandable={{ expandedRowRender: e => <div>{e.payload.evidence?.mode && <div>执行方式：{e.payload.evidence.mode === 'manual' ? '人工立即触发' : '自动触发'} · 截止依据：{({ established_incident: '已记录故障起点', first_observed_failure: '首次观察失败', manual_snapshot: '人工操作时点' } as Record<string, string>)[e.payload.evidence.cutoff_source || ''] || '—'}</div>}{e.payload.evidence?.warnings?.map((warning, i) => <div key={i}>{warning}</div>)}{e.payload.before && <div>原入口：{e.payload.before.host}</div>}{e.payload.pulled_ids && <><div>已拉取 ID：{e.payload.pulled_ids.join(', ') || '无'}</div><div>未拉取 ID：{e.payload.unpulled_ids?.join(', ') || '无'}</div>{e.payload.recent_ids && <><div>120分钟内拉取 ID：{e.payload.recent_ids.join(', ') || '无'}</div><div>更早拉取 ID：{e.payload.older_ids?.join(', ') || '无'}</div></>}</>}{e.payload.evidence?.controls && Object.entries(e.payload.evidence.controls).map(([probe, hosts]) => <div key={probe}>探针 #{probe} · 正常对照：{hosts.join(', ')}</div>)}{e.payload.reason && <div>{e.payload.reason}</div>}</div> }} locale={{ emptyText: '暂无记录' }} />
  <Modal open={!!editing} title="编辑分组" onCancel={() => setEditing(undefined)} onOk={saveEdit} confirmLoading={saving} okText="保存" destroyOnClose>
   <Form form={editForm} layout="vertical"><Form.Item name="name" label="组名" rules={[{ required: true }]}><Input maxLength={200} /></Form.Item><Form.Item label="ID 范围"><Input.TextArea aria-label="ID 范围" readOnly value={editing ? memberRanges(editing.user_ids) || '—' : ''} autoSize={{ minRows: 2, maxRows: 5 }} /></Form.Item><Form.Item name="host" label="下发地址" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="manual_only" label="仅人工操作" valuePropName="checked"><Switch disabled={!!editing && editing.user_ids.length <= 1} /></Form.Item></Form>
  </Modal>
  <Modal open={!!action} title={action?.kind === 'confirm' ? '确认入口' : '立即触发'} onCancel={() => { if (!actionBusy) setAction(undefined); }} onOk={runAction} confirmLoading={actionBusy} cancelButtonProps={{ disabled: actionBusy }} closable={!actionBusy} maskClosable={!actionBusy} keyboard={!actionBusy} okText={action?.kind === 'confirm' ? '确认并开始观察' : '立即触发'} destroyOnClose>
   <Typography.Paragraph><strong>{action?.group.name}</strong> · #{action?.group.id}<br />入口：{action?.group.host}<br />成员：{action?.group.user_ids.length} 人</Typography.Paragraph>
   <Typography.Paragraph>{action?.kind === 'confirm' ? '确认当前入口进入新一轮观察，从本次确认后重新记录拉取与检测结果。成员和下发地址不变，不立即换 IP。此前记录不参与本轮筛选。' : '立即按当前轮次的拉取记录执行筛选、二分或换 IP。使用已记录的首次失败作为截止时间；没有失败记录时，以本次操作时点为截止时间。不等待自动故障确认、正常对照或自动限频。需要足够的健康备用 IP，处理成功后会改变相关用户的实际下发入口。'}</Typography.Paragraph>
   {actionError && <Alert type="error" showIcon message={actionError} />}
  </Modal>
 </div>;
}
