import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tag, Typography, message } from 'antd';
import { apiGet, apiPut, unwrapData, unwrapList } from '../lib/api';
import DispatchMonitorStatus, { type DispatchMonitorStatusEntry } from './DispatchMonitorStatus';

type Settings = { enabled: boolean; scope: 'all' | 'multi_range'; revision: number; entry_window_minutes: number; global_window_minutes: number; global_max: number };
type Group = { id: number; root_id: number; parent_id: number; name: string; kind: string; host: string; monitor_id: number; manual_only: boolean; revision: number; reason: string; user_ids: string[]; no_pull_count: number };
type Event = { id: number; root_id: number; group_id: number; kind: string; first_failure_at: number; created_at: number; payload: { before?: Group; pulled_ids?: number[]; unpulled_ids?: number[]; recent_ids?: number[]; older_ids?: number[]; recent_window_minutes?: number; partitions?: { group_id: number; user_ids: number[]; kind: string; host: string; merged_into?: number }[]; evidence?: { controls?: Record<string, string[]> }; reason?: string; host?: string; user_ids?: number[]; after?: any } };
type Monitor = DispatchMonitorStatusEntry & { id: number; host: string };
const endpoint = '/dns-failover/dispatch-investigation';
const stamp = (v: number) => v ? new Date(v * 1000).toLocaleString() : '—';
const kindName: Record<string, string> = { candidate: '卧底', recent: '120分钟', observation: '观察', confirmed: '实锤内鬼', filtered: '已筛选', bisected: '全部拉取 · 已二分', no_pulls: '无人拉取 · 已换入口', started: '开始观察', settings: '设置变更', edited: '人工编辑' };

export default function DispatchInvestigationPanel({ active = true }: { active?: boolean }) {
 const [form] = Form.useForm<Settings>(), [editForm] = Form.useForm<Group>();
 const [settings, setSettings] = useState<Settings>(), [groups, setGroups] = useState<Group[]>([]), [events, setEvents] = useState<Event[]>([]);
 const [monitors, setMonitors] = useState<Monitor[]>([]), [error, setError] = useState(''), [workerError, setWorkerError] = useState('');
 const [saving, setSaving] = useState(false), [editing, setEditing] = useState<Group>(), [page, setPage] = useState(1), [total, setTotal] = useState(0);
 const generation = useRef(0), initialized = useRef(false), revision = useRef(0);
 const load = async () => {
  const seq = ++generation.current;
  try {
   const [res, monitorRes] = await Promise.all([apiGet(endpoint, { page }), apiGet('/dns-failover/dispatch-entries', { include_deleted: true })]);
   if (seq !== generation.current) return;
   const data = unwrapData(res); setSettings(data.settings); setGroups(data.groups || []); setEvents(data.events || []); setTotal(data.total || 0); setMonitors(unwrapList(monitorRes)); setError(''); setWorkerError(data.worker_error || '');
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
 return <div style={{ padding: 16 }}>
  <Space style={{ marginBottom: 12 }}><Typography.Text strong>谁是卧底</Typography.Text><Tag color={settings?.enabled ? 'processing' : 'default'}>{settings?.enabled ? '已开启' : '已关闭'}</Tag></Space>
  {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
  {workerError && <Alert type="error" showIcon message={workerError} style={{ marginBottom: 12 }} />}
  <Form form={form} layout="inline" disabled={!settings || saving} style={{ gap: 12, marginBottom: 16 }}>
   <Form.Item name="enabled" label="总开关" valuePropName="checked"><Switch aria-label="谁是卧底总开关" /></Form.Item>
   <Form.Item name="scope" label="生效范围" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'all', label: '全部入口组' }, { value: 'multi_range', label: '仅多ID范围组' }]} /></Form.Item>
   <Form.Item name="entry_window_minutes" label="同原始组每 N 分钟最多一次" rules={[{ required: true }]}><InputNumber min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_window_minutes" label="全局窗口（分钟）" rules={[{ required: true }]}><InputNumber min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_max" label="全局最多次数" rules={[{ required: true }]}><InputNumber min={1} max={100} precision={0} /></Form.Item>
   <Button type="primary" disabled={!settings} loading={saving} onClick={save}>保存</Button><Button onClick={() => { initialized.current = false; void load(); }}>刷新</Button>
  </Form>
  <Table<Group> rowKey="id" size="small" dataSource={groups} pagination={{ pageSize: 15 }} scroll={{ x: 1300 }} columns={[
   { title: '分组', render: (_, g) => <><strong>{g.name}</strong><div>#{g.id} · 原始组 #{g.root_id}{g.parent_id ? ` · 来源 #${g.parent_id}` : ''}</div></> },
   { title: '类型', render: (_, g) => <Space direction="vertical" size={0}><Tag color={g.kind === 'confirmed' ? 'error' : g.kind === 'observation' ? 'default' : 'processing'}>{kindName[g.kind]}</Tag>{(g.manual_only || g.user_ids.length <= 1) && <Tag>仅人工操作</Tag>}</Space> },
   { title: '人数', render: (_, g) => g.user_ids.length }, { title: '下发入口', dataIndex: 'host' },
   { title: '监控状态', width: 190, render: (_, g) => { if (error) return <Tag>状态读取失败</Tag>; const m = monitors.find(m => m.id === g.monitor_id && m.host === g.host); return m ? <DispatchMonitorStatus entry={m} /> : <Tag>未参与当前下发</Tag>; } },
   { title: '处理状态', render: (_, g) => <>{g.reason}{g.no_pull_count > 0 && <div>无人拉取累计 {g.no_pull_count} 次</div>}</> },
   { title: '操作', render: (_, g) => <Button type="link" onClick={() => { setEditing(g); editForm.setFieldsValue({ ...g, manual_only: g.manual_only || g.user_ids.length <= 1 }); }}>编辑</Button> },
  ]} expandable={{ expandedRowRender: g => <Typography.Text copyable>{g.user_ids.join(', ')}</Typography.Text> }} locale={{ emptyText: '暂无分组' }} />
  <Typography.Title level={5}>筛选历史</Typography.Title>
  <Table<Event> rowKey="id" size="small" dataSource={events} pagination={{ current: page, pageSize: 20, total, onChange: setPage, showSizeChanger: false }} scroll={{ x: 1100 }} columns={[
   { title: '时间', render: (_, e) => stamp(e.created_at) }, { title: '原始组 / 来源组', render: (_, e) => e.root_id ? `#${e.root_id} / #${e.group_id}` : '—' },
   { title: '结果', render: (_, e) => <Tag>{kindName[e.kind] || e.kind}</Tag> }, { title: '首次失败', render: (_, e) => stamp(e.first_failure_at) },
   { title: '拉取 / 未拉取', render: (_, e) => e.payload.pulled_ids ? `${e.payload.pulled_ids.length} / ${e.payload.unpulled_ids?.length || 0}` : '—' },
   { title: '处理后入口', render: (_, e) => e.payload.partitions?.map((p, i) => <div key={i}>#{p.group_id} · {kindName[p.kind]} · {p.user_ids.length} 人 → {p.host}{p.merged_into ? '（归并）' : ''}</div>) || e.payload.host || '—' },
  ]} expandable={{ expandedRowRender: e => <div>{e.payload.before && <div>原入口：{e.payload.before.host}</div>}{e.payload.pulled_ids && <><div>已拉取 ID：{e.payload.pulled_ids.join(', ') || '无'}</div><div>未拉取 ID：{e.payload.unpulled_ids?.join(', ') || '无'}</div>{e.payload.recent_ids && <><div>120分钟内拉取 ID：{e.payload.recent_ids.join(', ') || '无'}</div><div>更早拉取 ID：{e.payload.older_ids?.join(', ') || '无'}</div></>}</>}{e.payload.evidence?.controls && Object.entries(e.payload.evidence.controls).map(([probe, hosts]) => <div key={probe}>探针 #{probe} · 正常对照：{hosts.join(', ')}</div>)}{e.payload.reason && <div>{e.payload.reason}</div>}</div> }} locale={{ emptyText: '暂无记录' }} />
  <Modal open={!!editing} title="编辑分组" onCancel={() => setEditing(undefined)} onOk={saveEdit} confirmLoading={saving} okText="保存" destroyOnClose>
   <Form form={editForm} layout="vertical"><Form.Item name="name" label="组名" rules={[{ required: true }]}><Input maxLength={200} /></Form.Item><Form.Item name="host" label="下发地址" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="manual_only" label="仅人工操作" valuePropName="checked"><Switch disabled={!!editing && editing.user_ids.length <= 1} /></Form.Item></Form>
  </Modal>
 </div>;
}
