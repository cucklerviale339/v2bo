import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tag, Typography, message } from 'antd';
import { apiGet, apiPut, unwrapData, unwrapList } from '../lib/api';
import DispatchMonitorStatus, { type DispatchMonitorStatusEntry } from './DispatchMonitorStatus';

type Settings = { enabled: boolean; entry_window_minutes: number; global_window_minutes: number; global_max: number; armed_at?: number };
type Operation = { id: number; group_id: number; root_group_id: number; child_a_id: number; child_b_id: number; host: string; root_host: string; probe_id: number; status: string; reason: string; range_a: string; range_b: string; ip_a: string; ip_b: string; created_at: number; updated_at: number };
type Group = { id: number; root_group_id: number; parent_group_id: number; monitor_id: number; host: string; id_range: string; revision: number; active: boolean; has_children: boolean };
type MonitorStatusRow = DispatchMonitorStatusEntry & { id: number; host: string };
const endpoint = '/dns-failover/dispatch-auto-split';
const stamp = (v?: number) => v ? new Date(v * 1000).toLocaleString() : '—';

export default function DispatchAutoSplitPanel({ active = true }: { active?: boolean }) {
 const [form] = Form.useForm<Settings>();
 const [settings, setSettings] = useState<Settings>();
 const [rows, setRows] = useState<Operation[]>([]), [error, setError] = useState(''), [workerError, setWorkerError] = useState('');
 const [saving, setSaving] = useState(false);
 const [groups, setGroups] = useState<Group[]>([]), [editing, setEditing] = useState<Group[]>([]), [editingSaving, setEditingSaving] = useState(false);
 const [monitors, setMonitors] = useState<MonitorStatusRow[]>([]);
 const [editForm] = Form.useForm<{ groups: Group[] }>();
 const initialized = useRef(false), generation = useRef(0);
 const load = async () => {
  const seq = ++generation.current;
  try {
   const [response, monitorResponse] = await Promise.all([apiGet(endpoint), apiGet('/dns-failover/dispatch-entries', { include_deleted: true })]);
   const data = unwrapData(response);
   if (seq !== generation.current) return;
   setSettings(data.settings); setRows(data.operations || []); setGroups(data.groups || []); setWorkerError(data.worker_error || ''); setError('');
   setMonitors(unwrapList(monitorResponse));
   if (!initialized.current) { form.setFieldsValue(data.settings); initialized.current = true; }
  } catch (e: any) { if (seq === generation.current) setError(e.message || '自动二分设置读取失败'); }
 };
 const openEdit = (ids: number[]) => {
  const selected = ids.map(id => groups.find(g => g.id === id)).filter((g): g is Group => !!g);
  if (selected.length !== ids.length) { message.error('分组信息已变化，请刷新后重试'); return; }
  setEditing(selected); editForm.setFieldsValue({ groups: selected.map(g => ({ ...g })) });
 };
 const saveGroups = async () => {
  try {
   const values = await editForm.validateFields(); setEditingSaving(true);
   await apiPut(endpoint + '/groups', { groups: values.groups.map((g, index) => ({ id: editing[index].id, revision: editing[index].revision, parent_group_id: g.parent_group_id, id_range: g.id_range, host: g.host })) });
   generation.current++;
   setMonitors(previous => previous.map(m => editing.some(g => g.monitor_id === m.id) ? { ...m, states: [] } : m));
   setEditing([]); message.success('分组关系和实际下发规则已保存'); await load();
  } catch (e: any) { if (!e.errorFields) message.error(e.message || '保存分组失败'); }
  finally { setEditingSaving(false); }
 };
 const parentOptions = (id: number) => {
  const excluded = new Set([id]);
  for (let i = 0; i < groups.length; i++) for (const g of groups) if (excluded.has(g.parent_group_id)) excluded.add(g.id);
  return [{ value: 0, label: '无父分组（作为根分组）' }, ...groups.filter(g => !excluded.has(g.id)).map(g => ({ value: g.id, label: `G${g.id} · ${g.host} · ${g.id_range}` }))];
 };
 useEffect(() => { if (!active) return; void load(); const timer = window.setInterval(() => void load(), 15000); return () => { generation.current++; clearInterval(timer); }; }, [active]);
 const save = async () => {
  try {
   const values = await form.validateFields(); setSaving(true); generation.current++;
   const data = unwrapData(await apiPut(endpoint, values));
   setSettings(data.settings); setRows(data.operations || []); setError('');
   message.success('自动二分设置已保存，将重新累计 10 分钟连续超时');
  } catch (e: any) { if (!e.errorFields) message.error(e.message || '保存失败'); }
  finally { setSaving(false); }
 };
 return <div style={{ padding: 16 }}>
  <Space style={{ marginBottom: 12 }}><Typography.Text strong>超时自动二分</Typography.Text><Tag color={settings?.enabled ? 'warning' : 'default'}>{settings?.enabled ? '已开启' : '已关闭'}</Tag></Space>
  {error && <Alert showIcon type="error" message={error} style={{ marginBottom: 10 }} />}
  {workerError && <Alert showIcon type="error" message={workerError} style={{ marginBottom: 10 }} />}
  <Form form={form} layout="inline" disabled={!settings || saving} style={{ gap: 12, marginBottom: 12 }}>
   <Form.Item name="enabled" label="自动二分" valuePropName="checked"><Switch aria-label="超时自动二分开关" /></Form.Item>
   <Form.Item name="entry_window_minutes" label="同入口每 N 分钟最多一次" rules={[{ required: true }]}><InputNumber aria-label="单入口频率分钟" min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_window_minutes" label="全局窗口（分钟）" rules={[{ required: true }]}><InputNumber aria-label="全局频率分钟" min={1} max={10080} precision={0} /></Form.Item>
   <Form.Item name="global_max" label="全局窗口内最多次数" rules={[{ required: true }]}><InputNumber aria-label="全局最多次数" min={1} max={100} precision={0} /></Form.Item>
   <Button type="primary" loading={saving} disabled={!settings} onClick={save}>保存自动二分设置</Button>
  </Form>
  <Typography.Title level={5}>当前分组</Typography.Title>
  <Table<Group> size="small" rowKey="id" dataSource={groups} pagination={{ pageSize: 10 }} scroll={{ x: 1000 }} columns={[
   { title: '分组', render: (_, g) => `G${g.id}` },
   { title: '父分组 / 根分组', render: (_, g) => `${g.parent_group_id ? `G${g.parent_group_id}` : '无'} / G${g.root_group_id}` },
   { title: '下发地址', dataIndex: 'host' },
   { title: 'ID 范围', dataIndex: 'id_range' },
   { title: '监控状态', width: 190, render: (_, g) => {
    if (error) return <Tag>状态读取失败</Tag>;
    const monitor = monitors.find(m => m.id === g.monitor_id && m.host === g.host);
    if (monitor) return <DispatchMonitorStatus entry={monitor} />;
    return g.active ? <Tag>未参与当前下发</Tag> : <DispatchMonitorStatus entry={{ enabled: false, probe_ids: [], states: [] }} />;
   } },
   { title: '操作', render: (_, g) => <Button type="link" aria-label={`编辑分组 G${g.id}`} onClick={() => openEdit([g.id])}>编辑</Button> },
  ]} locale={{ emptyText: '暂无分组' }} />
  <Typography.Title level={5}>历史二分记录</Typography.Title>
  <Table<Operation> size="small" rowKey="id" dataSource={rows} pagination={{ pageSize: 10 }} scroll={{ x: 1100 }} columns={[
   { title: '更新时间', width: 170, render: (_, r) => stamp(r.updated_at) },
   { title: '原入口 / 探针', width: 210, render: (_, r) => <>{r.host}<div>分组 G{r.group_id} · 根分组 G{r.root_group_id}</div><div>探针 #{r.probe_id}</div>{r.root_host !== r.host && <div>最初入口：{r.root_host}</div>}</> },
   { title: '状态', width: 95, render: (_, r) => <Tag color={r.status === 'succeeded' ? 'success' : r.status === 'waiting' ? 'warning' : 'default'}>{r.status === 'succeeded' ? '已二分' : r.status === 'waiting' ? '等待条件' : '已取消'}</Tag> },
   { title: '原因', dataIndex: 'reason', width: 320 },
   { title: '二分后下发', render: (_, r) => r.ip_a ? <><div>G{r.child_a_id}：{r.range_a} → {r.ip_a}</div><div>G{r.child_b_id}：{r.range_b} → {r.ip_b}</div></> : '未修改' },
   { title: '操作', width: 100, render: (_, r) => <Button type="link" aria-label={`编辑二分记录 ${r.id}`} onClick={() => openEdit(r.status === 'succeeded' ? [r.child_a_id, r.child_b_id] : [r.group_id])}>编辑</Button> },
  ]} locale={{ emptyText: error ? '读取失败' : '暂无自动二分记录' }} />
  <Modal open={!!editing.length} width={760} title="编辑故障转移分组" confirmLoading={editingSaving} okText="保存并更新实际下发" onOk={saveGroups} onCancel={() => !editingSaving && setEditing([])} maskClosable={!editingSaving}>
   <Form form={editForm} layout="vertical" disabled={editingSaving}>
    {editing.map((g, index) => <div key={g.id} style={{ padding: 12, border: '1px solid #e8e8e8', borderRadius: 6, marginBottom: 12 }}>
     <Typography.Title level={5}>分组 G{g.id}</Typography.Title>
     <Form.Item name={['groups', index, 'parent_group_id']} label="父分组" rules={[{ required: true }]}><Select aria-label={`G${g.id} 父分组`} showSearch optionFilterProp="label" options={parentOptions(g.id)} /></Form.Item>
     <Form.Item name={['groups', index, 'id_range']} label="ID 范围" rules={[{ required: true, message: '请输入 ID 范围' }]}><Input aria-label={`G${g.id} ID范围`} disabled={!g.active} placeholder="例如 100-199" /></Form.Item>
     <Form.Item name={['groups', index, 'host']} label="下发地址" rules={[{ required: true, message: '请输入下发地址' }]}><Input aria-label={`G${g.id} 下发地址`} disabled={!g.active} placeholder="IP 或域名，不含端口" /></Form.Item>
    </div>)}
   </Form>
  </Modal>
 </div>;
}
