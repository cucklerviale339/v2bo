import { MonitoringHistoryModal } from './MonitoringHistoryPanel';
import DispatchMonitorStatus from './DispatchMonitorStatus';
import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Descriptions, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from 'antd';
import { DeleteOutlined, ReloadOutlined, SettingOutlined } from '@ant-design/icons';
import { apiGet, apiJsonPost, apiPut, unwrapList } from '../lib/api';
import { getMonitorPort, rememberMonitorPort } from '../lib/monitorPortPreference';

type Probe = { id: number; name: string; enabled: boolean; version?: string };
type ProbeState = {
  probe_id: number; probe_name: string; online: boolean; stale: boolean;
  success: boolean | null; latency_ms: number | null; error: string;
  resolved_ip: string; reported_at: number | null;
};
type Entry = {
  host: string; user_ids: string[]; user_id_ranges: string[]; sources: string[];
  id: number; check_port: number; enabled: boolean; deleted: boolean; check_interval_sec: number;
  tcp_timeout_ms: number; probe_ids: number[]; states: ProbeState[];
};

const ENDPOINT = '/dns-failover/dispatch-entries';
const time = (value?: number | null) => value ? new Date(value * 1000).toLocaleString() : '—';
const rangeLabel = (value: string) => value === '1-9223372036854775807'
  ? '全部 ID' : value.replace(/-9223372036854775807$/, ' 及以上');
const scopeLabel = (entry: Entry) => [...entry.user_id_ranges.map(rangeLabel), ...entry.user_ids].join('、');

export default function DispatchMonitorPanel({ probes }: { probes: Probe[] }) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [calculatedAt, setCalculatedAt] = useState<number>();
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<React.Key[]>([]);
  const [showDeleted, setShowDeleted] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [historyHost, setHistoryHost] = useState<string>();
  const [editing, setEditing] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();
  const request = useRef(0);
  const alive = useRef(true);

  const load = async (quiet = false) => {
    const sequence = ++request.current;
    if (!quiet) setLoading(true);
    try {
      const response = await apiGet(ENDPOINT, { include_deleted: true });
      if (!alive.current || sequence !== request.current) return;
      const rows: Entry[] = unwrapList(response);
      setEntries(rows);
      setSelected(previous => previous.filter(host => rows.some(entry => entry.host === host)));
      setCalculatedAt(response.calculated_at);
      setError('');
    } catch (cause: any) {
      if (alive.current && sequence === request.current) setError(cause.message || '加载入口监控失败');
    } finally {
      if (alive.current && sequence === request.current) setLoading(false);
    }
  };

  useEffect(() => {
    alive.current = true;
    load();
    const timer = window.setInterval(() => load(true), 15000);
    return () => { alive.current = false; request.current++; window.clearInterval(timer); };
  }, []);

  const configure = (hosts: string[]) => {
    const entry = hosts.length === 1 ? entries.find(item => item.host === hosts[0]) : undefined;
    form.resetFields();
    form.setFieldsValue({
      check_port: entry?.id ? entry.check_port : getMonitorPort('entry'), enabled: entry?.enabled ?? true,
      check_interval_sec: entry?.check_interval_sec ?? 30, tcp_timeout_ms: entry?.tcp_timeout_ms ?? 3000,
      probe_ids: entry?.probe_ids ?? [],
    });
    setEditing(hosts);
  };

  const save = async () => {
    let value;
    try { value = await form.validateFields(); } catch { return; }
    setSaving(true);
    const failed: string[] = [];
    let failureMessage = '';
    for (const host of editing) {
      try { await apiPut(ENDPOINT, { host, ...value }); }
      catch (cause: any) { failed.push(host); failureMessage ||= cause.message || '请刷新后重试'; }
    }
    if (!alive.current) return;
    setSaving(false);
    if (failed.length) {
      setEditing(failed);
      message.error(`有 ${failed.length} 个入口保存失败：${failureMessage}。其余入口已保存`);
    } else {
      message.success(`已保存 ${editing.length} 个入口的监控配置`);
      setEditing([]);
    }
    load();
  };

  const remove = async (hosts: string[]) => {
    setDeleting(true);
    try {
      await apiJsonPost(`${ENDPOINT}/delete`, { hosts });
      if (!alive.current) return;
      // Invalidate any refresh started before the mutation completed.
      request.current++;
      setEntries(previous => previous.map(entry => hosts.includes(entry.host) ? { ...entry, deleted: true, enabled: false, probe_ids: [], states: [] } : entry));
      setSelected(previous => previous.filter(host => !hosts.includes(String(host))));
      message.success(`已删除 ${hosts.length} 个入口监控`);
      await load();
    } catch (cause: any) {
      if (alive.current) message.error(cause.message || '删除失败，请刷新后确认');
    } finally {
      if (alive.current) setDeleting(false);
    }
  };

  const visible = entries.filter(entry => !!entry.deleted === showDeleted && `${entry.host} ${scopeLabel(entry)} ${entry.sources.join(' ')}`.toLowerCase().includes(search.trim().toLowerCase()));
  const changeView = (deleted: boolean) => { setShowDeleted(deleted); setSelected([]); };

  return <>
    {historyHost && <MonitoringHistoryModal host={historyHost} source="entry" onClose={() => setHistoryHost(undefined)} />}
    <div style={{ padding: 16 }}>
      <Space wrap>
        <Input.Search allowClear value={search} onChange={event => setSearch(event.target.value)} placeholder="搜索入口、ID 范围或来源" style={{ width: 280 }} />
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => load()}>刷新入口与状态</Button>
        <Button type="primary" icon={<SettingOutlined />} disabled={!selected.length} onClick={() => configure(selected.map(String))}>批量配置{selected.length ? `（${selected.length}）` : ''}</Button>
        {!showDeleted && <Popconfirm title={`删除选中的 ${selected.length} 个入口监控？`} description="停止检测并移到已删除入口，可重新配置恢复；节点下发地址不变。" onConfirm={() => remove(selected.map(String))} disabled={!selected.length || selected.length > 500 || deleting}>
          <Button danger icon={<DeleteOutlined />} loading={deleting} disabled={!selected.length || selected.length > 500 || saving}>批量删除{selected.length ? `（${selected.length}）` : ''}</Button>
        </Popconfirm>}
        <Select aria-label="入口监控视图" value={showDeleted ? 'deleted' : 'active'} onChange={value => changeView(value === 'deleted')} options={[{ value: 'active', label: '入口监控' }, { value: 'deleted', label: `已删除入口（${entries.filter(entry => entry.deleted).length}）` }]} style={{ minWidth: 160 }} />
        <Typography.Text type="secondary">更新于 {time(calculatedAt)} · 每 15 秒刷新</Typography.Text>
      </Space>
      {error && <Alert type="error" showIcon message={error} description="当前显示可能是旧数据，请刷新后确认。" style={{ marginTop: 12 }} />}
    </div>
    <Table<Entry> rowKey="host" dataSource={visible} loading={loading} scroll={{ x: 1000 }}
      rowSelection={{ selectedRowKeys: selected, onChange: setSelected }}
      pagination={{ defaultPageSize: 20, showSizeChanger: true }}
      locale={{ emptyText: showDeleted ? '暂无已删除入口' : '暂无可监控的节点入口，可检查节点下发地址或已删除入口' }}
      expandable={{ expandedRowRender: entry => <div style={{ padding: '0 8px 8px' }}>
        <Descriptions size="small" column={1} items={[
          { key: 'users', label: '下发 ID / ID 范围', children: <span style={{ overflowWrap: 'anywhere' }}>{scopeLabel(entry)}</span> },
          { key: 'sources', label: '地址来源', children: entry.sources.join('；') },
        ]} />
        <Table<ProbeState> size="small" rowKey="probe_id" dataSource={entry.states} pagination={false} scroll={{ x: 760 }} locale={{ emptyText: '尚未选择探针' }} columns={[
          { title: '探针', dataIndex: 'probe_name' },
          { title: '状态', render: (_, state) => !entry.enabled ? <Tag>监控已停用</Tag> : !state.online ? <Tag>探针离线 / 已撤销</Tag> : state.stale ? <Tag color="warning">等待上报 / 数据过期</Tag> : <Tag color={state.success ? 'success' : 'error'}>{state.success ? '正常' : '异常'}</Tag> },
          { title: '延迟', render: (_, state) => !state.stale && state.latency_ms != null ? `${state.latency_ms} ms` : '—' },
          { title: '解析 IP', render: (_, state) => !state.stale ? state.resolved_ip || '—' : '—' },
          { title: '最近上报', render: (_, state) => time(state.reported_at) },
          { title: '错误', render: (_, state) => !state.stale ? state.error || '—' : '—' },
        ]} />
      </div> }}
      columns={[
        { title: '节点入口', dataIndex: 'host', width: 240, render: host => <Typography.Text copyable style={{ overflowWrap: 'anywhere' }}>{host}</Typography.Text> },
        { title: 'port', dataIndex: 'check_port', width: 80 },
        { title: '监控状态', width: 180, render: (_, entry) => <DispatchMonitorStatus entry={entry} /> },
        { title: '下发 ID / ID 范围', render: (_, entry) => <Typography.Paragraph ellipsis={{ rows: 2, expandable: true, symbol: '展开' }} style={{ margin: 0, minWidth: 200, maxWidth: 450 }}>{scopeLabel(entry)}</Typography.Paragraph> },
        { title: '探针', width: 90, render: (_, entry) => `${entry.states.filter(state => state.online).length} / ${entry.probe_ids.length}` },
        { title: '操作', width: 250, fixed: 'right', render: (_, entry) => <Space size={0}><Button type="link" onClick={() => setHistoryHost(entry.host)}>历史</Button>
          <Button type="link" icon={<SettingOutlined />} disabled={deleting} onClick={() => configure([entry.host])}>{entry.deleted ? '恢复配置' : '配置'}</Button>
          {!entry.deleted && <Popconfirm title={`删除 ${entry.host} 的入口监控？`} description="停止检测并移到已删除入口，可恢复；节点下发地址不变。" onConfirm={() => remove([entry.host])} disabled={deleting}>
            <Button danger type="link" icon={<DeleteOutlined />} disabled={deleting || saving}>删除</Button>
          </Popconfirm>}
        </Space> },
      ]} />
    <Modal open={!!editing.length} title={editing.length === 1 ? `入口监控 · ${editing[0]}` : `批量配置 ${editing.length} 个入口`} onCancel={() => !saving && setEditing([])}
      onOk={save} confirmLoading={saving} okText="保存" cancelText="取消" maskClosable={!saving} closable={!saving} forceRender>
      <Form form={form} layout="vertical" preserve={false}>
        <Form.Item name="check_port" label="探测 port" rules={[{ required: true, message: '请输入端口' }]}><InputNumber min={1} max={65535} precision={0} onChange={value => rememberMonitorPort('entry', value)} style={{ width: '100%' }} /></Form.Item>
        <Form.Item name="probe_ids" label="绑定探针" dependencies={['enabled']} rules={[({ getFieldValue }) => ({ validator: (_, ids) => getFieldValue('enabled') && !ids?.length ? Promise.reject(new Error('启用监控前请选择探针')) : Promise.resolve() })]}>
          <Select mode="multiple" placeholder="选择已部署的探针" options={probes.filter(probe => probe.enabled).map(probe => ({ value: probe.id, label: `${probe.name} (#${probe.id})` }))} />
        </Form.Item>
        <Form.Item name="check_interval_sec" label="检测间隔（秒）" rules={[{ required: true }]}><InputNumber min={1} max={86400} /></Form.Item>
        <Form.Item name="tcp_timeout_ms" label="TCP 超时（毫秒）" rules={[{ required: true }]}><InputNumber min={1} max={60000} /></Form.Item>
        <Form.Item name="enabled" label="启用监控" valuePropName="checked"><Switch /></Form.Item>
      </Form>
    </Modal>
  </>;
}
