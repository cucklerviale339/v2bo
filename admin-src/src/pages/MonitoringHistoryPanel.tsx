import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Collapse, DatePicker, Input, InputNumber, Modal, Pagination, Select, Space, Table, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { apiGet } from '../lib/api';

type Scope = { user_ids?: string[]; user_id_ranges?: string[]; sources?: string[] };
type Record = {
 id: number; source: 'entry' | 'pool'; host: string; port: number; name: string;
 probe_id: number; probe_name: string; success: boolean; latency_ms: number | null;
 error: string; resolved_ip: string; reported_at: number; created_at: number;
 event_type: string; ownership: Scope; ownership_known: boolean; status: string;
};
type Props = { active: boolean; mode?: 'history' | 'logs' | 'events'; host?: string; source?: 'entry' | 'pool'; dnsContent?: React.ReactNode; legacyContent?: React.ReactNode };
const stamp = (v: number) => new Date(v * 1000).toLocaleString();
const address = (host: string, port: number) => `${host.includes(':') ? `[${host}]` : host}:${port}`;
const scopeText = (scope: Scope) => [...(scope.user_id_ranges || []).map(v => v === '1-9223372036854775807' ? '全部 ID' : v.replace(/-9223372036854775807$/, ' 及以上')), ...(scope.user_ids || [])].join('、') || '当时无下发 ID';

export default function MonitoringHistoryPanel({ active, mode = 'history', host: fixedHost, source: fixedSource, dnsContent, legacyContent }: Props) {
 const [rows, setRows] = useState<Record[]>([]), [page, setPage] = useState(1), [total, setTotal] = useState(0);
 const [source, setSource] = useState<string>(fixedSource || ''), [host, setHost] = useState(fixedHost || ''), [draft, setDraft] = useState(fixedHost || '');
 const [port, setPort] = useState<number | null>(null);
 const [probe, setProbe] = useState<number | null>(null), [success, setSuccess] = useState<string>(), [eventType, setEventType] = useState<string>();
 const [range, setRange] = useState<[number, number] | undefined>(), [error, setError] = useState(''), [warning, setWarning] = useState('');
 const [loading, setLoading] = useState(false), [revision, setRevision] = useState(0);
 const request = useRef(0);
 const kind = mode === 'events' ? 'event' : 'sample';
 useEffect(() => {
  if (!active || source === 'dns') return;
  let alive = true;
  const load = async (quiet = false) => {
   const seq = ++request.current;
   if (!quiet) setLoading(true);
   try {
    const result = await apiGet('/dns-failover/dispatch-history', { kind, page, source: source || undefined, host: host || undefined, port: port || undefined, probe_id: probe || undefined, success, event_type: eventType, from: range?.[0], to: range?.[1] });
    if (!alive || seq !== request.current) return;
    setRows(result.data || []); setTotal(result.total || 0); setWarning(result.writer_error || ''); setError('');
   } catch (cause: any) { if (alive && seq === request.current) setError(cause.message || '检测记录加载失败'); }
   finally { if (alive && seq === request.current) setLoading(false); }
  };
  void load(); const timer = window.setInterval(() => void load(true), 10000);
  return () => { alive = false; request.current++; window.clearInterval(timer); };
 }, [active, source, host, port, probe, success, eventType, range, page, revision, kind]);
 const changed = (fn: () => void) => { fn(); setPage(1); };
 return <div style={{ padding: 16 }}>
  <Space wrap style={{ marginBottom: 14 }}>
   {!fixedSource && <Select aria-label="记录来源" value={source} style={{ width: 185 }} onChange={v => changed(() => setSource(v))} options={[{ value: '', label: '入口监控和备用 IP 池' }, { value: 'entry', label: '入口监控' }, { value: 'pool', label: '备用 IP 池' }, ...(dnsContent ? [{ value: 'dns', label: 'DNS 切换' }] : [])]} />}
   {source !== 'dns' && <>
    {!fixedHost && <Input.Search aria-label="检测地址" placeholder="完整检测地址，不含端口" allowClear value={draft} onChange={e => setDraft(e.target.value)} onSearch={v => changed(() => setHost(v.trim()))} style={{ width: 250 }} />}
    <InputNumber aria-label="检测端口" placeholder="检测端口" min={1} max={65535} precision={0} value={port} onChange={v => changed(() => setPort(v))} />
    <InputNumber aria-label="探针 ID" placeholder="探针 ID" min={1} precision={0} value={probe} onChange={v => changed(() => setProbe(v))} />
    <Select aria-label="检测结果" allowClear placeholder="全部结果" value={success} onChange={v => changed(() => setSuccess(v))} style={{ width: 125 }} options={[{ value: 'true', label: '检测成功' }, { value: 'false', label: '检测失败' }]} />
    {kind === 'event' && <Select aria-label="事件类型" allowClear placeholder="全部事件" value={eventType} onChange={v => changed(() => setEventType(v))} style={{ width: 125 }} options={[{ value: 'down', label: '检测故障' }, { value: 'recovered', label: '检测恢复' }]} />}
    <DatePicker.RangePicker showTime onChange={v => changed(() => setRange(v?.[0] && v?.[1] ? [v[0].unix(), v[1].unix()] : undefined))} />
    <Button icon={<ReloadOutlined />} onClick={() => setRevision(v => v + 1)} loading={loading}>刷新</Button>
   </>}
  </Space>
  {source === 'dns' ? dnsContent : <>
   {warning && <Alert showIcon type="warning" message={warning} style={{ marginBottom: 12 }} />}
   {error && <Alert showIcon type="error" message={error} description="以下可能是上次加载的数据，请刷新后确认。" style={{ marginBottom: 12 }} />}
   <Table<Record> size="small" loading={loading} rowKey="id" dataSource={rows} pagination={false} scroll={{ x: 1450 }} columns={[
    { title: '时间', width: 175, render: (_, row) => stamp(row.created_at) },
    { title: '来源', width: 105, render: (_, row) => row.source === 'entry' ? '入口监控' : '备用 IP 池' },
    { title: '检测地址 / 端口', width: 240, render: (_, row) => <><strong>{row.name}</strong><div><Typography.Text copyable>{address(row.host, row.port)}</Typography.Text></div></> },
    { title: '探针', width: 155, render: (_, row) => `${row.probe_name} (#${row.probe_id})` },
    { title: kind === 'event' ? '事件' : '检测结果', width: 115, render: (_, row) => kind === 'event' ? <Tag color={row.event_type === 'down' ? 'error' : 'success'}>{row.event_type === 'down' ? '检测故障' : '检测恢复'}</Tag> : <Tag color={row.success ? 'success' : 'error'}>{row.success ? '成功' : '失败'}</Tag> },
    { title: '延迟', width: 90, render: (_, row) => row.latency_ms == null ? '—' : `${row.latency_ms} ms` },
    { title: '解析 IP / 错误', width: 210, render: (_, row) => <>{row.resolved_ip || '—'}{row.error && <div style={{ color: '#cf1322' }}>{row.error}</div>}</> },
    { title: '下发 ID / 范围快照', width: 285, render: (_, row) => row.ownership_known ? <Typography.Paragraph style={{ margin: 0 }} ellipsis={{ rows: 2, expandable: true }}>{scopeText(row.ownership)}</Typography.Paragraph> : <Tag color="warning">归属快照暂不可用</Tag> },
   ]} expandable={{ expandedRowRender: row => <Typography.Paragraph>当时下发来源：{row.ownership_known ? row.ownership.sources?.join('；') || '无' : '快照暂不可用'}</Typography.Paragraph> }} locale={{ emptyText: error ? '记录读取失败' : '暂无记录' }} />
   <Pagination current={page} pageSize={50} total={total} showSizeChanger={false} showTotal={v => `共 ${v} 条`} onChange={setPage} style={{ marginTop: 14 }} />
   {legacyContent && <Collapse style={{ marginTop: 18 }} items={[{ key: 'legacy', label: '旧版主动检测任务记录', children: legacyContent }]} />}
  </>}
 </div>;
}

export function MonitoringHistoryModal({ host, source, onClose }: { host: string; source: 'entry' | 'pool'; onClose: () => void }) {
 return <Modal open title={`检测历史 · ${host}`} width={1350} footer={null} onCancel={onClose} destroyOnHidden><MonitoringHistoryPanel active host={host} source={source} /></Modal>;
}
