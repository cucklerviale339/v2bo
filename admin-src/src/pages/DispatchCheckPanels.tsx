import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Form, Input, InputNumber, Modal, Pagination, Popconfirm, Space, Switch, Table, Tag, Typography, message } from 'antd';
import { CopyOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { apiDelete, apiGet, apiJsonPost, unwrapList } from '../lib/api';
import { copyText } from '../lib/clipboard';

const POOL = '/dns-failover/dispatch-pool';
const RUNS = '/dns-failover/dispatch-runs';
const stamp = (v?: number | null) => v ? new Date(v * 1000).toLocaleString() : '—';
type Scope = { host: string; user_ids?: string[]; user_id_ranges?: string[]; sources?: string[] };
export const dispatchScopeText = (s?: Scope) => [...(s?.user_id_ranges || []).map(v => v === '1-9223372036854775807' ? '全部 ID' : v.replace(/-9223372036854775807$/, ' 及以上')), ...(s?.user_ids || [])].join('、') || '当前无下发 ID';
type State = { probe_id: number; probe_name: string; online: boolean; stale: boolean; success: boolean | null; latency_ms: number | null; error: string; resolved_ip: string; reported_at: number | null; consecutive_success: number };
type Pool = { id: number; name: string; ip: string; port: number; enabled: boolean; check_interval_sec: number; tcp_timeout_ms: number; sort: number; status: string; available: boolean; used: boolean; references: string[]; ownership: Scope; states: State[] };
type Run = { id: number; status: string; created_at: number; deadline_at: number; completed_at: number | null; expected: number; received: number; failed: number };
type Result = State & { target_id: number; name: string; port: number; ownership: Scope };
const statusLabels: Record<string, string> = { available: '可用', in_use: '有配置引用', disabled: '已停用', no_probe: '暂无启用探针', probe_offline: '探针全部离线', unhealthy: '故障', checking: '检测中' };
const addr = (host: string, port: number) => `${host.includes(':') ? `[${host}]` : host}:${port}`;
const errorText = (e: any) => e?.message || '操作失败，请重试';
const successTag = (value: boolean | null) => value == null ? <Tag>等待结果</Tag> : <Tag color={value ? 'success' : 'error'}>{value ? '成功' : '失败'}</Tag>;

export function DispatchPoolPanel({ active }: { active: boolean }) {
 const [items, setItems] = useState<Pool[]>([]);
 const [selected, setSelected] = useState<React.Key[]>([]);
 const [loading, setLoading] = useState(false);
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState('');
 const [search, setSearch] = useState('');
 const [batch, setBatch] = useState(false);
 const [editing, setEditing] = useState<Pool | null>(null);
 const [form] = Form.useForm();
 const [batchForm] = Form.useForm();
 const generation = useRef(0);
 const load = async (quiet = false) => {
  const seq = ++generation.current; if (!quiet) setLoading(true);
  try { const next: Pool[] = unwrapList(await apiGet(POOL)); if (seq !== generation.current) return; setItems(next); setSelected(old => old.filter(id => next.some(p => p.id === id))); setError(''); }
  catch (e) { if (seq === generation.current) setError(errorText(e)); }
  finally { if (seq === generation.current) setLoading(false); }
 };
 useEffect(() => { if (!active) return; void load(); const timer = window.setInterval(() => void load(true), 10000); return () => { clearInterval(timer); generation.current++; }; }, [active]);
 const action = async (fn: () => Promise<any>, label: string) => { setBusy(true); try { await fn(); message.success(label); await load(true); } catch (e) { message.error(errorText(e)); } finally { setBusy(false); } };
 const deleteFaulty = () => {
  const candidates = items.filter(p => p.status === 'unhealthy' && !p.used);
  if (!candidates.length) return;
  const candidateIDs = new Set(candidates.map(p => p.id));
  Modal.confirm({
   title: `删除 ${candidates.length} 条故障 IP 记录？`,
   content: '范围为整个备用 IP 池，不受搜索和勾选影响。仅删除故障且无配置引用的记录；正常、检测中、已停用及探针离线的记录保留。同一 IP 的其他端口记录独立判断。',
   okText: '删除故障 IP', cancelText: '取消', okButtonProps: { danger: true },
   onOk: async () => {
    setBusy(true); let deleted = 0;
    try {
     // Recheck after confirmation so recovered or newly referenced rows survive.
     const current: Pool[] = unwrapList(await apiGet(POOL));
     const ids = current.filter(p => candidateIDs.has(p.id) && p.status === 'unhealthy' && !p.used).map(p => p.id);
     for (let i = 0; i < ids.length; i += 500) {
      const result = await apiJsonPost(`${POOL}/delete-faulty`, { ids: ids.slice(i, i + 500) });
      deleted += Number(result.data?.deleted) || 0;
     }
     message.success(deleted ? `已删除 ${deleted} 条故障 IP 记录` : '当前没有可删除的故障 IP，状态已更新');
    } catch (e) {
     message.error(`${deleted ? `已删除 ${deleted} 条；` : ''}${errorText(e)}`);
     throw e;
    } finally { await load(true); setBusy(false); }
   },
  });
 };
 const saveBatch = async () => {
  let values: any; try { values = await batchForm.validateFields(); } catch { return; }
  const rows = String(values.lines).split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!rows.length || rows.length > 500) { message.error('每次请输入 1 至 500 行'); return; }
  const parsed: any[] = [];
  for (const [i, line] of rows.entries()) {
   const [first, ...rest] = line.split(/\s+/); let ip = first, port = values.port;
   const joined = first.match(/^\[([^\]]+)\]:(\d+)$/) || first.match(/^([^:]+):(\d+)$/);
   if (joined) { ip = joined[1]; port = Number(joined[2]); }
   else if (first.startsWith('[') && first.endsWith(']')) ip = first.slice(1, -1);
   if (rest.length && /^\d+$/.test(rest[0])) port = Number(rest.shift());
   if (port < 1 || port > 65535) { message.error(`第 ${i + 1} 行端口无效`); return; }
   parsed.push({ ip, port, name: rest.join(' ') || ip, enabled: true, check_interval_sec: values.check_interval_sec, tcp_timeout_ms: values.tcp_timeout_ms, sort: 0 });
  }
  await action(async () => { await apiJsonPost(POOL, { items: parsed }); setBatch(false); batchForm.resetFields(); }, `已添加 ${parsed.length} 个备用资源，等待探针测活`);
 };
 const saveEdit = async () => {
  let values: any; try { values = await form.validateFields(); } catch { return; }
  if (!editing) return;
  const { id, ip, port } = editing;
  await action(async () => { await apiJsonPost(POOL, { items: [{ id, ip, port, ...values }] }); setEditing(null); }, '已保存，等待重新测活');
 };
 const copyAvailable = async () => {
  const ips = [...new Set(items.filter(p => p.available).map(p => p.ip))];
  if (!ips.length) { message.warning('当前没有可用 IP'); return; }
  const text = ips.join('\n');
  try { await copyText(text); message.success(`已复制 ${ips.length} 个可用 IP`); }
  catch { Modal.info({ title: '浏览器未允许自动复制，请选择下方 IP 手动复制', content: <Input.TextArea readOnly value={text} autoSize={{ minRows: 3, maxRows: 12 }} onFocus={event => event.target.select()} />, okText: '关闭' }); }
 };
 const states = (p: Pool) => <Table<State> size="small" rowKey="probe_id" dataSource={p.states} pagination={false} scroll={{ x: 800 }} columns={[
  { title: '探针', dataIndex: 'probe_name' },
  { title: '状态', render: (_, s) => !p.enabled ? <Tag>停用</Tag> : !s.online ? <Tag>离线</Tag> : s.stale ? <Tag color="warning">等待 / 数据过期</Tag> : successTag(s.success) },
  { title: '连续成功', render: (_, s) => !s.stale ? s.consecutive_success : '—' },
  { title: '延迟', render: (_, s) => !s.stale && s.latency_ms != null ? `${s.latency_ms} ms` : '—' },
  { title: '最近上报', render: (_, s) => stamp(s.reported_at) },
  { title: '错误', render: (_, s) => !s.stale ? s.error || '—' : '—' },
 ]} locale={{ emptyText: '暂无启用探针，请先部署探针' }} />;
 const visible = items.filter(p => `${p.ip} ${p.name} ${p.port} ${dispatchScopeText(p.ownership)} ${p.references.join(' ')}`.toLowerCase().includes(search.trim().toLowerCase()));
 return <div style={{ padding: 16 }}>
  <Alert showIcon type="info" message="备用 IP 持续测活" description="按 IP＋port 管理；所有在线启用探针均有新鲜结果并连续成功 2 次，且没有地址配置引用时，才标记可用。离线探针不参与通过条件。每枚探针最多启用 1000 个入口及备用池目标，备用池使用全部启用探针。" />
  <Space wrap style={{ margin: '14px 0' }}>
   <Tag>共 {items.length}</Tag><Tag color="success">可用 {items.filter(p => p.available).length}</Tag><Tag color="blue">有引用 {items.filter(p => p.used).length}</Tag>
   <Button type="primary" icon={<PlusOutlined />} disabled={busy} onClick={() => { batchForm.setFieldsValue({ port: 443, check_interval_sec: 30, tcp_timeout_ms: 3000 }); setBatch(true); }}>批量添加</Button>
   <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>刷新</Button>
   <Button icon={<CopyOutlined />} disabled={!items.some(p => p.available)} onClick={() => void copyAvailable()}>复制可用 IP</Button>
   <Button disabled={!selected.length || busy || selected.some(id => !items.find(p => p.id === id)?.enabled)} onClick={() => action(() => apiJsonPost(`${POOL}/refresh`, { ids: selected }), '已清除旧状态，等待重新测活')}>重新测活所选</Button>
   <Popconfirm title="删除所选备用资源及测活状态？" description="有配置引用的资源不能删除；本轮删除会整体取消。" onConfirm={() => action(() => apiJsonPost(`${POOL}/delete`, { ids: selected }), '已删除所选资源')}><Button danger disabled={!selected.length || busy || selected.some(id => items.find(p => p.id === id)?.used)}>删除所选</Button></Popconfirm>
   <Button danger disabled={busy || loading || !!error || !items.some(p => p.status === 'unhealthy' && !p.used)} onClick={deleteFaulty}>删除故障 IP</Button>
   <Input.Search allowClear placeholder="搜索 IP、port、名称、ID 或来源" value={search} onChange={e => setSearch(e.target.value)} style={{ width: 280 }} />
  </Space>
  {error && <Alert type="error" showIcon message={error} description="当前可能显示旧数据，请刷新后确认。" style={{ marginBottom: 12 }} />}
  <Table<Pool> size="small" rowKey="id" loading={loading} dataSource={visible} scroll={{ x: 1200 }} rowSelection={{ selectedRowKeys: selected, onChange: setSelected }} pagination={{ defaultPageSize: 20, showSizeChanger: true }} expandable={{ expandedRowRender: p => <>
   <Typography.Paragraph>配置引用（含停用配置，仅按字面 IP）：{p.references.join('；') || '无'}</Typography.Paragraph>
   <Typography.Paragraph>当前下发 ID / 范围：{dispatchScopeText(p.ownership)}</Typography.Paragraph>
   <Typography.Paragraph type="secondary">当前下发来源：{p.ownership.sources?.join('；') || '无'}</Typography.Paragraph>{states(p)}
  </> }} columns={[
   { title: '名称 / 地址', width: 250, render: (_, p) => <><strong>{p.name}</strong><div><Typography.Text copyable>{addr(p.ip, p.port)}</Typography.Text></div></> },
   { title: '状态', width: 150, render: (_, p) => <Tag color={p.available ? 'success' : p.status === 'unhealthy' ? 'error' : 'default'}>{statusLabels[p.status] || p.status}</Tag> },
   { title: '在线 / 启用探针', width: 135, render: (_, p) => `${p.states.filter(s => s.online).length} / ${p.states.length}` },
   { title: '下发 ID / ID 范围', render: (_, p) => <Typography.Paragraph ellipsis={{ rows: 2, expandable: true }} style={{ maxWidth: 400, margin: 0 }}>{dispatchScopeText(p.ownership)}</Typography.Paragraph> },
   { title: '检测策略', width: 165, render: (_, p) => `${p.check_interval_sec}s / ${p.tcp_timeout_ms}ms` },
   { title: '排序', dataIndex: 'sort', width: 65 },
   { title: '操作', fixed: 'right', width: 170, render: (_, p) => <Space><Button type="link" disabled={busy} onClick={() => { form.setFieldsValue(p); setEditing(p); }}>编辑</Button><Button type="link" disabled={busy || !p.enabled} onClick={() => action(() => apiJsonPost(`${POOL}/refresh`, { ids: [p.id] }), '已提交重新测活')}>重新测活</Button></Space> },
  ]} locale={{ emptyText: '暂无备用资源，点击批量添加' }} />
  <Modal open={batch} title="批量添加备用 IP" confirmLoading={busy} closable={!busy} maskClosable={!busy} onCancel={() => setBatch(false)} onOk={saveBatch} okText="添加">
   <Form form={batchForm} layout="vertical"><Form.Item name="lines" label="每行：IP [端口] [名称]" rules={[{ required: true, message: '请输入备用 IP' }]} extra="支持 IPv4、IPv6、IPv4:port 和 [IPv6]:port；省略端口时使用下方默认值。重复 IP＋port 会使整批添加取消。"><Input.TextArea rows={7} placeholder={'192.0.2.10 443 备用一\n[2001:db8::10]:8443 备用二'} /></Form.Item><Form.Item name="port" label="默认 port" rules={[{ required: true }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item><Form.Item name="check_interval_sec" label="检测间隔（秒）" rules={[{ required: true }]}><InputNumber min={5} max={3600} precision={0} /></Form.Item><Form.Item name="tcp_timeout_ms" label="TCP 超时（毫秒）" rules={[{ required: true }]}><InputNumber min={100} max={60000} precision={0} /></Form.Item></Form>
  </Modal>
  <Modal open={!!editing} title={`编辑备用资源 · ${editing ? addr(editing.ip, editing.port) : ''}`} confirmLoading={busy} closable={!busy} maskClosable={!busy} onCancel={() => setEditing(null)} onOk={saveEdit}>
   <Form form={form} layout="vertical"><Form.Item name="name" label="名称" rules={[{ required: true }, { max: 255 }]}><Input /></Form.Item><Form.Item name="port" label="探测 port" rules={[{ required: true }]}><InputNumber min={1} max={65535} precision={0} /></Form.Item><Form.Item name="enabled" label="启用测活" valuePropName="checked"><Switch /></Form.Item><Form.Item name="check_interval_sec" label="检测间隔（秒）" rules={[{ required: true }]}><InputNumber min={5} max={3600} precision={0} /></Form.Item><Form.Item name="tcp_timeout_ms" label="TCP 超时（毫秒）" rules={[{ required: true }]}><InputNumber min={100} max={60000} precision={0} /></Form.Item><Form.Item name="sort" label="排序（越小越靠前）" rules={[{ required: true }]}><InputNumber min={0} max={2147483647} precision={0} /></Form.Item></Form>
  </Modal>
 </div>;
}

function RunResults({ runID, active }: { runID: number; active: boolean }) {
 const [rows, setRows] = useState<Result[]>([]), [page, setPage] = useState(1), [total, setTotal] = useState(0), [error, setError] = useState('');
 useEffect(() => { if (!active) return; let alive = true; const load = async () => { try { const r = await apiGet(`${RUNS}/${runID}`, { page }); if (alive) { setRows(unwrapList(r)); setTotal(r.total); setError(''); } } catch (e) { if (alive) setError(errorText(e)); } }; void load(); const timer = window.setInterval(load, 5000); return () => { alive = false; clearInterval(timer); }; }, [runID, page, active]);
 return <>{error && <Alert type="error" message={error} />}<Table<Result> size="small" rowKey={r => `${r.target_id}-${r.probe_id}`} dataSource={rows} pagination={false} scroll={{ x: 1250 }} columns={[
  { title: '目标快照', width: 240, render: (_, r) => <><strong>{r.name}</strong><div>{addr(r.ownership.host, r.port)}</div></> },
  { title: '下发 ID / 范围快照', width: 260, render: (_, r) => <Typography.Paragraph style={{ margin: 0 }} ellipsis={{ rows: 2, expandable: true }}>{dispatchScopeText(r.ownership)}</Typography.Paragraph> },
  { title: '探针', dataIndex: 'probe_name', width: 140 },
  { title: '结果', render: (_, r) => successTag(r.success), width: 90 },
  { title: '延迟', width: 90, render: (_, r) => r.latency_ms != null ? `${r.latency_ms} ms` : '—' },
  { title: '解析 IP / 错误', width: 170, render: (_, r) => <>{r.resolved_ip || '—'}{r.error && <div style={{ color: '#cf1322' }}>{r.error}</div>}</> },
  { title: '上报时间', width: 180, render: (_, r) => stamp(r.reported_at) },
 ]} expandable={{ expandedRowRender: r => <Typography.Paragraph>当时下发来源：{r.ownership.sources?.join('；') || '无'}</Typography.Paragraph> }} /><Pagination current={page} pageSize={100} total={total} showSizeChanger={false} onChange={setPage} showTotal={n => `共 ${n} 份结果，等待结果也列出`} style={{ marginTop: 12 }} /></>;
}

export function DispatchRunsPanel({ active }: { active: boolean }) {
 const [rows, setRows] = useState<Run[]>([]), [page, setPage] = useState(1), [total, setTotal] = useState(0), [error, setError] = useState(''), [clearing, setClearing] = useState(false);
 const refresh = useRef<() => void>(() => {});
 useEffect(() => { if (!active) return; let alive = true; let seq = 0; const load = async () => { const n = ++seq; try { const r = await apiGet(RUNS, { page }); if (alive && n === seq) { setRows(unwrapList(r)); setTotal(r.total); setError(''); } } catch (e) { if (alive && n === seq) setError(errorText(e)); } }; refresh.current = () => void load(); void load(); const timer = window.setInterval(load, 5000); return () => { alive = false; clearInterval(timer); }; }, [page, active]);
 const clear = async () => { setClearing(true); try { await apiDelete(RUNS); message.success('已清理结束的任务'); if (page === 1) refresh.current(); else setPage(1); } catch (e) { message.error(errorText(e)); } finally { setClearing(false); } };
 return <div style={{ padding: 16 }}><Alert showIcon type="info" message="历史检测记录保留 7 天" description="此处查看已有检测任务的地址、port、探针及下发 ID 归属快照。主动检测入口已移除；持续监控和重新测活的结果在入口监控及备用 IP 池中查看。" />
  <Space style={{ margin: '14px 0' }}><Button icon={<ReloadOutlined />} onClick={() => refresh.current()}>刷新</Button><Popconfirm title="清理全部已结束的任务？" description="正在执行的任务会保留。" onConfirm={clear}><Button danger loading={clearing}>清理记录</Button></Popconfirm></Space>
  {error && <Alert type="error" message={error} />}
  <Table<Run> size="small" rowKey="id" dataSource={rows} pagination={false} scroll={{ x: 900 }} expandable={{ expandedRowRender: r => <RunResults runID={r.id} active={active} /> }} columns={[
   { title: '任务', render: (_, r) => `#${r.id}`, width: 90 },
   { title: '状态', render: (_, r) => <Tag color={r.status === 'running' ? 'processing' : r.status === 'timeout' ? 'warning' : 'default'}>{{ running: '进行中', completed: '已完成', timeout: '已超时' }[r.status] || r.status}</Tag>, width: 110 },
   { title: '进度', render: (_, r) => `${r.received} / ${r.expected}`, width: 130 },
   { title: '结果', render: (_, r) => <Space><Tag color="success">成功 {r.received - r.failed}</Tag><Tag color={r.failed ? 'error' : 'default'}>失败 {r.failed}</Tag><Tag>未返回 {r.expected - r.received}</Tag></Space> },
   { title: '发起时间', render: (_, r) => stamp(r.created_at), width: 180 },
   { title: '结束时间', render: (_, r) => stamp(r.completed_at), width: 180 },
  ]} locale={{ emptyText: '暂无主动检测任务' }} /><Pagination current={page} pageSize={20} total={total} showSizeChanger={false} onChange={setPage} style={{ marginTop: 14 }} />
 </div>;
}
