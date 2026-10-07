import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Input, Modal, Select, Space, Table, Tag, Typography, message } from 'antd';
import { apiGet, apiPost } from '../lib/api';
import SubscribeIPIntelligence, { IPIntelligence } from './SubscribeIPIntelligence';

type Entry = { id: number; revision: number; assessed_at: number; status: string; note: string; reviewed_by: number; reviewed_at: number; review_source: number; cooldown_until: number; profile: { user_id: number; email: string; token_hash: string; score: number; last_at: number; ua: string; intelligence: IPIntelligence; factors: { label: string; points: number }[]; metrics: Record<string, number> } };
type Result = { data: Entry[]; total: number; current: number; page_size: number };
const endpoint = '/subscribe-access/guard/';
const statusNames: Record<string, string> = { pending: '待复核', handled: '已处理', false_positive: '误报', suppressed: '误报冷却记录' };
const dateText = (value: number) => value ? new Date(value * 1000).toLocaleString() : '-';

export default function SubscribeRiskHistory({ onUserSelect }: { onUserSelect: (id: number) => void }) {
  const [result, setResult] = useState<Result | null>(null);
  const [keyword, setKeyword] = useState('');
  const [status, setStatus] = useState('');
  const [applied, setApplied] = useState({ keyword: '', status: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [detail, setDetail] = useState<Entry | null>(null);
  const [decision, setDecision] = useState('handled');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const sequence = useRef(0);
  const load = async (current = 1, filter = { keyword: keyword.trim(), status }) => {
    const request = ++sequence.current;
    setLoading(true);
    try { const response = await apiGet(endpoint + 'risk-history', { ...filter, current, page_size: 20 }); if (request === sequence.current) { setResult(response.data); setApplied(filter); setError(''); } }
    catch (failure: any) { if (request === sequence.current) { setResult(null); setError(failure.message || '风险历史查询失败'); } }
    finally { if (request === sequence.current) setLoading(false); }
  };
  useEffect(() => { load(); return () => { sequence.current++; }; }, []);
  const save = async () => {
    if (!detail || !note.trim()) { message.info('请填写复核说明'); return; }
    setSaving(true);
    try { await apiPost(endpoint + 'risk-review', { id: detail.id, revision: detail.revision, status: decision, note: note.trim() }); setDetail(null); await load(result?.current || 1, applied); message.success('复核结果已保存'); }
    catch (failure: any) { message.error(failure.message); }
    finally { setSaving(false); }
  };
  return <Card title="高风险历史与复核" style={{ marginTop: 16 }}>
    <Space wrap style={{ marginBottom: 12 }}><Input value={keyword} maxLength={255} onChange={event => setKeyword(event.target.value)} onPressEnter={() => load()} placeholder="用户 ID、邮箱、IP 或完整 Token 指纹" style={{ width: 320 }} /><Select value={status} onChange={setStatus} style={{ width: 140 }} options={[{ value: '', label: '全部状态' }, ...Object.entries(statusNames).map(([value, label]) => ({ value, label }))]} /><Button loading={loading} onClick={() => load()}>查询历史</Button></Space>
    <Typography.Paragraph type="secondary">每分钟评估最近 24 小时行为，保存 60 分及以上快照，保留 30 天；同一对象、同一小时、同一分数去重。定期采样可能漏掉短暂高分。标记误报后，同一对象、来源与评分原因完全相同的记录在 24 小时内归为冷却记录，仍保存快照；不改变实时评分、封禁或解除限制。</Typography.Paragraph>
    {error && <Alert type="error" showIcon message={error} />}
    <Table rowKey="id" size="small" loading={loading} dataSource={result?.data || []} scroll={{ x: 1050 }} pagination={{ current: result?.current || 1, total: result?.total || 0, pageSize: 20, showSizeChanger: false, onChange: current => load(current, applied) }} columns={[
      { title: '评估时间', dataIndex: 'assessed_at', width: 175, render: dateText },
      { title: '用户', render: (_: any, row: Entry) => row.profile.user_id ? <Typography.Link onClick={() => onUserSelect(row.profile.user_id)}>{row.profile.email || `#${row.profile.user_id}`}</Typography.Link> : '未识别用户' },
      { title: '分数', width: 90, render: (_: any, row: Entry) => <Tag color={row.profile.score >= 80 ? 'red' : 'orange'}>{row.profile.score}</Tag> },
      { title: '状态', dataIndex: 'status', width: 100, render: value => statusNames[value] || value },
      { title: '复核人 / 时间', width: 210, render: (_: any, row: Entry) => row.review_source ? `依据误报记录 #${row.review_source}` : row.reviewed_by ? `#${row.reviewed_by} · ${dateText(row.reviewed_at)}` : '-' },
      { title: '说明', dataIndex: 'note', ellipsis: true },
      { title: '操作', width: 110, render: (_: any, row: Entry) => <Button size="small" onClick={() => { setDetail(row); setNote(''); setDecision('handled'); }}>查看 / 复核</Button> },
    ]} />
    <Modal open={!!detail} title="风险历史快照" width={850} maskClosable={!saving} closable={!saving} onCancel={() => !saving && setDetail(null)} footer={<Space>{detail?.status === 'pending' && <Button type="primary" loading={saving} onClick={save}>保存复核结果</Button>}<Button disabled={saving} onClick={() => setDetail(null)}>关闭</Button></Space>} destroyOnClose>
      {detail && <Space direction="vertical" style={{ width: '100%' }} size="middle">
        <Typography.Text>{detail.profile.email || `用户 #${detail.profile.user_id}`} · {detail.profile.score} 分 · 评估于 {dateText(detail.assessed_at)} · 最近请求 {dateText(detail.profile.last_at)}</Typography.Text>
        <Typography.Text copyable={{ text: detail.profile.token_hash }} style={{ overflowWrap: 'anywhere' }}>Token 指纹：{detail.profile.token_hash || '登录态入口'}</Typography.Text>
        <SubscribeIPIntelligence value={detail.profile.intelligence} />
        <Typography.Text type="secondary">情报与原因均为评估时保存的结果，不代表当前风险。</Typography.Text>
        {!!detail.cooldown_until && <Alert type="info" message={detail.review_source ? `依据误报记录 #${detail.review_source}，此次快照无需重复复核` : '相同来源和评分原因冷却 24 小时'} description={`冷却截止：${dateText(detail.cooldown_until)}。仅影响重复复核，已有规则继续执行；不同来源、分数或原因不匹配此冷却。`} />}
        {detail.profile.factors.map(factor => <Typography.Text key={factor.label}>{factor.label}：+{factor.points} 分</Typography.Text>)}
        <Typography.Text style={{ overflowWrap: 'anywhere' }}>UA：{detail.profile.ua || '空'}</Typography.Text>
        {detail.status === 'pending' ? <><Select value={decision} onChange={setDecision} disabled={saving} options={[{ value: 'handled', label: '已处理' }, { value: 'false_positive', label: '误报（相同原因冷却 24 小时）' }]} />{decision === 'false_positive' && <Typography.Text type="secondary">确认误报后，匹配的重复快照仍保留，但 24 小时内不重复进入待复核列表。</Typography.Text>}<Input.TextArea value={note} onChange={event => setNote(event.target.value)} maxLength={500} showCount rows={3} disabled={saving} placeholder="填写核查结果或处理说明；不在此处修改封禁规则" /></> : detail.status !== 'suppressed' && <Alert type="info" message={`${statusNames[detail.status]} · 管理员 #${detail.reviewed_by} · ${dateText(detail.reviewed_at)}`} description={detail.note} />}
      </Space>}
    </Modal>
  </Card>;
}
