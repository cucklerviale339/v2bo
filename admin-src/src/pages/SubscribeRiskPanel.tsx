import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Descriptions, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { apiGet } from '../lib/api';
import SubscribeIPIntelligence, { IPIntelligence } from './SubscribeIPIntelligence';
import SubscribeMonitorStatus from './SubscribeMonitorStatus';
import SubscribeRiskHistory from './SubscribeRiskHistory';

const endpoint = '/subscribe-access/guard/';
const levels: Record<string, [string, string]> = { critical: ['严重', 'red'], high: ['高', 'volcano'], medium: ['中', 'gold'], mild: ['轻度', 'blue'], low: ['低', 'green'] };
const dateText = (value: number) => value ? new Date(value * 1000).toLocaleString() : '-';
type Filter = { keyword: string; min_score: number };
type Factor = { label: string; points: number };
type Profile = {
  subject: string; token_hash: string; user_id: number; email: string; last_at: number; ip: string; ua: string;
  status: number; blocked: boolean; ua_whitelisted: boolean; score: number; level: string; review: boolean; factors: Factor[];
  intelligence?: IPIntelligence;
  metrics: { requests_24h: number; requests_1h: number; ips_24h: number; ips_10m: number; ips_30m: number; uas_24h: number; ua_changes_24h: number; errors_24h: number; server_errors_24h: number; blocked_24h: number; resolved_ips: number; asns_24h: number; countries_24h: number };
};
type Result = { data: Profile[]; total: number; subjects: number; review: number; current: number; page_size: number; assessed_at: number; dropped: number };

export default function SubscribeRiskPanel({ onUserSelect, onRule }: { onUserSelect: (id: number) => void; onRule: (kind: string, value: string) => void }) {
  const [result, setResult] = useState<Result | null>(null);
  const [keyword, setKeyword] = useState('');
  const [minScore, setMinScore] = useState(0);
  const [applied, setApplied] = useState<Filter>({ keyword: '', min_score: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [detail, setDetail] = useState<Profile | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const sequence = useRef(0);
  const detailSequence = useRef(0);
  const load = async (current = 1, filter: Filter = { keyword: keyword.trim(), min_score: minScore }) => {
    const request = ++sequence.current;
    setLoading(true);
    try { const response = await apiGet(endpoint + 'risk', { ...filter, current, page_size: 20 }); if (request !== sequence.current) return; setResult(response.data); setApplied(filter); setError(''); }
    catch (error: any) { if (request === sequence.current) { setResult(null); setError(error.message || '风险排行加载失败'); } }
    finally { if (request === sequence.current) setLoading(false); }
  };
  const showDetail = async (row: Profile) => {
    const request = ++detailSequence.current;
    setDetail(row); setEvents([]); setDetailError(''); setDetailLoading(true);
    try { const response = await apiGet(endpoint + 'risk-events', { token_hash: row.token_hash, id: row.user_id }); if (request === detailSequence.current) setEvents(response.data || []); }
    catch (error: any) { if (request === detailSequence.current) setDetailError(error.message || '请求明细加载失败'); }
    finally { if (request === detailSequence.current) setDetailLoading(false); }
  };
  useEffect(() => { load(); return () => { sequence.current++; detailSequence.current++; }; }, []);
  const columns: any[] = [
    { title: '风险', width: 115, render: (_: any, row: Profile) => { const level = levels[row.level] || levels.low; return <Tag color={level[1]}>{level[0]} · {row.score}</Tag>; } },
    { title: '用户 / Token 指纹', width: 250, render: (_: any, row: Profile) => <Space direction="vertical" size={0} style={{ maxWidth: 230 }}>{row.user_id ? <Typography.Link onClick={() => onUserSelect(row.user_id)} title={row.email}>{row.email || `#${row.user_id}`}</Typography.Link> : <Typography.Text type="secondary">未识别用户</Typography.Text>}{row.token_hash ? <Typography.Text copyable={{ text: row.token_hash }} title={row.token_hash}>{row.token_hash.slice(0, 12)}…</Typography.Text> : <Typography.Text type="secondary">登录态入口 · #{row.user_id}</Typography.Text>}</Space> },
    { title: '请求（24h / 1h）', width: 145, render: (_: any, row: Profile) => `${row.metrics.requests_24h} / ${row.metrics.requests_1h}` },
    { title: 'IP（24h / 10m）', width: 145, render: (_: any, row: Profile) => `${row.metrics.ips_24h} / ${row.metrics.ips_10m}` },
    { title: 'ASN / 国家（24h）', width: 155, render: (_: any, row: Profile) => <Space direction="vertical" size={0}><span>{row.metrics.asns_24h || 0} / {row.metrics.countries_24h || 0}</span><Typography.Text type="secondary">已识别 {row.metrics.resolved_ips || 0} / {row.metrics.ips_24h} IP</Typography.Text></Space> },
    { title: '最近 IP 情报', width: 290, render: (_: any, row: Profile) => <SubscribeIPIntelligence value={row.intelligence} /> },
    { title: 'UA 变化', width: 90, dataIndex: ['metrics', 'ua_changes_24h'] }, { title: '4xx / 5xx', width: 105, render: (_: any, row: Profile) => `${row.metrics.errors_24h} / ${row.metrics.server_errors_24h}` },
    { title: '最近请求', width: 175, dataIndex: 'last_at', render: dateText }, { title: '复核', width: 170, render: (_: any, row: Profile) => <Space direction="vertical" size={4}>{row.review && <Tag color="red">建议人工复核</Tag>}<Button size="small" onClick={() => showDetail(row)}>原因 / 请求明细</Button></Space> },
  ];
  return <><SubscribeMonitorStatus /><Card title="订阅风险监控"><Space wrap style={{ marginBottom: 16 }}><Input value={keyword} maxLength={255} onChange={event => setKeyword(event.target.value)} onPressEnter={() => load()} placeholder="用户 ID、邮箱、完整 Token 指纹或 IP" style={{ width: 320, maxWidth: '100%' }} /><Select value={minScore} style={{ width: 160 }} onChange={setMinScore} options={[{ value: 0, label: '全部风险' }, { value: 20, label: '20 分及以上' }, { value: 40, label: '40 分及以上' }, { value: 60, label: '60 分及以上' }, { value: 80, label: '80 分及以上' }]} /><Button type="primary" loading={loading} onClick={() => load()}>查询 / 刷新</Button></Space>
    {error && <Alert type="error" showIcon message={error} />} {!!result?.dropped && <Alert type="warning" showIcon message={`本进程有 ${result.dropped} 条风控记录未保存，评分可能不完整。`} />}
    {result && <Typography.Paragraph type="secondary">当前搜索范围 {result.subjects} 个 Token / 登录态用户 · 建议复核 {result.review} 个 · 计算时间 {dateText(result.assessed_at)}</Typography.Paragraph>}
    <Table loading={loading} rowKey="subject" size="small" scroll={{ x: 1640 }} dataSource={result?.data || []} columns={columns} pagination={{ current: result?.current || 1, total: result?.total || 0, pageSize: result?.page_size || 20, showSizeChanger: false, onChange: current => load(current, applied) }} />
    <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>最近 24 小时按 Token / 登录态用户统计，仅辅助人工复核，不自动封禁。IP 情报在后台查询，成功缓存 24 小时，失败或缺失标记未知；刷新页面查看进度。国家 / ASN 来自 ipwho.is，IDC 与代理信号来自 ip-api（免费接口使用 HTTP，仅发送公网 IP）。代理标签是 VPN / Tor 等综合信号，并非确证；过期或失败数据不加分。</Typography.Paragraph>
    <Modal open={!!detail} title="风险原因与请求明细" width={1000} onCancel={() => { detailSequence.current++; setDetail(null); }} footer={<Space wrap>{detail?.token_hash && <Button danger onClick={() => onRule('token_block', detail.token_hash)}>限制此 Token</Button>}{!!detail?.user_id && <Button onClick={() => onUserSelect(detail.user_id)}>查看用户</Button>}<Button onClick={() => { detailSequence.current++; setDetail(null); }}>关闭</Button></Space>} destroyOnClose>
      {detail && <Space direction="vertical" size="middle" style={{ width: '100%' }}><Descriptions bordered size="small" column={2} items={[{ key: 'user', label: '用户', children: detail.email || (detail.user_id ? `#${detail.user_id}` : '未识别用户') }, { key: 'score', label: '评分', children: `${detail.score} / 100 · ${levels[detail.level]?.[0] || '低'}风险` }, { key: 'token', label: 'Token 指纹', span: 2, children: detail.token_hash ? <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{detail.token_hash}</Typography.Text> : '登录态入口，无 Token' }, { key: 'ua', label: 'UA 数 / 变化次数', children: `${detail.metrics.uas_24h} / ${detail.metrics.ua_changes_24h}` }, { key: 'ips', label: 'IP（10m / 30m / 24h）', children: `${detail.metrics.ips_10m} / ${detail.metrics.ips_30m} / ${detail.metrics.ips_24h}` }, { key: 'blocked', label: '已拦截', children: detail.metrics.blocked_24h }, { key: 'whitelist', label: '最近请求命中白名单', children: detail.ua_whitelisted ? '是' : '否' }]} /><SubscribeIPIntelligence value={detail.intelligence} /><Typography.Text type="secondary">最近 24 小时最新 100 条请求；分数最高 100 分。情报表示当前查询结果，不是访问当时的历史定位。</Typography.Text>{detail.factors.length ? <Space direction="vertical">{detail.factors.map(factor => <Typography.Text key={factor.label}>{factor.label}：+{factor.points} 分</Typography.Text>)}</Space> : <Typography.Text type="secondary">当前未触发加分项</Typography.Text>}{detailError && <Alert type="error" message={detailError} />}<Table loading={detailLoading} rowKey="id" size="small" dataSource={events} scroll={{ x: 970 }} pagination={{ pageSize: 10, showSizeChanger: false }} columns={[{ title: '时间', dataIndex: 'time', width: 175, render: dateText }, { title: 'IP / 情报', width: 290, render: (_: any, row: any) => <SubscribeIPIntelligence value={row.intelligence} /> }, { title: 'UA', dataIndex: 'ua', width: 260, ellipsis: true }, { title: '入口', dataIndex: 'endpoint', width: 140 }, { title: '结果', width: 125, render: (_: any, row: any) => `${row.blocked ? '拦截' : row.status >= 400 ? '失败' : '放行'} · ${row.status}` }]} /></Space>}
    </Modal>
  </Card><SubscribeRiskHistory onUserSelect={onUserSelect} /></>;
}
