import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Modal, Space, Switch, Typography, message } from 'antd';
import { apiGet, apiPost } from '../lib/api';

type Status = { ready: boolean; force_off: boolean; enabled: boolean; revision: number; cached: number; pending: number; failed: number; geo_ready: number; risk_ready: number; next_request: number; last_checked: number; snapshot_at: number };
const endpoint = '/subscribe-access/guard/';
const dateText = (value: number) => value ? new Date(value * 1000).toLocaleString() : '尚未完成';

export default function SubscribeMonitorStatus() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const sequence = useRef(0);
  const load = async () => {
    const current = ++sequence.current;
    try { const response = await apiGet(endpoint + 'monitor-status'); if (current === sequence.current) { setStatus(response.data); setError(''); } }
    catch (failure: any) { if (current === sequence.current) setError(failure.message || '监控状态查询失败'); }
  };
  useEffect(() => { load(); return () => { sequence.current++; }; }, []);
  const change = (enabled: boolean) => Modal.confirm({
    title: enabled ? '开启 IP 情报查询？' : '暂停 IP 情报查询？',
    content: enabled ? '向情报服务查询公网 IP 的国家、ASN 和网络标签。' : '暂停新增外部查询。已有未过期情报、访问统计和原防护规则继续生效，正在进行的查询可能完成。',
    onOk: async () => {
      setBusy(true);
      try { await apiPost(endpoint + 'monitor-config', { enabled, revision: status?.revision }); await load(); }
      catch (failure: any) { message.error(failure.message); await load(); }
      finally { setBusy(false); }
    },
  });
  const retry = async () => {
    setBusy(true);
    try { const response = await apiPost(endpoint + 'monitor-retry'); message.success(`${response.data.queued} 个失败 IP 已排队重试，仍遵守查询限速`); await load(); }
    catch (failure: any) { message.error(failure.message); }
    finally { setBusy(false); }
  };
  return <Card size="small" title="监控运行状态" style={{ marginBottom: 16 }} extra={<Button size="small" disabled={busy} onClick={load}>刷新状态</Button>}>
    {error && <Alert type="error" showIcon message={error} />}
    {status && !status.ready && <Alert type="warning" showIcon message="IP 情报与风险历史暂未就绪，后台会重试；原订阅防护和基础统计继续运行。" />}
    {status?.ready && <Space direction="vertical" style={{ width: '100%' }}>
      <Space wrap><Typography.Text>IP 情报查询</Typography.Text><Switch checked={status.enabled && !status.force_off} disabled={busy || status.force_off || !!error} onChange={change} checkedChildren="开启" unCheckedChildren="暂停" /><Typography.Text type="secondary">已缓存 {status.cached} · 国家/ASN 已识别 {status.geo_ready} · 网络标签已识别 {status.risk_ready} · 待查/过期 {status.pending} · 查询失败 {status.failed}</Typography.Text><Button size="small" disabled={busy || !status.enabled || status.force_off || !status.failed || !!error} onClick={retry}>重试失败查询</Button></Space>
      {status.force_off && <Alert type="info" message="服务器已强制暂停外部 IP 查询，后台开关暂不可用。" />}
      <Typography.Text type="secondary">最近情报查询：{dateText(status.last_checked)} · 最近历史评估：{dateText(status.snapshot_at)}{status.next_request > Date.now() / 1000 + 5 ? ` · 查询冷却至 ${dateText(status.next_request)}` : ''}</Typography.Text>
      {!!status.snapshot_at && status.snapshot_at < Date.now() / 1000 - 180 && <Alert type="warning" message="历史评估超过 3 分钟未完成，请检查后台监控任务。" />}
    </Space>}
  </Card>;
}
