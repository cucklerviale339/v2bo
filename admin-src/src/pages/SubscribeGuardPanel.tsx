import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from 'antd';
import { apiGet, apiPost } from '../lib/api';
import SubscribeGuardDashboard from './SubscribeGuardDashboard';
import SubscribeCrawlerPanel from './SubscribeCrawlerPanel';

type Rule = { kind: string; value: string; token?: string; note: string; expires_at: number };
type Policy = { revision: number; mode: string; ip_limit: number; token_limit: number; block_empty_ua: boolean; block_crawler_ua: boolean; keep_days: number; trusted_proxies: string[]; token_blacklist: string[]; rules: Rule[] };
const kinds: Record<string, string> = { ip_allow: 'IP 白名单', ip_block: 'IP 黑名单', ua_allow: 'UA 白名单', ua_block: 'UA 黑名单', token_block: 'Token 黑名单', user_block: '限制用户订阅' };
const modes: Record<string, string> = { off: '关闭', observe: '仅观察', enforce: '正式拦截' };
const reasons: Record<string, string> = { ip: 'IP 黑名单', token: 'Token 黑名单', user: '用户订阅限制', empty_ua: '空 UA', crawler_ua: '脚本 UA', ua: 'UA 黑名单', ip_rate: 'IP 超频', token_rate: 'Token 超频', guard_unavailable: '防护异常，已放行' };
const dateText = (value: number) => value ? new Date(value * 1000).toLocaleString() : '-';

export default function SubscribeGuardPage() {
  const [selectedUserID, setSelectedUserID] = useState(0);
  const [refreshKey, setRefreshKey] = useState(0);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [forceOff, setForceOff] = useState(false);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [failure, setFailure] = useState('');
  const [form] = Form.useForm();
  const [rules, setRules] = useState<Rule[]>([]);
  const [listTexts, setListTexts] = useState<Record<string, string>>({});
  const [events, setEvents] = useState<any>({ data: [] });
  const [loading, setLoading] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [outcome, setOutcome] = useState('');
  const [cursor, setCursor] = useState(0);
  const [appliedFilter, setAppliedFilter] = useState({ keyword: '', outcome: '' });
  const requestID = useRef(0);
  const replaceRules = (next: Rule[]) => {
    setRules(next);
    setListTexts(Object.fromEntries(Object.keys(kinds).map(kind => [kind, next.filter(rule => rule.kind === kind && !rule.token).map(rule => rule.value).join('\n')])));
  };

  const loadConfig = async () => {
    try {
      const response = await apiGet('/subscribe-access/guard/config');
      const current = response.data.policy;
      setPolicy(current);
      replaceRules(current.rules || []);
      setForceOff(response.data.force_off);
      form.setFieldsValue({ ...current, token_blacklist: (current.token_blacklist || []).join('\n') });
      setDirty(false);
      setFailure('');
    } catch (error: any) { setFailure(error.message || '防护配置加载失败'); }
  };
  const loadEvents = async (before = 0, search = keyword, result = outcome) => {
    const currentRequest = ++requestID.current;
    setLoading(true);
    try {
      const response = await apiGet('/subscribe-access/guard/events', { keyword: search.trim(), outcome: result, before });
      if (currentRequest !== requestID.current) return;
      setEvents(response.data);
      setCursor(before);
      setAppliedFilter({ keyword: search.trim(), outcome: result });
    } catch (error: any) { if (currentRequest === requestID.current) message.error(error.message || '风控记录加载失败'); }
    finally { if (currentRequest === requestID.current) setLoading(false); }
  };
  useEffect(() => { loadConfig(); loadEvents(); return () => { requestID.current++; }; }, []);

  const save = async (values: any) => {
    if (!policy) return;
    setSaving(true);
    try {
      const response = await apiPost('/subscribe-access/guard/config', { policy: {
        ...policy, ...values, rules,
        token_blacklist: [...new Set(String(values.token_blacklist || '').split(/\r?\n/).map(value => value.trim()).filter(Boolean))],
      } });
      setPolicy(response.data);
      replaceRules(response.data.rules || []);
      form.setFieldsValue({ token_blacklist: (response.data.token_blacklist || []).join('\n') });
      setDirty(false);
      message.success('防护配置已保存，最多 2 秒生效');
    } catch (error: any) { message.error(error.message || '保存失败'); }
    finally { setSaving(false); }
  };
  const submit = (values: any) => {
    if (values.mode === 'enforce') {
      Modal.confirm({ title: '启用这些订阅拦截规则？', content: '命中规则的用户将无法更新订阅。建议先用“仅观察”确认不会误伤正常客户端。用户订阅限制和 Token 黑名单不会被 IP 白名单放行。', okText: '保存并拦截', onOk: () => save(values) });
    } else { save(values); }
  };
  const quickRule = (kind: string, value: string) => {
    if (!policy || saving) return;
    if (dirty) { message.warning('请先保存或放弃防护设置中的修改，再使用快捷封禁'); return; }
    const normalizedValue = kind.startsWith('ua_') ? value.trim().toLowerCase() : value.trim();
    Modal.confirm({
      title: `确认添加${kinds[kind]}？`,
      content: <Space direction="vertical"><Typography.Text style={{ wordBreak: 'break-all' }}>{value}</Typography.Text><Typography.Text>默认有效 24 小时。只保存这一条规则，不改变当前模式；关闭或观察模式不会拦截。UA 和共享 IP 可能对应多个正常用户。</Typography.Text></Space>,
      okText: '确认添加',
      onOk: async () => {
        setSaving(true);
        try {
          const next = { kind, value: normalizedValue, note: '订阅防护快捷操作', expires_at: Math.floor(Date.now() / 1000) + 86400 };
          const response = await apiPost('/subscribe-access/guard/config', { policy: { ...policy, rules: [...policy.rules.filter(rule => !(rule.kind === kind && rule.value === normalizedValue)), next] } });
          setPolicy(response.data); replaceRules(response.data.rules || []);
          message.success(policy.mode === 'enforce' ? '规则已保存，最多 2 秒生效' : '规则已保存；当前未启用正式拦截');
        } catch (error: any) { message.error(error.message || '保存失败'); throw error; }
        finally { setSaving(false); }
      },
    });
  };
  const editList = (kind: string, text: string) => {
    const values = [...new Set(text.split(/\r?\n/).map(value => kind.startsWith('ua_') ? value.trim().toLowerCase() : value.trim()).filter(Boolean))];
    setListTexts(current => ({ ...current, [kind]: text }));
    setRules(current => [...current.filter(rule => rule.kind !== kind || rule.token), ...values.map(value => current.find(rule => rule.kind === kind && rule.value === value) || { kind, value, note: '', expires_at: 0 })]);
    setDirty(true);
  };

  const settings = policy && <Card title="订阅防护设置" extra={<Space><Tag color={policy.mode === 'enforce' ? 'red' : 'blue'}>{modes[policy.mode]}</Tag>{dirty && <Tag color="orange">有未保存修改</Tag>}</Space>}>
    <Form form={form} layout="vertical" onFinish={submit} onValuesChange={() => setDirty(true)} disabled={saving}>
      {[
        ['mode', '订阅防护模式', '关闭：只记录访问，不执行规则；仅观察：记录命中，不拦截；正式拦截：按规则执行。', <Select style={{ width: 200 }} options={Object.entries(modes).map(([value, label]) => ({ value, label }))} />],
        ['ip_limit', 'IP 频率限制', '每 IP 每分钟请求数，0 不限制。共享出口可能有多个正常用户。', <InputNumber min={0} max={100000} precision={0} />],
        ['token_limit', 'Token 频率限制', '每 Token 每分钟请求数，0 不限制。', <InputNumber min={0} max={100000} precision={0} />],
        ['keep_days', '请求日志保留天数', '仅清理新防护记录，不影响原订阅统计。', <InputNumber min={1} max={365} precision={0} />],
        ['block_empty_ua', '拦截空 UA', '开启后没有 User-Agent 的订阅请求会被拒绝。', <Switch />],
        ['block_crawler_ua', '拦截常见爬虫 UA', '默认只记录和统计。开启后，且防护模式为“正式拦截”时才会拦截；识别 curl、wget、httpie、aria2、Python、aiohttp、urllib、Go-http-client、Java、OkHttp、Postman、Insomnia、Node fetch、Axios、Undici、Scrapy、Spider、Crawler、Bot、HeadlessChrome、Selenium、Playwright、Puppeteer 等。', <Switch />],
      ].map(([key, label, description, control]) => <div className="config-row" key={String(key)}><div className="config-row-copy"><div className="config-row-title">{label}</div><div className="config-row-desc">{description}</div></div><div className="config-row-control"><Form.Item name={String(key)} valuePropName={String(key).startsWith('block_') ? 'checked' : 'value'} rules={[{ required: true }]} style={{ marginBottom: 0 }}>{control}</Form.Item></div></div>)}
      {['ip_allow', 'ip_block', 'ua_allow', 'ua_block'].map(kind => <div className="config-row" key={kind}><div className="config-row-copy"><div className="config-row-title">{kinds[kind]}</div><div className="config-row-desc">{kind.startsWith('ip_') ? '每行一个 IP 或 CIDR。白名单跳过 IP/UA 检查及 IP 限流，但不绕过 Token 或用户限制。' : kind === 'ua_allow' ? '每行一个关键词，大小写不敏感。命中后跳过 UA 拦截。' : '每行一个关键词，大小写不敏感。命中后禁止拉取订阅。'}</div></div><div className="config-row-control"><Input.TextArea rows={3} value={listTexts[kind] || ''} onChange={event => editList(kind, event.target.value)} /></div></div>)}
      <div className="config-row"><div className="config-row-copy"><div className="config-row-title">Token 黑名单</div><div className="config-row-desc">每行一个订阅 Token。命中后禁止拉取订阅。</div></div><div className="config-row-control"><Form.Item name="token_blacklist" style={{ marginBottom: 0 }}><Input.TextArea rows={4} autoComplete="off" placeholder={'订阅 Token 1\n订阅 Token 2'} /></Form.Item></div></div>
      <Typography.Paragraph type="secondary">Token 黑名单可直接粘贴和编辑，数据库加密保存；请求日志和操作历史不保存 Token 明文。</Typography.Paragraph>
      <Space style={{ marginTop: 16 }}><Button type="primary" htmlType="submit" loading={saving}>保存防护设置</Button><Popconfirm title="重新加载并放弃未保存修改？" onConfirm={loadConfig}><Button disabled={saving}>重新加载</Button></Popconfirm></Space>
    </Form>
  </Card>;

  return <div className="legacy-page config-page subscribe-guard-page">
    <h2 className="content-heading">订阅防护</h2>
    <Card className="block-card"><div className="block-content">
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Alert type="info" showIcon message="升级后默认关闭，现有订阅继续使用。建议先观察，再按需启用拦截。" description="防护请求单独记录，原有订阅统计和低流量统计继续保留。用户订阅限制只限制获取节点，不会封禁账号或踢掉已经连接的设备。" />
      {forceOff && <Alert type="warning" showIcon message="服务器已启用紧急关闭，当前所有防护规则均不执行。" />}
      {failure && <Alert type="error" showIcon message={failure} action={<Button onClick={loadConfig}>重试</Button>} />}
      <SubscribeGuardDashboard selectedUserID={selectedUserID} onUserSelect={setSelectedUserID} onRule={quickRule} refreshKey={refreshKey}>
      <SubscribeCrawlerPanel refreshKey={refreshKey} onUserSelect={setSelectedUserID} />
      <Card title="最近订阅防护记录">
      <Space wrap>
        <Input value={keyword} maxLength={255} style={{ width: 290 }} onChange={event => setKeyword(event.target.value)} placeholder="用户 ID / 邮箱 / 完整 IP / UA 关键词" onPressEnter={() => loadEvents()} />
        <Select value={outcome} style={{ width: 160 }} onChange={value => { setOutcome(value); loadEvents(0, keyword, value); }} options={[{ value: '', label: '全部请求' }, { value: 'matched', label: '命中规则' }, { value: 'blocked', label: '实际拦截' }, { value: 'allowed', label: '放行且成功' }, { value: 'failed', label: '业务失败' }]} />
        <Button onClick={() => { loadEvents(); setRefreshKey(value => value + 1); }}>查询 / 刷新</Button>
        <Typography.Text>保留期内匹配请求 {events.total || 0} · 命中 {events.matched || 0} · 拦截 {events.blocked || 0} · 业务失败 {events.failed || 0}</Typography.Text>
      </Space>
      {events.dropped > 0 && <Alert type="warning" message={`本进程因写入失败或队列繁忙未保存 ${events.dropped} 条风控记录，订阅响应未因此阻塞。`} />}
      <Table loading={loading} rowKey="id" size="small" pagination={false} scroll={{ x: 1450 }} dataSource={events.data || []} columns={[
        { title: '时间', dataIndex: 'time', width: 175, render: dateText },
        { title: '用户', width: 200, render: (_: any, row: any) => row.user_id ? <Button type="link" onClick={() => setSelectedUserID(row.user_id)}>{row.email || `#${row.user_id}`}</Button> : '未识别用户' },
        { title: '结果', width: 180, render: (_: any, row: any) => <Space direction="vertical" size={0}><Tag color={row.blocked ? 'red' : row.reason ? 'orange' : 'green'}>{row.blocked ? '拦截' : row.status >= 400 ? '业务失败' : '放行'} · {row.status}</Tag>{reasons[row.reason] || ''}{row.mode === 'observe' && <Typography.Text type="secondary">仅观察</Typography.Text>}</Space> },
        { title: 'IP', dataIndex: 'ip', width: 160 },
        { title: 'Token 指纹', dataIndex: 'token_hash', width: 140, render: (value: string) => value ? <Typography.Text copyable={{ text: value }}>{value.slice(0, 10)}…</Typography.Text> : '-' },
        { title: 'UA', dataIndex: 'ua', ellipsis: true, width: 250 },
        { title: '入口', dataIndex: 'endpoint', width: 130 },
        { title: '操作', width: 320, render: (_: any, row: any) => <Space wrap size={4}>
          <Button size="small" disabled={!policy || saving || !row.ip} onClick={() => quickRule('ip_block', row.ip)}>封 IP</Button>
          <Button size="small" disabled={!policy || saving || !row.ua} onClick={() => quickRule('ua_block', row.ua)}>封 UA</Button>
          <Button size="small" disabled={!policy || saving || !row.token_hash} onClick={() => quickRule('token_block', row.token_hash)}>封 Token</Button>
          <Button size="small" disabled={!policy || saving || !row.user_id} onClick={() => quickRule('user_block', String(row.user_id))}>仅限制订阅</Button>
        </Space> },
      ]} />
      <Space><Button disabled={!cursor || loading} onClick={() => loadEvents(0, appliedFilter.keyword, appliedFilter.outcome)}>最新记录</Button><Button disabled={loading || events.data?.length !== 50} onClick={() => loadEvents(events.data[events.data.length - 1].id, appliedFilter.keyword, appliedFilter.outcome)}>更早记录</Button></Space>
      </Card>
      </SubscribeGuardDashboard>
      {settings}
    </Space>
    </div></Card>
  </div>;
}
