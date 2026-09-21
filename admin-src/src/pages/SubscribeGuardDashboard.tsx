import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Col, Descriptions, Input, Modal, Popconfirm, Row, Segmented, Space, Spin, Statistic, Table, Tag, Typography, message } from 'antd';
import { apiGet, apiPost, bytes, money } from '../lib/api';

const endpoint = '/subscribe-access/guard/';
const dateText = (value: any) => Number(value) ? new Date(Number(value) * 1000).toLocaleString() : '-';
const copyText = (value: any) => <Typography.Text copyable={value ? { text: String(value) } : false} ellipsis={{ tooltip: String(value || '') }}>{value || '-'}</Typography.Text>;
const accountStatus = (row: any) => Number(row.banned) ? <Tag color="red">封禁</Tag> : <Tag color="green">正常</Tag>;
const insiderText = (row: any) => row.insider_rule ? `${row.insider_rule.name} · ${row.insider_rule.host || '额外节点'} · ${row.insider_rule.extra_nodes_count} 个额外节点` : '按原节点地址规则下发';
const countColumns = (label: string) => [{ title: label, dataIndex: 'value', render: copyText }, { title: '次数', dataIndex: 'count', width: 80 }];

export default function SubscribeGuardDashboard({ selectedUserID, onUserSelect, onRule, refreshKey, children }: { selectedUserID: number; onUserSelect: (id: number) => void; onRule: (kind: string, value: string) => void; refreshKey: number; children: React.ReactNode }) {
  const [stats, setStats] = useState<any>({});
  const [statsError, setStatsError] = useState('');
  const [loading, setLoading] = useState(false);
  const [rank, setRank] = useState<any>({ data: [], total: 0 });
  const [rankSort, setRankSort] = useState('count');
  const [rankPage, setRankPage] = useState(1);
  const [rankLoading, setRankLoading] = useState(false);
  const [userSearch, setUserSearch] = useState('');
  const [userRows, setUserRows] = useState<any[]>([]);
  const [userLoading, setUserLoading] = useState(false);
  const [uaSearch, setUASearch] = useState('');
  const [uaApplied, setUAApplied] = useState('');
  const [uaResult, setUAResult] = useState<any>({ data: [], total: 0, current: 1 });
  const [uaLoading, setUALoading] = useState(false);
  const [detail, setDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [list, setList] = useState<any>(null);
  const statsSequence = useRef(0);
  const rankSequence = useRef(0);
  const userSequence = useRef(0);
  const uaSequence = useRef(0);
  const detailSequence = useRef(0);

  const loadStats = async () => {
    const sequence = ++statsSequence.current;
    setLoading(true);
    try {
      const response = await apiGet(endpoint + 'stats');
      if (sequence !== statsSequence.current) return;
      setStats(response.data); setStatsError('');
    }
    catch (error: any) { if (sequence === statsSequence.current) setStatsError(error.message || '订阅统计加载失败'); }
    finally { if (sequence === statsSequence.current) setLoading(false); }
  };
  const loadRank = async (sort = rankSort, current = rankPage) => {
    const sequence = ++rankSequence.current;
    setRankLoading(true);
    try {
      const response = await apiGet(endpoint + 'user-rank', { sort, current, page_size: 20 });
      if (sequence !== rankSequence.current) return;
      setRank(response.data); setRankPage(current); setRankSort(sort);
    } catch (error: any) { if (sequence === rankSequence.current) message.error(error.message); }
    finally { if (sequence === rankSequence.current) setRankLoading(false); }
  };
  const searchUsers = async (keyword: string) => {
    const sequence = ++userSequence.current;
    if (!keyword.trim()) { setUserRows([]); setUserLoading(false); return; }
    setUserLoading(true);
    try {
      const response = await apiGet(endpoint + 'user-search', { keyword: keyword.trim() });
      if (sequence === userSequence.current) setUserRows(response.data || []);
    } catch (error: any) { if (sequence === userSequence.current) message.error(error.message); }
    finally { if (sequence === userSequence.current) setUserLoading(false); }
  };
  const searchUA = async (keyword: string, current = 1) => {
    if (!keyword.trim()) { message.info('请输入 UA 关键词'); return; }
    const sequence = ++uaSequence.current;
    setUALoading(true);
    try {
      const response = await apiGet(endpoint + 'ua-search', { keyword: keyword.trim(), current, page_size: 20 });
      if (sequence !== uaSequence.current) return;
      setUAResult(response.data); setUAApplied(keyword.trim());
    } catch (error: any) { if (sequence === uaSequence.current) message.error(error.message); }
    finally { if (sequence === uaSequence.current) setUALoading(false); }
  };
  const loadDetail = async (id: number) => {
    const sequence = ++detailSequence.current;
    setDetail(null); setDetailError(''); setDetailLoading(true);
    try {
      const response = await apiGet(endpoint + 'user-detail', { id });
      if (sequence === detailSequence.current) setDetail(response.data);
    } catch (error: any) { if (sequence === detailSequence.current) setDetailError(error.message); }
    finally { if (sequence === detailSequence.current) setDetailLoading(false); }
  };
  const banUser = async (row: any) => {
    try {
      await apiPost(endpoint + 'set-user-banned', { id: row.id || row.user_id, banned: Number(row.banned) ? 0 : 1 });
      message.success('账号状态已更新'); loadRank();
      if (selectedUserID) loadDetail(selectedUserID);
      if (userSearch.trim()) searchUsers(userSearch);
      if (uaApplied) searchUA(uaApplied, uaResult.current);
    } catch (error: any) { message.error(error.message); }
  };
  const banButton = (row: any) => <Popconfirm title={Number(row.banned) ? '恢复账号为正常状态？' : '封禁此账号？会清除登录会话，并影响节点使用。'} onConfirm={() => banUser(row)}><Button size="small" danger={!Number(row.banned)} disabled={!!Number(row.is_admin) || !!Number(row.is_staff) || !!row.deleted_user}>{Number(row.banned) ? '恢复正常' : '封禁账号'}</Button></Popconfirm>;
  const showMatching = async (row: any) => {
    try {
      const response = await apiGet(endpoint + 'events', { user_id: row.user_id, ua: uaApplied });
      setList({ title: `${row.email || row.user_id} · UA 匹配记录（最近 50 条）`, rows: response.data.data, columns: eventColumns });
    } catch (error: any) { message.error(error.message); }
  };
  useEffect(() => { loadStats(); loadRank(); }, [refreshKey]);
  useEffect(() => () => { statsSequence.current++; rankSequence.current++; userSequence.current++; uaSequence.current++; detailSequence.current++; }, []);
  useEffect(() => { if (selectedUserID) loadDetail(selectedUserID); else { detailSequence.current++; setDetail(null); } }, [selectedUserID]);

  const eventColumns: any[] = [
    { title: '时间', dataIndex: 'time', width: 170, render: dateText },
    { title: '结果', width: 140, render: (_: any, row: any) => <Tag color={row.blocked ? 'red' : 'green'}>{row.blocked ? '拦截' : '放行'} · {row.status}</Tag> },
    { title: 'IP', dataIndex: 'ip', render: copyText }, { title: 'UA', dataIndex: 'ua', render: copyText },
    { title: '模式', dataIndex: 'mode', render: (value: string) => ({ off: '关闭', observe: '仅观察', enforce: '正式拦截' }[value]) },
  ];
  const rankColumns: any[] = [
    { title: '用户邮箱', render: (_: any, row: any) => <a onClick={() => onUserSelect(row.user_id)}>{row.email || `#${row.user_id}`}</a> },
    { title: '账号状态', width: 90, render: (_: any, row: any) => accountStatus(row) },
    { title: '请求数', dataIndex: 'count', width: 90 }, { title: '已放行', dataIndex: 'allowed', width: 90 }, { title: '已拦截', dataIndex: 'blocked', width: 90 },
    { title: 'IP 数', dataIndex: 'ip_count', width: 80 }, { title: 'UA 数', dataIndex: 'ua_count', width: 80 },
    { title: '最近请求', dataIndex: 'last_at', width: 175, render: dateText },
    { title: '操作', width: 210, render: (_: any, row: any) => <Space><Button size="small" onClick={() => onUserSelect(row.user_id)}>查看详细</Button>{banButton(row)}</Space> },
  ];
  const detailUser = detail?.user || {};
  const detailStats = detail?.stats || {};
  return <Space direction="vertical" size="large" style={{ width: '100%', marginBottom: 24 }}>
    <Space><Button loading={loading} onClick={() => { loadStats(); loadRank(); }}>刷新统计</Button><Typography.Text type="secondary">保留期内请求；关闭拦截时仍记录访问，观察模式记录命中但不拦截。</Typography.Text></Space>
    {statsError && <Alert type="error" showIcon message={statsError} />}
    <Row gutter={[16, 16]}>{[['总请求', stats.total], ['已放行', stats.allowed], ['已拦截', stats.blocked], ['频率限制', stats.rate_limited]].map(([label, value]) => <Col xs={12} md={6} key={label}><Card size="small"><Statistic title={label} value={value || 0} /></Card></Col>)}</Row>
    <Row gutter={[16, 16]}>{[['Top IP', 'ips'], ['Top Token（指纹）', 'tokens'], ['Top UA', 'uas']].map(([label, key]) => <Col xs={24} lg={8} key={key}><Card size="small" title={label}><Table size="small" rowKey="value" pagination={{ pageSize: 5, size: 'small' }} columns={countColumns(label)} dataSource={stats[key] || []} /></Card></Col>)}</Row>
    <Card size="small" title="搜索用户"><Space direction="vertical" style={{ width: '100%' }}>
      <Input.Search value={userSearch} maxLength={255} allowClear enterButton="搜索" loading={userLoading} onChange={event => { setUserSearch(event.target.value); userSequence.current++; setUserRows([]); setUserLoading(false); }} onSearch={searchUsers} placeholder="用户 ID 或邮箱，支持邮箱模糊搜索" style={{ maxWidth: 620 }} />
      <Table size="small" rowKey="id" loading={userLoading} dataSource={userRows} pagination={false} scroll={{ x: 1250 }} columns={[
        { title: 'ID', dataIndex: 'id', width: 80 }, { title: '邮箱', dataIndex: 'email', render: (value: string, row: any) => <a onClick={() => onUserSelect(row.id)}>{value}</a> },
        { title: '状态', render: (_: any, row: any) => accountStatus(row) }, { title: '当前下发规则', width: 260, render: (_: any, row: any) => insiderText(row) },
        { title: '套餐', render: (_: any, row: any) => row.plan_name || (row.plan_id ? `#${row.plan_id}` : '无套餐') },
        { title: '已用 / 总流量', render: (_: any, row: any) => `${bytes(Number(row.u || 0) + Number(row.d || 0))} / ${bytes(row.transfer_enable)}` },
        { title: '到期', dataIndex: 'expired_at', render: value => value === null ? '长期有效' : dateText(value) },
        { title: '操作', render: (_: any, row: any) => <Button size="small" onClick={() => onUserSelect(row.id)}>查看详细</Button> },
      ]} />
    </Space></Card>
    <Card size="small" title="按 UA 搜索用户"><Space direction="vertical" style={{ width: '100%' }}>
      <Input.Search value={uaSearch} maxLength={255} allowClear enterButton="搜索" loading={uaLoading} onChange={event => { setUASearch(event.target.value); uaSequence.current++; setUAApplied(''); setUAResult({ data: [], total: 0, current: 1 }); setUALoading(false); }} onSearch={value => searchUA(value)} placeholder="UA 关键词，例如 curl；大小写不敏感" style={{ maxWidth: 620 }} />
      {uaApplied && <Typography.Text type="secondary">匹配 {uaResult.matched} 条请求，关联 {uaResult.total} 位用户；{uaResult.unresolved} 条请求未识别用户。</Typography.Text>}
      <Table size="small" rowKey="user_id" loading={uaLoading} dataSource={uaResult.data} columns={[...rankColumns.slice(0, -1), { title: '操作', width: 220, render: (_: any, row: any) => <Space><Button size="small" onClick={() => onUserSelect(row.user_id)}>查看用户</Button><Button size="small" onClick={() => showMatching(row)}>匹配记录</Button></Space> }]} scroll={{ x: 1250 }} pagination={{ current: uaResult.current, total: uaResult.total, pageSize: 20, showSizeChanger: false, onChange: current => searchUA(uaApplied, current) }} />
    </Space></Card>
    <Card size="small" title="订阅防控用户排行" extra={<Segmented value={rankSort} options={[{ label: '请求数最多', value: 'count' }, { label: 'IP 数最多', value: 'ip_count' }]} onChange={value => loadRank(String(value), 1)} />}><Table size="small" rowKey="user_id" loading={rankLoading} dataSource={rank.data} columns={rankColumns} scroll={{ x: 1250 }} pagination={{ current: rankPage, total: rank.total, pageSize: 20, showSizeChanger: false, onChange: current => loadRank(rankSort, current) }} /></Card>
    {children}
    <Modal open={!!selectedUserID} title="订阅防护用户详情" width={1000} onCancel={() => onUserSelect(0)} footer={<Space>{detail && banButton(detailUser)}<Button onClick={() => onUserSelect(0)}>关闭</Button></Space>} destroyOnClose>
      <Spin spinning={detailLoading}>{detailError ? <Alert type="error" message={detailError} /> : detail && <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Descriptions bordered size="small" column={2} title="账号信息" items={[
          { key: 'id', label: '用户 ID', children: detailUser.id }, { key: 'email', label: '邮箱', children: copyText(detailUser.email) }, { key: 'state', label: '账号状态', children: accountStatus(detailUser) }, { key: 'role', label: '身份', children: Number(detailUser.is_admin) ? '管理员' : Number(detailUser.is_staff) ? '员工' : '用户' },
          { key: 'plan', label: '套餐', children: detailUser.plan_name || (detailUser.plan_id ? `#${detailUser.plan_id}` : '无套餐') }, { key: 'group', label: '权限组', children: detailUser.group_name || detailUser.group_id || '-' }, { key: 'expiry', label: '到期时间', children: detailUser.expired_at === null ? '长期有效' : dateText(detailUser.expired_at) },
          { key: 'flow', label: '已用 / 总流量', children: `${bytes(Number(detailUser.u || 0) + Number(detailUser.d || 0))} / ${bytes(detailUser.transfer_enable)}` }, { key: 'balance', label: '余额 / 佣金', children: `${money(detailUser.balance)} / ${money(detailUser.commission_balance)}` }, { key: 'device', label: '设备限制', children: detailUser.device_limit || '不限制' },
          { key: 'speed', label: '限速', children: detailUser.speed_limit ? `${detailUser.speed_limit} Mbps` : '不限制' }, { key: 'created', label: '注册时间', children: dateText(detailUser.created_at) }, { key: 'last', label: '最后在线', children: dateText(detailUser.t || detailUser.last_login_at) }, { key: 'invite', label: '邀请人 / 邀请码', children: `${detailUser.invite_user_id || '-'} / ${detailUser.invite_code || '-'}` },
          { key: 'insider', label: '当前下发规则', span: 2, children: insiderText(detailUser) }, { key: 'note', label: '备注', span: 2, children: detailUser.remarks || '-' },
        ]} />
        <Space wrap><Statistic title="总请求" value={detailStats.total || 0} /><Statistic title="已放行" value={detailStats.allowed || 0} /><Statistic title="已拦截" value={detailStats.blocked || 0} /><Statistic title="IP 数" value={detailStats.ip_count || 0} /><Statistic title="UA 数" value={detailStats.ua_count || 0} /><Button onClick={() => onRule('user_block', String(selectedUserID))}>仅限制订阅</Button></Space>
        <Row gutter={[16, 16]} style={{ width: '100%' }}>{[['请求 IP', 'ips'], ['User-Agent', 'uas']].map(([label, key]) => <Col span={12} key={key}><Card size="small" title={`${label}（最多展示 100 项）`}><Table size="small" rowKey="value" dataSource={detailStats[key] || []} pagination={{ pageSize: 5 }} columns={countColumns(label)} /></Card></Col>)}</Row>
        <Table size="small" rowKey="id" dataSource={detail.recent || []} columns={eventColumns} pagination={{ pageSize: 10 }} scroll={{ x: 780 }} />
      </Space>}</Spin>
    </Modal>
    <Modal open={!!list} title={list?.title} width={850} footer={<Space><Typography.Text copyable={{ text: (list?.rows || []).map((row: any) => row.value || JSON.stringify(row)).join('\n') }}>复制当前明细</Typography.Text><Button onClick={() => setList(null)}>关闭</Button></Space>} onCancel={() => setList(null)} destroyOnClose><Table size="small" rowKey={(_, index) => String(index)} dataSource={list?.rows || []} columns={list?.columns || []} pagination={{ pageSize: 10 }} scroll={{ x: 650 }} /></Modal>
  </Space>;
}
