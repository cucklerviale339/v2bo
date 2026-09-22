import React, { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Modal, Space, Table, Tag, Typography, message } from 'antd';
import { apiGet } from '../lib/api';

const dateText = (value: number) => value ? new Date(value * 1000).toLocaleString() : '-';
const reasonLabels: Record<string, string> = { crawler_ua: '常见爬虫 UA', ua: 'UA 黑名单', empty_ua: '空 UA', ip: 'IP 黑名单', token: 'Token 黑名单', user: '用户订阅限制', ip_rate: 'IP 限流', token_rate: 'Token 限流', guard_unavailable: '防护异常放行' };

export default function SubscribeCrawlerPanel({ refreshKey, onUserSelect }: { refreshKey: number; onUserSelect: (id: number) => void }) {
  const [users, setUsers] = useState<any>({ data: [], current: 1, total: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scope, setScope] = useState<number | null>(null);
  const [records, setRecords] = useState<any>({ data: [] });
  const [before, setBefore] = useState(0);
  const [recordsLoading, setRecordsLoading] = useState(false);
  const userSequence = useRef(0);
  const recordSequence = useRef(0);
  const loadUsers = async (current = 1) => {
    const sequence = ++userSequence.current;
    setLoading(true);
    try {
      const response = await apiGet('/subscribe-access/guard/crawler-users', { current, page_size: 20 });
      if (sequence !== userSequence.current) return;
      setUsers(response.data); setError('');
    } catch (error: any) { if (sequence === userSequence.current) setError(error.message); }
    finally { if (sequence === userSequence.current) setLoading(false); }
  };
  const loadRecords = async (userID: number, cursor = 0) => {
    const sequence = ++recordSequence.current;
    setScope(userID); setRecordsLoading(true); setRecords({ data: [] });
    try {
      const response = await apiGet('/subscribe-access/guard/events', { crawler_only: 1, user_id: userID || undefined, before: cursor });
      if (sequence !== recordSequence.current) return;
      setRecords(response.data); setBefore(cursor);
    } catch (error: any) { if (sequence === recordSequence.current) message.error(error.message); }
    finally { if (sequence === recordSequence.current) setRecordsLoading(false); }
  };
  const closeRecords = () => { recordSequence.current++; setScope(null); };
  useEffect(() => { loadUsers(); }, [refreshKey]);
  useEffect(() => () => { userSequence.current++; recordSequence.current++; }, []);
  return <Card title="常见爬虫 UA 触发用户" size="small">
    <Space direction="vertical" style={{ width: '100%' }}>
      <Alert showIcon type="info" message="爬虫 UA 默认只记录和统计。" description="如需拦截，请返回“统计与防护”页的订阅防护设置，开启“拦截常见爬虫 UA”，并将订阅防护模式设为“正式拦截”。UA 可以伪造，命中不等于恶意。" />
      <Space wrap><Button loading={loading} onClick={() => loadUsers(users.current)}>刷新</Button><Button onClick={() => loadRecords(0)}>全部触发记录</Button><Typography.Text>触发 {users.matched || 0} 次 · 关联 {users.total || 0} 位用户 · 未识别用户 {users.unresolved || 0} 次</Typography.Text></Space>
      {error && <Alert type="error" message={error} />}
      <Table size="small" rowKey="user_id" loading={loading} dataSource={users.data} scroll={{ x: 1250 }} pagination={{ current: users.current, total: users.total, pageSize: 20, showSizeChanger: false, onChange: loadUsers }} columns={[
        { title: '用户 ID', dataIndex: 'user_id', width: 90 }, { title: '邮箱', dataIndex: 'email', render: (value: string, row: any) => <a onClick={() => onUserSelect(row.user_id)}>{value || `#${row.user_id}`}</a> },
        { title: '触发次数', dataIndex: 'count' }, { title: '爬虫规则拦截', dataIndex: 'crawler_blocked' }, { title: '全部规则拦截', dataIndex: 'blocked' }, { title: '白名单命中', dataIndex: 'whitelisted' },
        { title: 'IP 数', dataIndex: 'ip_count' }, { title: 'UA 数', dataIndex: 'ua_count' }, { title: '最近触发', dataIndex: 'last_at', render: dateText, width: 175 },
        { title: '操作', width: 175, render: (_: any, row: any) => <Space><Button size="small" onClick={() => loadRecords(row.user_id)}>触发明细</Button><Button size="small" onClick={() => onUserSelect(row.user_id)}>用户详情</Button></Space> },
      ]} />
    </Space>
    <Modal open={scope !== null} title={scope ? `用户 #${scope} · 常见爬虫 UA 触发明细` : '常见爬虫 UA · 全部触发记录'} width={1100} onCancel={closeRecords} footer={<Button onClick={closeRecords}>关闭</Button>} destroyOnClose>
      <Table size="small" loading={recordsLoading} rowKey="id" pagination={false} dataSource={records.data} scroll={{ x: 1050 }} columns={[
        { title: '时间', dataIndex: 'time', render: dateText, width: 175 }, { title: '用户 ID', dataIndex: 'user_id', width: 85, render: (value: number) => value || '-' },
        { title: '邮箱', dataIndex: 'email', render: (value: string) => value || '未识别用户' }, { title: 'IP', dataIndex: 'ip' },
        { title: 'User-Agent', dataIndex: 'ua', width: 260, render: (value: string) => <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{value}</Typography.Text> },
        { title: '处理结果', width: 180, render: (_: any, row: any) => <Space direction="vertical" size={0}><Tag color={row.blocked ? 'red' : 'green'}>{row.blocked ? '已拦截' : row.status >= 400 ? '业务拒绝' : '已放行'} · {row.status}</Tag>{row.ua_whitelisted && <Tag color="blue">白名单命中</Tag>}<Typography.Text type="secondary">{reasonLabels[row.reason] || (row.mode === 'off' ? '防护关闭' : '仅记录')}</Typography.Text></Space> },
      ]} />
      <Space style={{ marginTop: 12 }}><Button disabled={!before || recordsLoading} onClick={() => loadRecords(scope || 0)}>最新记录</Button><Button disabled={recordsLoading || records.data?.length !== 50} onClick={() => loadRecords(scope || 0, records.data[records.data.length - 1].id)}>更早记录</Button></Space>
    </Modal>
  </Card>;
}
