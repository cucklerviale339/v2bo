import React, { useEffect, useRef, useState } from 'react';
import { Button, Descriptions, Input, InputNumber, Modal, Select, Space, Table, Typography, message } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { apiGet, apiPost, bytes } from '../lib/api';

function formatTime(value: any) {
  const timestamp = Number(value || 0);
  return timestamp > 0 ? new Date(timestamp * 1000).toLocaleString() : '-';
}

export default function SubscribeAccessPage() {
  const [loading, setLoading] = useState(false);
  const [keyword, setKeyword] = useState('');
  const [appliedKeyword, setAppliedKeyword] = useState('');
  const [payload, setPayload] = useState<any>({ summary: {}, data: [], total: 0, current: 1, page_size: 20 });
  const [sort, setSort] = useState('count');
  const [userDetail, setUserDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [uaKeyword, setUAKeyword] = useState('');
  const [appliedUAKeyword, setAppliedUAKeyword] = useState('');
  const [uaResult, setUAResult] = useState<any>({ data: [], total: 0, current: 1, page_size: 20 });
  const [uaLoading, setUALoading] = useState(false);
  const [keepDays, setKeepDays] = useState(7);
  const [lowTrafficLoading, setLowTrafficLoading] = useState(false);
  const [lowTraffic, setLowTraffic] = useState<any>({ data: [], total: 0, current: 1, page_size: 20, threshold_bytes: 200 * 1024 });
  const [todayThresholdKB, setTodayThresholdKB] = useState(200);
  const [appliedTodayThresholdKB, setAppliedTodayThresholdKB] = useState(200);
  const [consecutiveLoading, setConsecutiveLoading] = useState(false);
  const [consecutiveTraffic, setConsecutiveTraffic] = useState<any>({ data: [], total: 0, current: 1, page_size: 20, threshold_bytes: 200 * 1024, days: 3, dates: [] });
  const [consecutiveThresholdKB, setConsecutiveThresholdKB] = useState(200);
  const [appliedConsecutiveThresholdKB, setAppliedConsecutiveThresholdKB] = useState(200);
  const [consecutiveDays, setConsecutiveDays] = useState(3);
  const [appliedConsecutiveDays, setAppliedConsecutiveDays] = useState(3);
  const statsRequest = useRef(0);
  const detailRequest = useRef(0);
  const uaRequest = useRef(0);
  const lowTrafficRequest = useRef(0);
  const consecutiveRequest = useRef(0);

  const load = async (current = 1, pageSize = payload.page_size || 20, search = appliedKeyword, order = sort) => {
    const request = ++statsRequest.current;
    setLoading(true);
    try {
      const response = await apiGet('/subscribe-access/stats', {
        keyword: search,
        current,
        page_size: pageSize,
        sort: order,
      });
      if (request !== statsRequest.current) return;
      const data = response?.data || { summary: {}, data: [], total: 0, current, page_size: pageSize };
      setPayload(data);
      setKeepDays(Number(data.log_keep_days || 7));
    } catch (error: any) {
      if (request === statsRequest.current) message.error(error.message || '订阅统计加载失败');
    } finally {
      if (request === statsRequest.current) setLoading(false);
    }
  };

  const showUserDetail = async (userID: number) => {
    const request = ++detailRequest.current;
    setDetailLoading(true);
    setUserDetail({ user_id: userID });
    try {
      const response = await apiGet('/subscribe-access/user-detail', { id: userID });
      if (request !== detailRequest.current) return;
      setUserDetail(response?.data || null);
    } catch (error: any) {
      if (request === detailRequest.current) {
        message.error(error.message || '用户订阅详情加载失败');
        setUserDetail(null);
      }
    } finally {
      if (request === detailRequest.current) setDetailLoading(false);
    }
  };

  const searchUA = async (current = 1, pageSize = uaResult.page_size || 20, search = appliedUAKeyword) => {
    const value = search.trim();
    if (!value) { message.warning('请输入 User-Agent 关键词'); return; }
    const request = ++uaRequest.current;
    setUALoading(true);
    try {
      const response = await apiGet('/subscribe-access/ua-search', { keyword: value, current, page_size: pageSize });
      if (request !== uaRequest.current) return;
      setUAResult(response?.data || { data: [], total: 0, current, page_size: pageSize });
    } catch (error: any) {
      if (request === uaRequest.current) message.error(error.message || 'UA 反查失败');
    } finally {
      if (request === uaRequest.current) setUALoading(false);
    }
  };

  const applyUASearch = () => {
    const value = uaKeyword.trim();
    setAppliedUAKeyword(value);
    searchUA(1, uaResult.page_size || 20, value);
  };

  const copyDetailValues = async (key: 'ip' | 'ua') => {
    const values = Array.isArray(userDetail?.[`${key}s`]) ? userDetail[`${key}s`].map((item: any) => item[key]).filter(Boolean) : [];
    if (!values.length) { message.warning('没有可复制的内容'); return; }
    try {
      await navigator.clipboard.writeText(values.join('\n'));
      message.success(`已复制 ${values.length} 条`);
    } catch { message.error('复制失败，请逐条复制'); }
  };

  const saveRetention = async () => {
    const days = Math.min(3650, Math.max(1, Math.round(Number(keepDays) || 7)));
    try {
      await apiPost('/subscribe-access/retention', { days });
      setKeepDays(days);
      message.success(`成功订阅日志保留期已设为 ${days} 天，过期记录已清理`);
      load(payload.current || 1);
    } catch (error: any) { message.error(error.message || '保存失败'); }
  };

  const loadLowTraffic = async (current = 1, pageSize = lowTraffic.page_size || 20, threshold = appliedTodayThresholdKB) => {
    const request = ++lowTrafficRequest.current;
    setLowTrafficLoading(true);
    try {
      const response = await apiGet('/subscribe-access/low-traffic', { current, page_size: pageSize, threshold_kb: threshold });
      if (request !== lowTrafficRequest.current) return;
      setLowTraffic(response?.data || { data: [], total: 0, current, page_size: pageSize, threshold_bytes: threshold * 1024 });
    } catch (error: any) {
      if (request === lowTrafficRequest.current) message.error(error.message || '今日低流量用户加载失败');
    } finally {
      if (request === lowTrafficRequest.current) setLowTrafficLoading(false);
    }
  };

  const loadConsecutiveTraffic = async (current = 1, pageSize = consecutiveTraffic.page_size || 20, threshold = appliedConsecutiveThresholdKB, days = appliedConsecutiveDays) => {
    const request = ++consecutiveRequest.current;
    setConsecutiveLoading(true);
    try {
      const response = await apiGet('/subscribe-access/consecutive-low-traffic', { current, page_size: pageSize, threshold_kb: threshold, days });
      if (request !== consecutiveRequest.current) return;
      setConsecutiveTraffic(response?.data || { data: [], total: 0, current, page_size: pageSize, threshold_bytes: threshold * 1024, days, dates: [] });
    } catch (error: any) {
      if (request === consecutiveRequest.current) message.error(error.message || '连续低流量用户加载失败');
    } finally {
      if (request === consecutiveRequest.current) setConsecutiveLoading(false);
    }
  };

  useEffect(() => {
    load(1, 20, '');
    loadLowTraffic(1, 20);
    loadConsecutiveTraffic(1, 20);
    return () => {
      statsRequest.current++;
      detailRequest.current++;
      uaRequest.current++;
      lowTrafficRequest.current++;
      consecutiveRequest.current++;
    };
  }, []);

  const search = () => {
    const value = keyword.trim();
    setAppliedKeyword(value);
    load(1, payload.page_size || 20, value, sort);
  };

  const applyTodayThreshold = () => {
    const value = Math.max(1, Math.round(Number(todayThresholdKB) || 200));
    setTodayThresholdKB(value);
    setAppliedTodayThresholdKB(value);
    loadLowTraffic(1, lowTraffic.page_size || 20, value);
  };

  const applyConsecutiveFilters = () => {
    const threshold = Math.max(1, Math.round(Number(consecutiveThresholdKB) || 200));
    const days = Math.min(365, Math.max(1, Math.round(Number(consecutiveDays) || 3)));
    setConsecutiveThresholdKB(threshold);
    setAppliedConsecutiveThresholdKB(threshold);
    setConsecutiveDays(days);
    setAppliedConsecutiveDays(days);
    loadConsecutiveTraffic(1, consecutiveTraffic.page_size || 20, threshold, days);
  };

  const summary = payload.summary || {};
  const columns: any[] = [
    { title: '用户 ID', dataIndex: 'user_id', width: 100, render: (value: any) => <Button type="link" onClick={() => showUserDetail(Number(value))}>{value}</Button> },
    { title: '邮箱', dataIndex: 'email', width: 260, ellipsis: true, render: (value: any) => <Typography.Text copyable={{ text: value }} ellipsis>{value || '-'}</Typography.Text> },
    { title: '订阅次数', dataIndex: 'count', width: 110 },
    { title: 'IP 数', dataIndex: 'ip_count', width: 90 },
    { title: 'UA 数', dataIndex: 'ua_count', width: 90 },
    { title: '最近 IP', dataIndex: 'last_ip', width: 170, render: (value: any) => <Typography.Text copyable={{ text: value }}>{value || '-'}</Typography.Text> },
    { title: '最近 User-Agent', dataIndex: 'last_ua', ellipsis: true, render: (value: any) => <Typography.Text ellipsis={{ tooltip: value }}>{value || '-'}</Typography.Text> },
    { title: '最近订阅', dataIndex: 'last_at', width: 180, render: formatTime },
  ];
  const rankingColumns: any[] = [
    { title: '值', dataIndex: 'value', render: (_: any, row: any) => <Typography.Text copyable={{ text: row.ip || row.ua }}>{row.ip || row.ua || '-'}</Typography.Text> },
    { title: '请求数', dataIndex: 'count', width: 100 },
  ];
  const uaUserColumns: any[] = [
    { title: '用户 ID', dataIndex: 'user_id', width: 100, render: (value: any) => <Button type="link" onClick={() => showUserDetail(Number(value))}>{value}</Button> },
    { title: '邮箱', dataIndex: 'email', ellipsis: true }, { title: '匹配请求', dataIndex: 'count', width: 100 },
    { title: 'IP 数', dataIndex: 'ip_count', width: 80 }, { title: 'UA 数', dataIndex: 'ua_count', width: 80 },
    { title: '最近请求', dataIndex: 'last_at', width: 180, render: formatTime },
  ];
  const recentColumns: any[] = [
    { title: '用户', key: 'user', width: 230, render: (_: any, row: any) => <Button type="link" onClick={() => showUserDetail(Number(row.user_id))}>{row.email || `#${row.user_id}`}</Button> },
    { title: 'IP', dataIndex: 'ip', width: 170, render: (value: any) => <Typography.Text copyable={value ? { text: value } : false}>{value || '-'}</Typography.Text> },
    { title: 'User-Agent', dataIndex: 'ua', ellipsis: true, render: (value: any) => <Typography.Text copyable={value ? { text: value } : false} ellipsis={{ tooltip: value }}>{value || '-'}</Typography.Text> },
    { title: '请求时间', dataIndex: 'accessed_at', width: 180, render: formatTime },
  ];
  const lowTrafficColumns: any[] = [
    { title: '用户 ID', dataIndex: 'user_id', width: 100 },
    { title: '邮箱', dataIndex: 'email', width: 260, ellipsis: true, render: (value: any) => <Typography.Text copyable={{ text: value }} ellipsis>{value || '-'}</Typography.Text> },
    { title: '今日计费流量', dataIndex: 'traffic_bytes', width: 150, render: bytes },
    { title: '最近 IP', dataIndex: 'last_ip', width: 170, render: (value: any) => <Typography.Text copyable={value ? { text: value } : false}>{value || '-'}</Typography.Text> },
    { title: '最近 User-Agent', dataIndex: 'last_ua', ellipsis: true, render: (value: any) => <Typography.Text ellipsis={{ tooltip: value }}>{value || '-'}</Typography.Text> },
    { title: '最近订阅', dataIndex: 'last_at', width: 180, render: formatTime },
  ];
  const consecutiveDates = Array.isArray(consecutiveTraffic.dates) ? consecutiveTraffic.dates : [];
  const consecutiveColumns: any[] = [
    { title: '用户 ID', dataIndex: 'user_id', width: 100, fixed: 'left' },
    { title: '邮箱', dataIndex: 'email', width: 240, fixed: 'left', ellipsis: true, render: (value: any) => <Typography.Text copyable={{ text: value }} ellipsis>{value || '-'}</Typography.Text> },
    ...consecutiveDates.map((recordAt: any) => ({
      title: new Date(Number(recordAt) * 1000).toLocaleDateString(),
      key: `traffic-${recordAt}`,
      width: 140,
      render: (_: any, record: any) => {
        const detail = Array.isArray(record.daily_traffic) ? record.daily_traffic.find((item: any) => Number(item.record_at) === Number(recordAt)) : null;
        return detail ? bytes(detail.traffic_bytes) : '-';
      },
    })),
    { title: '最近 IP', dataIndex: 'last_ip', width: 170, render: (value: any) => <Typography.Text copyable={value ? { text: value } : false}>{value || '-'}</Typography.Text> },
    { title: '最近 User-Agent', dataIndex: 'last_ua', width: 260, ellipsis: true, render: (value: any) => <Typography.Text ellipsis={{ tooltip: value }}>{value || '-'}</Typography.Text> },
    { title: '最近订阅', dataIndex: 'last_at', width: 180, render: formatTime },
  ];

  return <div className="legacy-page subscribe-access-page">
    <div className="block block-rounded">
      <div className="block-content p-0">
        <div className="row no-gutters">
          <div className="col-lg-6 col-xl-3 border-right p-4 border-bottom"><div>订阅请求</div><div className="mt-4 font-size-h3">{summary.requests || 0}</div></div>
          <div className="col-lg-6 col-xl-3 border-right p-4 border-bottom"><div>订阅用户</div><div className="mt-4 font-size-h3">{summary.users || 0}</div></div>
          <div className="col-lg-6 col-xl-3 border-right p-4 border-bottom"><div>独立 IP</div><div className="mt-4 font-size-h3">{summary.ips || 0}</div></div>
          <div className="col-lg-6 col-xl-3 p-4 border-bottom"><div>User-Agent</div><div className="mt-4 font-size-h3">{summary.user_agents || 0}</div></div>
        </div>
      </div>
    </div>
    <div className="row">
      <div className="col-lg-6"><div className="block block-rounded"><div className="block-header block-header-default"><h3 className="block-title">Top IP</h3></div><div className="block-content p-0"><Table rowKey="ip" size="small" pagination={false} columns={rankingColumns} dataSource={payload.top_ips || []} /></div></div></div>
      <div className="col-lg-6"><div className="block block-rounded"><div className="block-header block-header-default"><h3 className="block-title">Top User-Agent</h3></div><div className="block-content p-0"><Table rowKey="ua" size="small" pagination={false} columns={rankingColumns} dataSource={payload.top_uas || []} /></div></div></div>
    </div>
    <div className="block block-rounded">
      <div className="block-header block-header-default"><div><h3 className="block-title">User-Agent 反查用户</h3><Typography.Text type="secondary">按 UA 关键词查找曾使用该客户端请求订阅的用户。</Typography.Text></div><Input.Search value={uaKeyword} allowClear placeholder="例如 Clash、Shadowrocket" style={{ width: 320 }} onChange={(event) => setUAKeyword(event.target.value)} onSearch={applyUASearch} /></div>
      <div className="block-content p-0"><Table rowKey="user_id" loading={uaLoading} columns={uaUserColumns} dataSource={uaResult.data || []} pagination={{ current: uaResult.current || 1, pageSize: uaResult.page_size || 20, total: uaResult.total || 0, showSizeChanger: true }} onChange={(page) => searchUA(Number(page.current || 1), Number(page.pageSize || 20), appliedUAKeyword)} /></div>
    </div>
    <div className="block block-rounded">
      <div className="block-header block-header-default"><div><h3 className="block-title">成功订阅日志</h3><Typography.Text type="secondary">展示最近 100 条成功订阅请求；这里的保留期只影响成功订阅日志。</Typography.Text></div><Space><InputNumber value={keepDays} min={1} max={3650} precision={0} addonAfter="天保留" onChange={(value) => setKeepDays(Number(value || 7))} /><Button type="primary" onClick={saveRetention}>保存成功订阅日志保留期</Button></Space></div>
      <div className="block-content p-0"><Table rowKey="id" pagination={false} columns={recentColumns} dataSource={payload.recent || []} scroll={{ x: 1000 }} /></div>
    </div>
    <div className="block block-rounded">
      <div className="block-header block-header-default">
        <div>
          <h3 className="block-title">当日低流量用户</h3>
          <Typography.Text type="secondary">仅统计当日计费流量大于 0 且不超过 {bytes(lowTraffic.threshold_bytes || 200 * 1024)} 的用户，按节点倍率计算。</Typography.Text>
        </div>
        <Space wrap>
          <InputNumber
            value={todayThresholdKB}
            min={1}
            max={1_048_576}
            precision={0}
            addonAfter="KB"
            style={{ width: 180 }}
            onChange={(value) => setTodayThresholdKB(Number(value || 200))}
            onPressEnter={applyTodayThreshold}
          />
          <Button type="primary" onClick={applyTodayThreshold}>应用</Button>
          <Button icon={<ReloadOutlined />} onClick={() => loadLowTraffic(lowTraffic.current || 1)} title="刷新" />
        </Space>
      </div>
      <div className="block-content p-0">
        <Table
          className="forest-table"
          rowKey="user_id"
          loading={lowTrafficLoading}
          columns={lowTrafficColumns}
          dataSource={Array.isArray(lowTraffic.data) ? lowTraffic.data : []}
          scroll={{ x: 1100 }}
          pagination={{
            current: Number(lowTraffic.current || 1),
            pageSize: Number(lowTraffic.page_size || 20),
            total: Number(lowTraffic.total || 0),
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 位用户`,
          }}
          onChange={(pagination) => loadLowTraffic(Number(pagination.current || 1), Number(pagination.pageSize || 20))}
        />
      </div>
    </div>
    <div className="block block-rounded">
      <div className="block-header block-header-default">
        <div>
          <h3 className="block-title">连续 {consecutiveTraffic.days || appliedConsecutiveDays} 天低流量用户</h3>
          <Typography.Text type="secondary">必须每天流量都大于 0 且每天都不超过 {bytes(consecutiveTraffic.threshold_bytes || 200 * 1024)}，缺少任意一天或任意一天超出阈值均不统计。</Typography.Text>
        </div>
        <Space wrap>
          <InputNumber
            value={consecutiveDays}
            min={1}
            max={365}
            precision={0}
            addonAfter="天"
            style={{ width: 140 }}
            onChange={(value) => setConsecutiveDays(Number(value || 3))}
            onPressEnter={applyConsecutiveFilters}
          />
          <InputNumber
            value={consecutiveThresholdKB}
            min={1}
            max={1_048_576}
            precision={0}
            addonAfter="KB/天"
            style={{ width: 190 }}
            onChange={(value) => setConsecutiveThresholdKB(Number(value || 200))}
            onPressEnter={applyConsecutiveFilters}
          />
          <Button type="primary" onClick={applyConsecutiveFilters}>应用</Button>
          <Button icon={<ReloadOutlined />} onClick={() => loadConsecutiveTraffic(consecutiveTraffic.current || 1)} title="刷新" />
        </Space>
      </div>
      <div className="block-content p-0">
        <Table
          className="forest-table"
          rowKey="user_id"
          loading={consecutiveLoading}
          columns={consecutiveColumns}
          dataSource={Array.isArray(consecutiveTraffic.data) ? consecutiveTraffic.data : []}
          scroll={{ x: 950 + consecutiveDates.length * 140 }}
          pagination={{
            current: Number(consecutiveTraffic.current || 1),
            pageSize: Number(consecutiveTraffic.page_size || 20),
            total: Number(consecutiveTraffic.total || 0),
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 位用户`,
          }}
          onChange={(pagination) => loadConsecutiveTraffic(Number(pagination.current || 1), Number(pagination.pageSize || 20))}
        />
      </div>
    </div>
    <div className="block block-rounded">
      <div className="block-header block-header-default">
        <h3 className="block-title">用户订阅记录</h3>
        <Space wrap>
          <Select value={sort} style={{ width: 150 }} options={[{ value: 'count', label: '按请求数排序' }, { value: 'ip_count', label: '按 IP 数排序' }]} onChange={(value) => { setSort(value); load(1, payload.page_size || 20, appliedKeyword, value); }} />
          <Input.Search
            value={keyword}
            allowClear
            placeholder="输入用户 ID 或邮箱"
            style={{ width: 300 }}
            onChange={(event) => setKeyword(event.target.value)}
            onSearch={search}
          />
          <Button icon={<ReloadOutlined />} onClick={() => load(payload.current || 1)} title="刷新" />
        </Space>
      </div>
      <div className="block-content p-0">
        <Table
          className="forest-table"
          rowKey="user_id"
          loading={loading}
          columns={columns}
          dataSource={Array.isArray(payload.data) ? payload.data : []}
          scroll={{ x: 1250 }}
          pagination={{
            current: Number(payload.current || 1),
            pageSize: Number(payload.page_size || 20),
            total: Number(payload.total || 0),
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 位用户`,
          }}
          onChange={(pagination) => load(Number(pagination.current || 1), Number(pagination.pageSize || 20))}
        />
      </div>
    </div>
    <Modal title={`用户订阅详情 #${userDetail?.user_id || ''}`} open={!!userDetail} width={980} footer={null} onCancel={() => setUserDetail(null)}>
      <Descriptions bordered size="small" column={3}>
        <Descriptions.Item label="邮箱">{userDetail?.email || '-'}</Descriptions.Item><Descriptions.Item label="套餐">{userDetail?.plan_name || '-'}</Descriptions.Item><Descriptions.Item label="状态">{Number(userDetail?.banned) ? '已禁用' : '正常'}</Descriptions.Item>
        <Descriptions.Item label="已用流量">{bytes(userDetail?.used || 0)}</Descriptions.Item><Descriptions.Item label="总流量">{bytes(userDetail?.transfer_enable || 0)}</Descriptions.Item><Descriptions.Item label="到期时间">{formatTime(userDetail?.expired_at)}</Descriptions.Item>
        <Descriptions.Item label="请求数">{userDetail?.total || 0}</Descriptions.Item><Descriptions.Item label="IP 数">{userDetail?.ip_count || 0}</Descriptions.Item><Descriptions.Item label="UA 数">{userDetail?.ua_count || 0}</Descriptions.Item>
      </Descriptions>
      <Space className="mt-3"><Typography.Title level={5} style={{ margin: 0 }}>IP 明细</Typography.Title><Button size="small" onClick={() => copyDetailValues('ip')}>复制全部 IP</Button></Space><Table loading={detailLoading} rowKey="ip" size="small" pagination={false} columns={rankingColumns} dataSource={userDetail?.ips || []} />
      <Space className="mt-3"><Typography.Title level={5} style={{ margin: 0 }}>User-Agent 明细</Typography.Title><Button size="small" onClick={() => copyDetailValues('ua')}>复制全部 UA</Button></Space><Table loading={detailLoading} rowKey="ua" size="small" pagination={false} columns={rankingColumns} dataSource={userDetail?.uas || []} />
      <Typography.Title level={5}>最近请求</Typography.Title><Table loading={detailLoading} rowKey="id" size="small" pagination={false} columns={recentColumns} dataSource={userDetail?.recent || []} scroll={{ x: 900 }} />
    </Modal>
  </div>;
}
