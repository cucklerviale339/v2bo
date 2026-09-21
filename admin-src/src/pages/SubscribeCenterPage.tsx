import React, { useState } from 'react';
import { Tabs, Typography } from 'antd';
import SubscribeAccessPage from './SubscribeAccessPage';
import SubscribeGuardPage from './SubscribeGuardPanel';

type Tab = 'stats' | 'requests' | 'crawler' | 'settings';

export default function SubscribeCenterPage({ initialTab = 'stats' }: { initialTab?: Tab }) {
  const [activeKey, setActiveKey] = useState<Tab>(initialTab);
  const [guardVisited, setGuardVisited] = useState(initialTab !== 'stats');

  return (
    <div className="legacy-page subscribe-center-page">
      <div className="content-heading">订阅中心</div>
      <Typography.Paragraph type="secondary">统计始终可用。订阅统计展示成功获取订阅及低流量用户；请求记录包含放行、失败和拦截。爬虫 UA 默认只记录，拦截需单独开启。</Typography.Paragraph>
      <Tabs
        activeKey={activeKey}
        onChange={value => { setActiveKey(value as Tab); if (value !== 'stats') setGuardVisited(true); }}
        items={[
          { key: 'stats', label: '订阅统计' },
          { key: 'requests', label: '请求与拦截记录' },
          { key: 'crawler', label: '爬虫 UA 用户' },
          { key: 'settings', label: '防护设置' },
        ]}
      />
      <div hidden={activeKey !== 'stats'}><SubscribeAccessPage /></div>
      {guardVisited && <div hidden={activeKey === 'stats'}><SubscribeGuardPage view={activeKey === 'stats' ? 'requests' : activeKey} /></div>}
    </div>
  );
}
