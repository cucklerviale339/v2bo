import React, { useState } from 'react';
import { Tabs, Typography } from 'antd';
import SubscribeAccessPage from './SubscribeAccessPage';
import SubscribeGuardPage from './SubscribeGuardPanel';

type Tab = 'stats' | 'requests' | 'crawler' | 'settings';

export default function SubscribeCenterPage({ initialTab = 'stats' }: { initialTab?: Tab }) {
  const [activeKey, setActiveKey] = useState<Tab>(initialTab === 'settings' ? 'stats' : initialTab);
  const guardView = activeKey === 'requests' || activeKey === 'crawler' ? activeKey : 'settings';

  return (
    <div className="legacy-page subscribe-center-page">
      <div className="content-heading">订阅中心</div>
      <Typography.Paragraph type="secondary">订阅统计与防护设置已合并展示。统计始终可用；请求记录包含放行、失败和拦截；爬虫 UA 默认只记录，拦截需单独开启。</Typography.Paragraph>
      <Tabs
        activeKey={activeKey}
        onChange={value => setActiveKey(value as Tab)}
        items={[
          { key: 'stats', label: '统计与防护' },
          { key: 'requests', label: '请求与拦截记录' },
          { key: 'crawler', label: '爬虫 UA 用户' },
        ]}
      />
      <div hidden={activeKey !== 'stats'}>
        <SubscribeAccessPage />
        <div id="subscribe-guard-settings"><SubscribeGuardPage view="settings" /></div>
      </div>
      <div hidden={activeKey === 'stats'}><SubscribeGuardPage view={guardView} /></div>
    </div>
  );
}
