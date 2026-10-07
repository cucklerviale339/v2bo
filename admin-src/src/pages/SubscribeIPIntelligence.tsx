import React from 'react';
import { Space, Tag, Typography } from 'antd';

export type IPIntelligence = {
  ip: string; geo_state: string; risk_state: string; asn: number; country: string; country_code: string;
  network: string; hosting: boolean | null; proxy: boolean | null; mobile: boolean | null;
  checked_at: number; expires_at: number;
};
const states: Record<string, string> = { pending: '等待查询', unavailable: '查询失败 / 未知', expired: '缓存过期，等待刷新', non_public: '非公网地址，不查询' };

export default function SubscribeIPIntelligence({ value, ip }: { value?: IPIntelligence; ip?: string }) {
  const geoReady = value?.geo_state === 'ok';
  const riskReady = value?.risk_state === 'ok';
  return <Space direction="vertical" size={2} style={{ maxWidth: 290, overflowWrap: 'anywhere' }}>
    <Typography.Text copyable={value?.ip || ip ? { text: value?.ip || ip || '' } : false}>{value?.ip || ip || '-'}</Typography.Text>
    <Typography.Text type="secondary">{geoReady ? `${value.country || value.country_code} · AS${value.asn}` : `国家 / ASN：${states[value?.geo_state || 'pending'] || '未知'}`}</Typography.Text>
    {geoReady && value?.network && <Typography.Text type="secondary">{value.network}</Typography.Text>}
    {riskReady ? <Space size={[2, 2]} wrap>
      <Tag color={value.hosting ? 'orange' : 'default'}>{value.hosting ? 'IDC / 云服务' : '未检测到 IDC 信号'}</Tag>
      <Tag color={value.proxy ? 'orange' : 'default'}>{value.proxy ? '代理 / VPN / Tor 信号' : '未检测到代理信号'}</Tag>
      {value.mobile && <Tag>移动网络</Tag>}
    </Space> : <Typography.Text type="secondary">网络标签：{states[value?.risk_state || 'pending'] || '未知'}</Typography.Text>}
    {!!value?.checked_at && <Typography.Text type="secondary" style={{ fontSize: 12 }}>查询于 {new Date(value.checked_at * 1000).toLocaleString()}</Typography.Text>}
  </Space>;
}
