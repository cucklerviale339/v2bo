import React from 'react';
import { Tag } from 'antd';

export type DispatchMonitorStatusEntry = {
  enabled: boolean;
  deleted?: boolean;
  probe_ids: number[];
  states: { stale: boolean; success: boolean | null }[];
};

// Both entry monitoring and failover show the same server-calculated freshness.
export default function DispatchMonitorStatus({ entry }: { entry: DispatchMonitorStatusEntry }) {
  if (entry.deleted) return <Tag>已删除</Tag>;
  if (!entry.enabled) return <Tag>未启用</Tag>;
  const fresh = entry.states.filter(state => !state.stale && state.success !== null);
  if (fresh.some(state => state.success === false)) return <Tag color="error">异常</Tag>;
  if (fresh.length === entry.probe_ids.length && fresh.length) return <Tag color="success">正常</Tag>;
  if (fresh.length) return <Tag color="warning">部分探针无新鲜数据</Tag>;
  return <Tag color="default">等待测活 / 数据过期</Tag>;
}
