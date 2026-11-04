import { useCallback, useEffect, useRef, useState } from 'react';
import { message } from 'antd';
import { apiGet, unwrapList } from './api';
import { ProbeStatus } from './dnsProbeStatus';

export type DNSProbe = ProbeStatus & {
  id: number; name: string; version?: string; arch?: string; public_ip?: string;
  prewarm_count?: number; secret?: string; install_command?: string;
};

export function useDNSProbes(live = true) {
  const [probes, setProbes] = useState<DNSProbe[]>([]);
  const [probeNow, setProbeNow] = useState(() => performance.now());
  const active = useRef(true);
  const pending = useRef<AbortController | null>(null);
  const loadProbes = useCallback(async (quiet = false) => {
    if (!active.current || quiet && pending.current) return;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    try {
      const response = await apiGet('/dns-failover/probes', {}, { signal: controller.signal, cache: 'no-store' });
      if (!active.current || controller.signal.aborted || pending.current !== controller) return;
      const received = performance.now();
      setProbes(unwrapList(response).map(probe => ({ ...probe, received_at_ms: received })));
      setProbeNow(received);
    } catch (error: any) {
      if (active.current && pending.current === controller && !quiet && !controller.signal.aborted) message.error(error.message || '探针加载失败');
    } finally {
      window.clearTimeout(timeout);
      if (pending.current === controller) pending.current = null;
    }
  }, []);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      pending.current?.abort();
      pending.current = null;
    };
  }, []);

  useEffect(() => {
    if (!live) return;
    const refresh = () => {
      if (document.visibilityState === 'hidden') return;
      setProbeNow(performance.now());
      void loadProbes(true);
    };
    refresh();
    const timer = window.setInterval(refresh, 30000);
    document.addEventListener('visibilitychange', refresh);
    window.addEventListener('focus', refresh);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', refresh);
      window.removeEventListener('focus', refresh);
    };
  }, [live, loadProbes]);
  return { probes, probeNow, loadProbes };
}
