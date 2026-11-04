export type ProbeStatus = {
  enabled: boolean;
  online?: boolean;
  last_heartbeat_at?: number;
  status_checked_at?: number;
  received_at_ms?: number;
};

// Only a fresh server snapshot can confirm online/offline. A failed browser
// refresh is not evidence that the probe stopped sending heartbeats.
export function dnsProbeStatus(probe: ProbeStatus | undefined, nowMS: number, offlineSec = 90): 'online' | 'offline' | 'disabled' | 'stale' {
  if (!probe?.enabled) return 'disabled';
  if (!Number.isFinite(probe.received_at_ms) || nowMS - probe.received_at_ms >= 60000) return 'stale';
  if (offlineSec === 90 && typeof probe.online === 'boolean') return probe.online ? 'online' : 'offline';
  if (!Number.isFinite(probe.last_heartbeat_at) || probe.last_heartbeat_at <= 0 || offlineSec <= 0) return 'offline';
  const checked = probe.status_checked_at;
  if (Number.isFinite(checked) && checked > 0 && Number.isFinite(probe.received_at_ms)) {
    return probe.last_heartbeat_at <= checked && checked - probe.last_heartbeat_at <= offlineSec ? 'online' : 'offline';
  }
  // Compatibility when loading an older backend during an upgrade.
  const now = Date.now() / 1000;
  return probe.last_heartbeat_at <= now && now - probe.last_heartbeat_at <= offlineSec ? 'online' : 'offline';
}

export function dnsProbeOnline(probe: ProbeStatus | undefined, nowMS: number, offlineSec = 90): boolean {
  return dnsProbeStatus(probe, nowMS, offlineSec) === 'online';
}
