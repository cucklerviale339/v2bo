import { getAdminPath, getAdminUserInfo } from './api';

type PortScope = 'entry' | 'pool';
const validPort = (port: unknown): port is number => typeof port === 'number' && Number.isInteger(port) && port >= 1 && port <= 65535;
const key = (scope: PortScope) => `forest_monitor_port:${getAdminPath()}:${getAdminUserInfo().id || getAdminUserInfo().email || 'admin'}:${scope}`;

export function getMonitorPort(scope: PortScope): number {
  try {
    const value = Number(localStorage.getItem(key(scope)));
    return validPort(value) ? value : 443;
  } catch { return 443; }
}

export function rememberMonitorPort(scope: PortScope, port: unknown) {
  if (!validPort(port)) return;
  try { localStorage.setItem(key(scope), String(port)); } catch { /* A blocked store must not prevent configuration. */ }
}
