import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createContext, runInContext } from 'node:vm';
import ts from 'typescript';

const source = await readFile(new URL('../src/pages/DispatchInvestigationPanel.tsx', import.meta.url), 'utf8');
const start = source.indexOf('function singletonManual(');
const end = source.indexOf('export default function', start);
const context = createContext({});
runInContext(ts.transpileModule(source.slice(start, end), {
  compilerOptions: { target: ts.ScriptTarget.ES2020 },
}).outputText, context);

test('timeout is visible even when promotion is held; disabled and manual policies still win', () => {
  const group = { user_ids: ['1', '2'], kind: 'observation', policy: 'smart', reason: '自动处理超时，等待重试', promotion_hold_count: 2 };
  assert.equal(context.processState(group, true).label, '超时待重试');
  assert.equal(context.processState(group, true).tone, 'error');
  assert.equal(context.processState(group, false).label, '已关闭');
  assert.equal(context.processState({ ...group, manual_only: true }, true).label, '仅人工');
  assert.equal(context.processState({ ...group, policy: 'fixed' }, true).label, '固定下发');
  assert.equal(context.processState({ ...group, reason: '正常观察中' }, true).label, '待复核·不晋级');
});
