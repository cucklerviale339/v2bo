import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Card, Form, Input, InputNumber, Modal, Popconfirm, Segmented, Select, Space, Spin, Switch, Table, Tag, message } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { apiGet, apiPost } from '../lib/api';

function splitList(value: any): string[] {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  return String(value || '').split(/[\n,]+/).map((item) => item.trim()).filter((item, index, arr) => !!item && arr.indexOf(item) === index);
}

function splitLines(value: any): string[] {
  const values = Array.isArray(value) ? value : String(value || '').split(/\r?\n/);
  return values.map((item) => String(item).trim()).filter(Boolean);
}

function normalizeRule(rule: any = {}, index = 0) {
  return {
    ...rule,
    match_user_ids: splitList(rule.match_user_ids),
    match_user_id_ranges: splitList(rule.match_user_id_ranges),
    extra_nodes: splitLines(rule.extra_nodes).join('\n'),
    extra_nodes_position: rule.extra_nodes_position === 'before' ? 'before' : 'replace',
    enabled: rule.enabled === undefined ? true : !!Number(rule.enabled),
    sort: rule.sort ?? index,
  };
}

function normalizeGroup(row: any = {}) {
  return {
    ...row,
    enabled: row.enabled === undefined ? true : !!Number(row.enabled),
    rules: Array.isArray(row.rules) ? row.rules.map(normalizeRule) : [],
  };
}

function savePayload(values: any) {
  return {
    ...values,
    enabled: values.enabled ? 1 : 0,
    rules: (Array.isArray(values.rules) ? values.rules : []).map((rule: any, index: number) => ({
      ...rule,
      match_user_ids: splitList(rule.match_user_ids),
      match_user_id_ranges: splitList(rule.match_user_id_ranges),
      extra_nodes: splitLines(rule.extra_nodes),
      extra_nodes_position: rule.extra_nodes_position === 'before' ? 'before' : 'replace',
      enabled: rule.enabled ? 1 : 0,
      sort: rule.sort ?? index,
    })),
  };
}

function ruleSummary(rule: any) {
  const parts: string[] = [];
  if (splitList(rule.match_user_ids).length) parts.push('明确ID');
  if (splitList(rule.match_user_id_ranges).length) parts.push('ID范围');
  const extraNodeCount = splitLines(rule.extra_nodes).length;
  if (extraNodeCount) parts.push(`额外节点 ${extraNodeCount}`);
  return parts.length ? parts.join(' / ') : '未配置条件';
}

function validateUserIDs(_: any, value: any) {
  const invalid = splitList(value).find((item) => !/^[1-9]\d*$/.test(item));
  return invalid ? Promise.reject(new Error('用户ID必须是正整数')) : Promise.resolve();
}

function validateUserIDRanges(_: any, value: any) {
  const invalid = splitList(value).find((item) => !/^[1-9]\d*\s*-\s*[1-9]\d*$/.test(item));
  return invalid ? Promise.reject(new Error('ID范围格式应为起始ID-结束ID')) : Promise.resolve();
}

type UserLookupOption = {
  value: string;
  label: string;
  email?: string;
};

function mergeUserLookupOptions(current: UserLookupOption[], rows: any): UserLookupOption[] {
  const next = new Map(current.map((item) => [item.value, item]));
  (Array.isArray(rows) ? rows : []).forEach((row: any) => {
    const id = String(row?.id || '').trim();
    const email = String(row?.email || '').trim();
    if (!/^[1-9]\d*$/.test(id) || !email) return;
    next.set(id, { value: id, label: `${email}（ID: ${id}）`, email });
  });
  return Array.from(next.values());
}

export function UserEmailSelect({ value, onChange }: { value?: any; onChange?: (value: string[]) => void }) {
  const selectedIDs = splitList(value);
  const selectedKey = selectedIDs.join(',');
  const [options, setOptions] = useState<UserLookupOption[]>([]);
  const [searchResultIDs, setSearchResultIDs] = useState<string[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchAttempted, setSearchAttempted] = useState(false);
  const [searchFailed, setSearchFailed] = useState(false);
  const searchTimer = useRef<ReturnType<typeof window.setTimeout> | null>(null);
  const searchSequence = useRef(0);

  useEffect(() => {
    if (!selectedKey) return;
    let active = true;
    apiGet('/user/lookup', { ids: selectedKey })
      .then((res) => {
        if (active) setOptions((current) => mergeUserLookupOptions(current, res?.data));
      })
      .catch(() => undefined);
    return () => { active = false; };
  }, [selectedKey]);

  useEffect(() => () => {
    if (searchTimer.current !== null) window.clearTimeout(searchTimer.current);
  }, []);

  const selectOptions = useMemo(() => {
    const known = new Map(options.map((item) => [item.value, item]));
    const next = new Map<string, UserLookupOption>();
    [...searchResultIDs, ...selectedIDs].forEach((id) => {
      if (next.has(id)) return;
      next.set(id, known.get(id) || { value: id, label: `用户 ID: ${id}` });
    });
    return Array.from(next.values());
  }, [options, searchResultIDs, selectedKey]);

  const search = (raw: string) => {
    if (searchTimer.current !== null) window.clearTimeout(searchTimer.current);
    const keyword = raw.trim();
    const sequence = ++searchSequence.current;
    setSearchFailed(false);
    setSearchResultIDs([]);
    if (!keyword) {
      setSearching(false);
      setSearchAttempted(false);
      return;
    }

    setSearchAttempted(true);
    searchTimer.current = window.setTimeout(async () => {
      setSearching(true);
      try {
        const params = /^[1-9]\d*$/.test(keyword) ? { ids: keyword } : { keyword, limit: 20 };
        const res = await apiGet('/user/lookup', params);
        if (sequence !== searchSequence.current) return;
        const resultOptions = mergeUserLookupOptions([], res?.data);
        setOptions((current) => mergeUserLookupOptions(current, res?.data));
        setSearchResultIDs(resultOptions.map((item) => item.value));
      } catch {
        if (sequence === searchSequence.current) setSearchFailed(true);
      } finally {
        if (sequence === searchSequence.current) setSearching(false);
      }
    }, 350);
  };

  return <Select
    mode="tags"
    allowClear
    showSearch
    filterOption={false}
    tokenSeparators={[',', '，']}
    value={selectedIDs}
    options={selectOptions}
    loading={searching}
    maxTagCount="responsive"
    placeholder="输入邮箱搜索，或输入用户ID"
    onSearch={search}
    onChange={(values) => {
      const items = splitList(values);
      const optionByEmail = new Map(options.filter((item) => item.email).map((item) => [String(item.email).toLowerCase(), item.value]));
      const ids: string[] = [];
      let invalid = false;
      items.forEach((item) => {
        if (/^[1-9]\d*$/.test(item)) {
          ids.push(item);
          return;
        }
        const matchedID = optionByEmail.get(item.toLowerCase());
        if (matchedID) ids.push(matchedID);
        else invalid = true;
      });
      if (invalid) message.warning('邮箱需要从检索结果中选择');
      onChange?.(Array.from(new Set(ids)));
    }}
    notFoundContent={searching ? <Spin size="small" /> : searchFailed ? '检索失败' : searchAttempted ? '未找到用户' : '输入邮箱或用户ID'}
  />;
}

export default function NodeAddressPage() {
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [togglingID, setTogglingID] = useState<any>(null);
  const [edit, setEdit] = useState<any>(null);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      const res = await apiGet('/server/address/fetch');
      setRows(Array.isArray(res.data) ? res.data : []);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const openEditor = (row?: any) => {
    const next = normalizeGroup(row || { name: '', description: '', enabled: true });
    setEdit(next);
    form.resetFields();
    form.setFieldsValue(next);
  };

  const save = async () => {
    setSaving(true);
    try {
      const values = await form.validateFields();
      await apiPost('/server/address/save', savePayload({ ...edit, ...values }));
      message.success('保存成功');
      setEdit(null);
      load();
    } catch (e: any) {
      if (!e?.errorFields) message.error(e.message || '保存失败');
    } finally {
      setSaving(false);
    }
  };

  const drop = async (row: any) => {
    await apiPost('/server/address/drop', { id: row.id }, { form: true });
    message.success('已删除');
    load();
  };

  const toggleEnabled = async (row: any, enabled: boolean) => {
    setTogglingID(row.id);
    try {
      await apiPost('/server/address/save', savePayload({ ...normalizeGroup(row), enabled }));
      message.success('保存成功');
      load();
    } catch (e: any) {
      message.error(e.message || '保存失败');
      load();
    } finally {
      setTogglingID(null);
    }
  };

  const columns: any[] = [
    { title: 'ID', dataIndex: 'id', width: 80 },
    { title: '地址组名称', dataIndex: 'name', width: 180 },
    { title: '说明', dataIndex: 'description', render: (value: any) => value || '-' },
    { title: '规则', dataIndex: 'rules', width: 260, render: (rules: any[]) => {
      const list = Array.isArray(rules) ? rules : [];
      if (!list.length) return '无规则';
      return <Space wrap>{list.map((rule, index) => <Tag key={rule.id || index}>{rule.name || ruleSummary(rule)}</Tag>)}</Space>;
    } },
    { title: '绑定节点', dataIndex: 'bindings', width: 150, render: (bindings: any[]) => {
      const count = Array.isArray(bindings) ? bindings.length : 0;
      return count ? `${count} 个节点` : '-';
    } },
    { title: '启用', dataIndex: 'enabled', width: 90, render: (enabled: any, row: any) => <Switch size="small" checked={!!Number(enabled)} loading={togglingID === row.id} onChange={(checked) => toggleEnabled(row, checked)} /> },
    { title: '操作', dataIndex: 'action', align: 'right', width: 120, render: (_: any, row: any) => <Space split={<span className="ant-divider ant-divider-vertical" />}><a onClick={() => openEditor(row)}>编辑</a><Popconfirm title="确认删除？" onConfirm={() => drop(row)}><a>删除</a></Popconfirm></Space> },
  ];

  return <div className="legacy-page node-address-page">
    <div className="content-heading">节点地址</div>
    <Spin spinning={loading}>
      <Card className="block-card" styles={{ body: { padding: 0 } }}>
        <div className="forest-table-action"><Button icon={<PlusOutlined />} onClick={() => openEditor()}>新建地址组</Button></div>
        <Table className="forest-table" rowKey="id" tableLayout="auto" columns={columns} dataSource={rows} pagination={false} scroll={{ x: 760 }} />
      </Card>
    </Spin>

    <Modal title={edit?.id ? '编辑地址组' : '新建地址组'} open={!!edit} onCancel={() => setEdit(null)} onOk={save} okText="提交" confirmLoading={saving} width={960} destroyOnHidden>
      <Form form={form} layout="vertical" className="legacy-node-address-form">
        <Form.Item name="id" hidden><Input /></Form.Item>
        <Form.Item name="name" label="地址组名称" rules={[{ required: true, message: '请输入地址组名称' }]}><Input placeholder="请输入地址组名称" /></Form.Item>
        <Form.Item name="description" label="说明"><Input placeholder="请输入说明" /></Form.Item>
        <Form.List name="rules">
          {(fields, { add, remove }) => <>
            <div className="node-address-rule-head">
              <span>地址规则</span>
              <Button size="small" icon={<PlusOutlined />} onClick={() => add({ name: '', host: '', extra_nodes: '', extra_nodes_position: 'replace', enabled: true, sort: fields.length })}>添加规则</Button>
            </div>
            {fields.map((field, index) => <div key={field.key} className="node-address-rule-item">
              <div className="node-address-rule-title">
                <span>规则 {index + 1}</span>
                <Button size="small" danger icon={<DeleteOutlined />} onClick={() => remove(field.name)} />
              </div>
              <div className="form-grid">
                <div className="form-col-8"><Form.Item name={[field.name, 'name']} label="规则名称"><Input placeholder="规则名称" /></Form.Item></div>
                <div className="form-col-10"><Form.Item name={[field.name, 'host']} label="节点下发地址" dependencies={[['rules', field.name, 'extra_nodes']]} extra="额外节点为空时使用。" rules={[{ validator: async (_, value) => {
                  const extraNodes = splitLines(form.getFieldValue(['rules', field.name, 'extra_nodes']));
                  if (!String(value || '').trim() && !extraNodes.length) throw new Error('下发地址和额外节点至少填写一个');
                } }]}><Input placeholder="example.com" /></Form.Item></div>
                <div className="form-col-3"><Form.Item name={[field.name, 'sort']} label="排序"><InputNumber style={{ width: '100%' }} min={0} /></Form.Item></div>
                <div className="form-col-3"><Form.Item name={[field.name, 'enabled']} label="启用" valuePropName="checked"><Switch /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_user_ids']} label="明确用户" rules={[{ validator: validateUserIDs }]}><UserEmailSelect /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_user_id_ranges']} label="用户ID范围" rules={[{ validator: validateUserIDRanges }]}><Select mode="tags" tokenSeparators={[',']} placeholder="例如 1-100，回车确认" /></Form.Item></div>
                <div className="form-col-24"><Form.Item name={[field.name, 'extra_nodes']} label="额外下发节点" extra="一行一个完整节点 URI；可覆盖命中规则绑定的本站节点，或保留本站节点并置于其之前。"><Input.TextArea rows={4} placeholder={'trojan://password@example.com:443#备用节点\nvless://uuid@example.com:443?...'} /></Form.Item></div>
                <div className="form-col-12"><Form.Item name={[field.name, 'extra_nodes_position']} label="额外节点方式"><Segmented block options={[{ label: '覆盖原节点', value: 'replace' }, { label: '置于原节点之前', value: 'before' }]} /></Form.Item></div>
              </div>
            </div>)}
          </>}
        </Form.List>
      </Form>
    </Modal>
  </div>;
}
