import React, { useEffect, useState } from 'react';
import { Button, Card, Checkbox, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Spin, Switch, Table, Tag, message } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { apiGet, apiPost } from '../lib/api';

function splitList(value: any): string[] {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  return String(value || '').split(/[\n,]+/).map((item) => item.trim()).filter((item, index, arr) => !!item && arr.indexOf(item) === index);
}

function normalizeRule(rule: any = {}, index = 0) {
  return {
    ...rule,
    match_user_ids: splitList(rule.match_user_ids),
    match_plan_ids: splitList(rule.match_plan_ids),
    match_group_ids: splitList(rule.match_group_ids),
    match_ua_keywords: splitList(rule.match_ua_keywords),
    exclude_ua_keywords: splitList(rule.exclude_ua_keywords),
    no_ua: !!rule.no_ua,
    is_default: !!rule.is_default,
    show: rule.show === undefined ? true : !!Number(rule.show),
    sort: rule.sort ?? index,
  };
}

function normalizeGroup(row: any = {}) {
  return {
    ...row,
    show: row.show === undefined ? true : !!Number(row.show),
    rules: Array.isArray(row.rules) && row.rules.length > 0
      ? row.rules.map(normalizeRule)
      : [{ name: '默认地址', host: '', show: true, sort: 0, is_default: true }],
  };
}

function savePayload(values: any) {
  return {
    ...values,
    show: values.show ? 1 : 0,
    rules: (Array.isArray(values.rules) ? values.rules : []).map((rule: any, index: number) => ({
      ...rule,
      match_user_ids: splitList(rule.match_user_ids),
      match_plan_ids: splitList(rule.match_plan_ids),
      match_group_ids: splitList(rule.match_group_ids),
      match_ua_keywords: splitList(rule.match_ua_keywords),
      exclude_ua_keywords: splitList(rule.exclude_ua_keywords),
      no_ua: !!rule.no_ua,
      is_default: !!rule.is_default,
      show: rule.show ? 1 : 0,
      sort: rule.sort ?? index,
      min_registered_days: rule.min_registered_days ?? undefined,
      max_registered_days: rule.max_registered_days ?? undefined,
    })),
  };
}

function ruleSummary(rule: any) {
  if (rule.is_default) return '默认';
  const parts: string[] = [];
  if (splitList(rule.match_user_ids).length) parts.push('用户');
  if (splitList(rule.match_plan_ids).length) parts.push('套餐');
  if (splitList(rule.match_group_ids).length) parts.push('权限组');
  if (splitList(rule.match_ua_keywords).length) parts.push('客户端');
  if (splitList(rule.exclude_ua_keywords).length) parts.push('排除客户端');
  if (rule.no_ua) parts.push('无UA');
  if (rule.min_registered_days !== undefined || rule.max_registered_days !== undefined) parts.push('注册天数');
  return parts.length ? parts.join(' / ') : '默认';
}

export default function NodeAddressPage() {
  const [rows, setRows] = useState<any[]>([]);
  const [groups, setGroups] = useState<any[]>([]);
  const [plans, setPlans] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [edit, setEdit] = useState<any>(null);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      const [res, groupRes, planRes] = await Promise.all([
        apiGet('/server/address/fetch'),
        apiGet('/server/group/fetch').catch(() => ({ data: [] })),
        apiGet('/plan/fetch').catch(() => ({ data: [] })),
      ]);
      setRows(Array.isArray(res.data) ? res.data : []);
      setGroups(Array.isArray(groupRes.data) ? groupRes.data : []);
      setPlans(Array.isArray(planRes.data) ? planRes.data : []);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const openEditor = (row?: any) => {
    const next = normalizeGroup(row || { name: '', description: '', show: true });
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

  const groupOptions = groups.map((group) => ({ label: group.name, value: String(group.id) }));
  const planOptions = plans.map((plan) => ({ label: plan.name || `#${plan.id}`, value: String(plan.id) }));

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
    { title: '显示', dataIndex: 'show', width: 90, render: (show: any) => <Tag color={Number(show) ? 'green' : 'default'}>{Number(show) ? '显示' : '隐藏'}</Tag> },
    { title: '操作', dataIndex: 'action', align: 'right', width: 120, render: (_: any, row: any) => <Space split={<span className="ant-divider ant-divider-vertical" />}><a onClick={() => openEditor(row)}>编辑</a><Popconfirm title="确认删除？" onConfirm={() => drop(row)}><a>删除</a></Popconfirm></Space> },
  ];

  return <div className="legacy-page node-address-page">
    <div className="content-heading">节点地址</div>
    <Spin spinning={loading}>
      <Card className="block-card" styles={{ body: { padding: 0 } }}>
        <div className="forest-table-action"><Button icon={<PlusOutlined />} onClick={() => openEditor()}>新建地址组</Button></div>
        <Table className="forest-table" rowKey="id" tableLayout="auto" columns={columns} dataSource={rows} pagination={false} scroll={{ x: 980 }} />
      </Card>
    </Spin>

    <Modal title={edit?.id ? '编辑地址组' : '新建地址组'} open={!!edit} onCancel={() => setEdit(null)} onOk={save} okText="提交" confirmLoading={saving} width={960} destroyOnHidden>
      <Form form={form} layout="vertical" className="legacy-node-address-form">
        <Form.Item name="id" hidden><Input /></Form.Item>
        <Form.Item name="name" label="地址组名称" rules={[{ required: true, message: '请输入地址组名称' }]}><Input placeholder="请输入地址组名称" /></Form.Item>
        <Form.Item name="description" label="说明"><Input placeholder="请输入说明" /></Form.Item>
        <Form.Item name="show" label="显示" valuePropName="checked"><Switch /></Form.Item>
        <Form.List name="rules">
          {(fields, { add, remove }) => <>
            <div className="node-address-rule-head">
              <span>地址规则</span>
              <Button size="small" icon={<PlusOutlined />} onClick={() => add({ name: '', host: '', show: true, sort: fields.length })}>添加规则</Button>
            </div>
            {fields.map((field, index) => <div key={field.key} className="node-address-rule-item">
              <div className="node-address-rule-title">
                <span>规则 {index + 1}</span>
                <Button size="small" danger icon={<DeleteOutlined />} onClick={() => remove(field.name)} />
              </div>
              <div className="form-grid">
                <div className="form-col-8"><Form.Item name={[field.name, 'name']} label="规则名称"><Input placeholder="规则名称" /></Form.Item></div>
                <div className="form-col-10"><Form.Item name={[field.name, 'host']} label="下发地址" rules={[{ required: true, message: '请输入下发地址' }]}><Input placeholder="example.com" /></Form.Item></div>
                <div className="form-col-3"><Form.Item name={[field.name, 'sort']} label="排序"><InputNumber style={{ width: '100%' }} min={0} /></Form.Item></div>
                <div className="form-col-3"><Form.Item name={[field.name, 'show']} label="显示" valuePropName="checked"><Switch /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_user_ids']} label="用户ID"><Select mode="tags" placeholder="1 或 1-100" /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_plan_ids']} label="套餐"><Select mode="tags" placeholder="选择或输入套餐ID" options={planOptions} /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_group_ids']} label="权限组"><Select mode="tags" placeholder="选择或输入权限组ID" options={groupOptions} /></Form.Item></div>
                <div className="form-col-12"><Form.Item name={[field.name, 'match_ua_keywords']} label="客户端UA"><Select mode="tags" placeholder="Clash / sing-box" /></Form.Item></div>
                <div className="form-col-12"><Form.Item name={[field.name, 'exclude_ua_keywords']} label="排除UA"><Select mode="tags" placeholder="V2rayU" /></Form.Item></div>
                <div className="form-col-6"><Form.Item name={[field.name, 'min_registered_days']} label="注册天数最小值"><InputNumber min={0} style={{ width: '100%' }} /></Form.Item></div>
                <div className="form-col-6"><Form.Item name={[field.name, 'max_registered_days']} label="注册天数最大值"><InputNumber min={0} style={{ width: '100%' }} /></Form.Item></div>
                <div className="form-col-6"><Form.Item name={[field.name, 'no_ua']} valuePropName="checked"><Checkbox>无UA</Checkbox></Form.Item></div>
                <div className="form-col-6"><Form.Item name={[field.name, 'is_default']} valuePropName="checked"><Checkbox>默认规则</Checkbox></Form.Item></div>
              </div>
            </div>)}
          </>}
        </Form.List>
      </Form>
    </Modal>
  </div>;
}
