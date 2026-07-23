import React, { useEffect, useState } from 'react';
import { Button, Card, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Spin, Switch, Table, Tag, message } from 'antd';
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
    match_user_id_ranges: splitList(rule.match_user_id_ranges),
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
      enabled: rule.enabled ? 1 : 0,
      sort: rule.sort ?? index,
    })),
  };
}

function ruleSummary(rule: any) {
  const parts: string[] = [];
  if (splitList(rule.match_user_ids).length) parts.push('明确ID');
  if (splitList(rule.match_user_id_ranges).length) parts.push('ID范围');
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
              <Button size="small" icon={<PlusOutlined />} onClick={() => add({ name: '', host: '', enabled: true, sort: fields.length })}>添加规则</Button>
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
                <div className="form-col-3"><Form.Item name={[field.name, 'enabled']} label="启用" valuePropName="checked"><Switch /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_user_ids']} label="明确用户ID" rules={[{ validator: validateUserIDs }]}><Select mode="tags" tokenSeparators={[',']} placeholder="例如 1、25，回车确认" /></Form.Item></div>
                <div className="form-col-8"><Form.Item name={[field.name, 'match_user_id_ranges']} label="用户ID范围" rules={[{ validator: validateUserIDRanges }]}><Select mode="tags" tokenSeparators={[',']} placeholder="例如 1-100，回车确认" /></Form.Item></div>
              </div>
            </div>)}
          </>}
        </Form.List>
      </Form>
    </Modal>
  </div>;
}
