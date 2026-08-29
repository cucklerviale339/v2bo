import React, { useEffect, useState } from 'react';
import { Button, Card, Form, Input, Modal, Popconfirm, Segmented, Select, Space, Switch, Table, Tag, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { apiGet, apiPost } from '../lib/api';
import { UserEmailSelect } from './NodeAddressPage';

const split = (value: any) => (Array.isArray(value) ? value : String(value || '').split(/[\n,]+/)).map((item: any) => String(item).trim()).filter(Boolean);
const lines = (value: any) => (Array.isArray(value) ? value : String(value || '').split(/\r?\n/)).map((item: any) => String(item).trim()).filter(Boolean);
function Editor({ row, onDone, children }: any) {
  const [open, setOpen] = useState(false); const [saving, setSaving] = useState(false); const [form] = Form.useForm();
  const show = () => { form.resetFields(); form.setFieldsValue({ ...row, match_user_ids: split(row?.match_user_ids), match_user_id_ranges: split(row?.match_user_id_ranges), extra_nodes: lines(row?.extra_nodes).join('\n'), extra_nodes_position: row?.extra_nodes_position === 'before' ? 'before' : 'replace', enabled: row?.enabled === undefined ? true : !!Number(row.enabled) }); setOpen(true); };
  const save = async () => { setSaving(true); try { const value = await form.validateFields(); await apiPost('/server/insider/save', { ...row, ...value, members: [], sort: null, match_user_ids: split(value.match_user_ids), match_user_id_ranges: split(value.match_user_id_ranges), extra_nodes: lines(value.extra_nodes), enabled: value.enabled ? 1 : 0 }); message.success('保存成功'); setOpen(false); onDone(); } catch (error: any) { if (!error?.errorFields) message.error(error.message || '保存失败'); } finally { setSaving(false); } };
  return <><span onClick={show}>{children}</span><Modal title={row?.id ? '编辑内鬼规则' : '新建内鬼规则'} open={open} onCancel={() => setOpen(false)} onOk={save} confirmLoading={saving} width={860} destroyOnHidden><Form form={form} layout="vertical">
    <div className="form-grid"><div className="form-col-21"><Form.Item name="name" label="规则名称" rules={[{ required: true }]}><Input placeholder="例如：指定用户独立入口" /></Form.Item></div><div className="form-col-3"><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item></div></div>
    <Form.Item name="match_user_ids" label="指定用户" extra="可按邮箱搜索或直接输入用户 ID；与 ID 范围任一命中即生效。"><UserEmailSelect /></Form.Item>
    <Form.Item name="match_user_id_ranges" label="用户 ID 范围"><Select mode="tags" tokenSeparators={[',']} placeholder="例如 100-200" /></Form.Item>
    <Form.Item name="host" label="节点下发地址" extra="默认对全部节点生效，并优先覆盖节点地址组和节点原地址。"><Input placeholder="域名或 IP；使用额外节点覆盖时可留空" /></Form.Item>
    <Form.Item name="extra_nodes" label="额外下发节点" extra="一行一个完整节点 URI。"><Input.TextArea rows={5} /></Form.Item>
    <Form.Item name="extra_nodes_position" label="额外节点方式"><Segmented block options={[{ label: '覆盖原节点', value: 'replace' }, { label: '置于原节点之前', value: 'before' }]} /></Form.Item>
  </Form></Modal></>;
}

export default function InsiderPage() {
  const [rows, setRows] = useState<any[]>([]); const [loading, setLoading] = useState(false);
  const load = async () => { setLoading(true); try { const rules = await apiGet('/server/insider/fetch'); setRows(rules.data || []); } catch (error: any) { message.error(error.message || '加载失败'); } finally { setLoading(false); } };
  useEffect(() => { load(); }, []);
  const drop = async (id: number) => { await apiPost('/server/insider/drop', { id }, { form: true }); message.success('已删除'); load(); };
  const columns: any[] = [
    { title: '规则名称', dataIndex: 'name', width: 190 },
    { title: '匹配用户', width: 260, render: (_: any, r: any) => <Space wrap>{split(r.match_user_ids).map((v: string) => <Tag key={`u${v}`}>ID {v}</Tag>)}{split(r.match_user_id_ranges).map((v: string) => <Tag color="blue" key={`r${v}`}>{v}</Tag>)}</Space> },
    { title: '生效范围', width: 100, render: () => '全部节点' }, { title: '节点地址', dataIndex: 'host', ellipsis: true, render: (v: any) => v || '-' },
    { title: '额外节点', dataIndex: 'extra_nodes', width: 150, render: (v: any[], r: any) => v?.length ? `${v.length} 个（${r.extra_nodes_position === 'before' ? '前置' : '覆盖'}）` : '-' },
    { title: '状态', dataIndex: 'enabled', width: 80, render: (v: any) => Number(v) ? <Tag color="green">启用</Tag> : <Tag>停用</Tag> },
    { title: '操作', width: 130, align: 'right', render: (_: any, r: any) => <Space><Editor row={r} onDone={load}><a>编辑</a></Editor><Popconfirm title="确认删除？" onConfirm={() => drop(r.id)}><a>删除</a></Popconfirm></Space> },
  ];
  return <div className="legacy-page"><div className="content-heading">内鬼管理</div><Card className="block-card" styles={{ body: { padding: 0 } }}><div className="forest-table-action"><Space><Editor onDone={load}><Button type="primary" icon={<PlusOutlined />}>新建规则</Button></Editor><span className="text-muted">规则对全部节点生效，并优先于节点地址组和节点原地址。</span></Space></div><Table loading={loading} rowKey="id" columns={columns} dataSource={rows} pagination={false} scroll={{ x: 1050 }} /></Card></div>;
}
