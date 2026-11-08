package httpapi

import (
	"forest/go-api/internal/admin"
	"forest/go-api/internal/aiops"
)

// These routes use this project's address ownership and probe implementation.
// In particular there is no active-check or reference-only split operation.
func panelDispatchOperations() []aiops.PanelOperation {
	out := []aiops.PanelOperation{}
	add := func(name, description, method, path string, write bool, schema panelSchema) {
		out = append(out, po(name, "entries", description, method, path, write, true, schema))
	}
	empty := poObj(panelSchema{})
	id := poObj(panelSchema{"id": poID()}, "id")
	ids := poObj(panelSchema{"ids": poArray(poID())}, "ids")
	add("entry_addresses.list", "读取节点地址组、启用状态、ID范围和规则；修改前读取完整配置", "GET", "/server/address/fetch", false, empty)
	add("entry_addresses.save", "保存节点地址组及规则，保留未修改的规则和绑定；仅enabled=1参与实际下发", "POST", "/server/address/save", true, poObj(poMerge(poFields("id:i name description enabled:i"), panelSchema{"rules": poArray(poObj(poFields("id:i name host match_user_ids:a match_user_id_ranges:a enabled:i sort:i"), "host"))}), "name", "rules"))
	add("entry_addresses.delete", "删除节点地址组，可能使节点回退到原host", "POST", "/server/address/drop", true, id)
	add("insider_rules.list", "读取优先于节点地址组生效的内鬼规则及用户ID/范围", "GET", "/server/insider/fetch", false, empty)
	add("insider_rules.save", "保存内鬼规则；新增必须填写name、host及用户ID或范围。编辑先读取原配置，按id提交要修改的字段，未提交字段保留原值；用户名单和范围数组为整项替换，追加时须包含原成员", "POST", "/server/insider/save", true, poObj(poMerge(poFields("id:i name host match_user_ids:a match_user_id_ranges:a enabled:i sort:i"), panelSchema{"members": poArray(poObj(poFields("server_type server_id:i"), "server_type", "server_id"))})))
	add("insider_rules.delete", "删除指定内鬼规则，可能使入口回退到节点地址组或节点host", "POST", "/server/insider/drop", true, id)
	base := "/dns-failover/"
	add("entry_monitors.list", "读取启用且实际链路会下发的入口，含去重后的ID/范围、来源和探针状态；include_deleted=true时包含已删除入口", "GET", base+"dispatch-entries", false, poObj(panelSchema{"include_deleted": poBool("是否包含已删除入口，默认false")}))
	add("entry_monitors.save", "保存一个实际入口的监控配置，也可恢复已删除入口；check_port仅检测使用，不改订阅端口", "PUT", base+"dispatch-entries", true, poReflect(admin.DispatchMonitorSaveRequest{}))
	add("entry_monitors.delete", "批量删除入口监控，停止探针检测并隐藏；不修改节点下发，include_deleted=true可查看并重新配置恢复", "POST", base+"dispatch-entries/delete", true, poObj(panelSchema{"hosts": poArray(poText("实际入口地址"))}, "hosts"))
	add("ip_pool.list", "读取备用IP池、健康状态、占用及引用", "GET", base+"dispatch-pool", false, empty)
	add("ip_pool.save", "批量新增或更新备用IP，port只用于检测，不修改下发端口", "POST", base+"dispatch-pool", true, poObj(panelSchema{"items": poArray(poReflect(admin.DispatchPoolSave{}))}, "items"))
	add("ip_pool.refresh", "重置指定备用IP的检测状态，等待现有探针重新测活", "POST", base+"dispatch-pool/refresh", true, ids)
	add("ip_pool.delete", "删除指定备用IP，后台校验引用和占用", "POST", base+"dispatch-pool/delete", true, ids)
	add("ip_pool.delete_faulty", "删除确认故障且未引用的备用IP；后台原子复查健康及探针状态", "POST", base+"dispatch-pool/delete-faulty", true, ids)
	add("entry_checks.history", "读取已有近期检测记录，不发起新检测", "GET", base+"dispatch-runs", false, poObj(poFields("page:i")))
	add("entry_checks.continuous_history", "读取入口监控和备用IP池的持续检测历史及故障恢复事件，不发起检测", "GET", base+"dispatch-history", false, poObj(poFields("page:i kind:s source:s host:s port:i probe_id:i success:b event_type:s from:i to:i")))
	add("entry_checks.results", "读取指定历史检测结果和用户ID范围", "GET", base+"dispatch-runs/{id}", false, poObj(poFields("id:i page:i"), "id"))
	return out
}
