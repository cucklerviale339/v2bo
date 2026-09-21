package httpapi

import (
	"context"
	"forest/go-api/internal/admin"
	"forest/go-api/internal/dnspod"
)

type fakeDNSAdminService struct {
	admin.Service
	err                         error
	dnspodConfig                admin.DNSPodConfigStatus
	dnspodDomains               dnspod.DescribeDomainListResult
	dnspodRecords               dnspod.DescribeRecordListResult
	dnspodTypes                 dnspod.DescribeRecordTypeResult
	dnspodLines                 dnspod.DescribeRecordLineListResult
	dnspodMutation              dnspod.RecordMutationResult
	dnsFailoverSettings         admin.DNSFailoverSettings
	dnsProbes                   []admin.DNSProbeRecord
	dnsProbeCreate              admin.DNSProbeCreateResult
	lastDNSProbeDeleteID        int64
	dnsRules                    []admin.DNSFailoverRuleRecord
	dnsRule                     admin.DNSFailoverRuleRecord
	dnsStatus                   admin.DNSFailoverStatus
	lastDNSRuleStatusID         int64
	dnsEvents                   admin.DNSFailoverEventListResult
	dnsLogs                     admin.DNSFailoverLogListResult
	lastDNSLogs                 admin.DNSFailoverLogListRequest
	lastDNSPodConfigSave        admin.DNSPodConfigSaveRequest
	lastDNSPodDomainList        admin.DNSPodDomainListRequest
	lastDNSPodRecordList        admin.DNSPodRecordListRequest
	lastDNSPodRecordSave        admin.DNSPodRecordSaveRequest
	lastDNSPodDeleteDomain      string
	lastDNSPodDeleteDomainID    int64
	lastDNSPodDeleteID          int64
	lastDNSPodStatusDomain      string
	lastDNSPodStatusDomainID    int64
	lastDNSPodStatusID          int64
	lastDNSPodStatus            string
	lastDNSFailoverSettingsSave admin.DNSFailoverSettingsSaveRequest
	lastDNSProbeCreate          admin.DNSProbeCreateRequest
	lastDNSProbeID              int64
	lastDNSProbeEnabled         bool
	lastDNSRuleSave             admin.DNSFailoverRuleSaveRequest
	lastDNSRuleID               int64
	lastDNSRuleEnabled          bool
	lastDNSManualGroupID        int64
	lastDNSManualTargetID       int64
	lastDNSEvents               admin.DNSFailoverEventListRequest
}

func (f *fakeDNSAdminService) GetDNSPodConfig(_ context.Context) (admin.DNSPodConfigStatus, error) {
	return f.dnspodConfig, f.err
}

func (f *fakeDNSAdminService) SaveDNSPodConfig(_ context.Context, req admin.DNSPodConfigSaveRequest) (admin.DNSPodConfigStatus, error) {
	f.lastDNSPodConfigSave = req
	return f.dnspodConfig, f.err
}

func (f *fakeDNSAdminService) TestDNSPodConfig(_ context.Context, req admin.DNSPodConfigSaveRequest) error {
	f.lastDNSPodConfigSave = req
	return f.err
}

func (f *fakeDNSAdminService) ListDNSPodDomains(_ context.Context, req admin.DNSPodDomainListRequest) (dnspod.DescribeDomainListResult, error) {
	f.lastDNSPodDomainList = req
	return f.dnspodDomains, f.err
}

func (f *fakeDNSAdminService) ListDNSPodRecords(_ context.Context, req admin.DNSPodRecordListRequest) (dnspod.DescribeRecordListResult, error) {
	f.lastDNSPodRecordList = req
	return f.dnspodRecords, f.err
}

func (f *fakeDNSAdminService) ListDNSPodRecordTypes(_ context.Context, domainGrade string) (dnspod.DescribeRecordTypeResult, error) {
	f.lastDNSPodRecordList.RecordType = domainGrade
	return f.dnspodTypes, f.err
}

func (f *fakeDNSAdminService) ListDNSPodRecordLines(_ context.Context, domain string, domainID int64, domainGrade, recordType string) (dnspod.DescribeRecordLineListResult, error) {
	f.lastDNSPodRecordList.Domain = domain
	f.lastDNSPodRecordList.DomainID = domainID
	f.lastDNSPodRecordList.RecordLine = domainGrade
	f.lastDNSPodRecordList.RecordType = recordType
	return f.dnspodLines, f.err
}

func (f *fakeDNSAdminService) SaveDNSPodRecord(_ context.Context, req admin.DNSPodRecordSaveRequest) (dnspod.RecordMutationResult, error) {
	f.lastDNSPodRecordSave = req
	return f.dnspodMutation, f.err
}

func (f *fakeDNSAdminService) DeleteDNSPodRecord(_ context.Context, domain string, domainID, recordID int64) error {
	f.lastDNSPodDeleteDomain = domain
	f.lastDNSPodDeleteDomainID = domainID
	f.lastDNSPodDeleteID = recordID
	return f.err
}

func (f *fakeDNSAdminService) SetDNSPodRecordStatus(_ context.Context, domain string, domainID, recordID int64, status string) error {
	f.lastDNSPodStatusDomain = domain
	f.lastDNSPodStatusDomainID = domainID
	f.lastDNSPodStatusID = recordID
	f.lastDNSPodStatus = status
	return f.err
}

func (f *fakeDNSAdminService) GetDNSFailoverSettings(_ context.Context) (admin.DNSFailoverSettings, error) {
	return f.dnsFailoverSettings, f.err
}

func (f *fakeDNSAdminService) SaveDNSFailoverSettings(_ context.Context, request admin.DNSFailoverSettingsSaveRequest) (admin.DNSFailoverSettings, error) {
	f.lastDNSFailoverSettingsSave = request
	return f.dnsFailoverSettings, f.err
}

func (f *fakeDNSAdminService) ListDNSProbes(_ context.Context) ([]admin.DNSProbeRecord, error) {
	return f.dnsProbes, f.err
}

func (f *fakeDNSAdminService) CreateDNSProbe(_ context.Context, request admin.DNSProbeCreateRequest) (admin.DNSProbeCreateResult, error) {
	f.lastDNSProbeCreate = request
	return f.dnsProbeCreate, f.err
}

func (f *fakeDNSAdminService) SetDNSProbeEnabled(_ context.Context, id int64, enabled bool) (bool, error) {
	f.lastDNSProbeID, f.lastDNSProbeEnabled = id, enabled
	return true, f.err
}

func (f *fakeDNSAdminService) DeleteDNSProbe(_ context.Context, id int64) (bool, error) {
	f.lastDNSProbeDeleteID = id
	return true, f.err
}

func (f *fakeDNSAdminService) GetDNSFailoverStatus(_ context.Context, id int64) (admin.DNSFailoverStatus, error) {
	f.lastDNSRuleStatusID = id
	return f.dnsStatus, f.err
}

func (f *fakeDNSAdminService) ListDNSFailoverLogs(_ context.Context, request admin.DNSFailoverLogListRequest) (admin.DNSFailoverLogListResult, error) {
	f.lastDNSLogs = request
	return f.dnsLogs, f.err
}

func (f *fakeDNSAdminService) ListDNSFailoverRules(_ context.Context) ([]admin.DNSFailoverRuleRecord, error) {
	return f.dnsRules, f.err
}

func (f *fakeDNSAdminService) GetDNSFailoverRule(_ context.Context, id int64) (admin.DNSFailoverRuleRecord, error) {
	f.lastDNSRuleID = id
	return f.dnsRule, f.err
}

func (f *fakeDNSAdminService) SaveDNSFailoverRule(_ context.Context, request admin.DNSFailoverRuleSaveRequest) (admin.DNSFailoverRuleRecord, error) {
	f.lastDNSRuleSave = request
	return f.dnsRule, f.err
}

func (f *fakeDNSAdminService) DeleteDNSFailoverRule(_ context.Context, id int64) (bool, error) {
	f.lastDNSRuleID = id
	return true, f.err
}

func (f *fakeDNSAdminService) SetDNSFailoverRuleEnabled(_ context.Context, id int64, enabled bool) (bool, error) {
	f.lastDNSRuleID, f.lastDNSRuleEnabled = id, enabled
	return true, f.err
}

func (f *fakeDNSAdminService) ManualSwitchDNSFailoverTarget(_ context.Context, groupID, targetID int64) error {
	f.lastDNSManualGroupID, f.lastDNSManualTargetID = groupID, targetID
	return f.err
}

func (f *fakeDNSAdminService) ListDNSFailoverEvents(_ context.Context, request admin.DNSFailoverEventListRequest) (admin.DNSFailoverEventListResult, error) {
	f.lastDNSEvents = request
	return f.dnsEvents, f.err
}
