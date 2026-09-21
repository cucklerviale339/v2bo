package admin

import (
	"context"

	"forest/go-api/internal/dnspod"
)

var _ DNSManagementService = (*DBService)(nil)

type DNSManagementService interface {
	GetDNSPodConfig(ctx context.Context) (DNSPodConfigStatus, error)
	SaveDNSPodConfig(ctx context.Context, req DNSPodConfigSaveRequest) (DNSPodConfigStatus, error)
	TestDNSPodConfig(ctx context.Context, req DNSPodConfigSaveRequest) error
	ListDNSPodDomains(ctx context.Context, req DNSPodDomainListRequest) (dnspod.DescribeDomainListResult, error)
	ListDNSPodRecords(ctx context.Context, req DNSPodRecordListRequest) (dnspod.DescribeRecordListResult, error)
	ListDNSPodRecordTypes(ctx context.Context, domainGrade string) (dnspod.DescribeRecordTypeResult, error)
	ListDNSPodRecordLines(ctx context.Context, domain string, domainID int64, domainGrade, recordType string) (dnspod.DescribeRecordLineListResult, error)
	SaveDNSPodRecord(ctx context.Context, req DNSPodRecordSaveRequest) (dnspod.RecordMutationResult, error)
	DeleteDNSPodRecord(ctx context.Context, domain string, domainID, recordID int64) error
	SetDNSPodRecordStatus(ctx context.Context, domain string, domainID, recordID int64, status string) error
	GetDNSFailoverSettings(ctx context.Context) (DNSFailoverSettings, error)
	SaveDNSFailoverSettings(ctx context.Context, req DNSFailoverSettingsSaveRequest) (DNSFailoverSettings, error)
	ListDNSProbes(ctx context.Context) ([]DNSProbeRecord, error)
	CreateDNSProbe(ctx context.Context, req DNSProbeCreateRequest) (DNSProbeCreateResult, error)
	SetDNSProbeEnabled(ctx context.Context, id int64, enabled bool) (bool, error)
	DeleteDNSProbe(ctx context.Context, id int64) (bool, error)
	ListDNSFailoverRules(ctx context.Context) ([]DNSFailoverRuleRecord, error)
	GetDNSFailoverRule(ctx context.Context, id int64) (DNSFailoverRuleRecord, error)
	GetDNSFailoverStatus(ctx context.Context, id int64) (DNSFailoverStatus, error)
	SaveDNSFailoverRule(ctx context.Context, req DNSFailoverRuleSaveRequest) (DNSFailoverRuleRecord, error)
	DeleteDNSFailoverRule(ctx context.Context, id int64) (bool, error)
	SetDNSFailoverRuleEnabled(ctx context.Context, id int64, enabled bool) (bool, error)
	ManualSwitchDNSFailoverTarget(ctx context.Context, groupID, targetID int64) error
	ListDNSFailoverEvents(ctx context.Context, req DNSFailoverEventListRequest) (DNSFailoverEventListResult, error)
	ListDNSFailoverLogs(ctx context.Context, req DNSFailoverLogListRequest) (DNSFailoverLogListResult, error)
}
