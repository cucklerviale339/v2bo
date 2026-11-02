package admin

import "strings"

// normalizeBulkMailSubject adds the configured brand to an unbranded bulk
// subject while preserving the administrator's wording.
func normalizeBulkMailSubject(subject, appName string) string {
	subject = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(subject))
	appName = strings.TrimSpace(appName)
	if subject == "" || appName == "" || strings.Contains(strings.ToLower(subject), strings.ToLower(appName)) {
		return subject
	}
	if compact := strings.Join(strings.Fields(subject), " "); compact != "请更新一下" && compact != "通知一下" && compact != "通知" && compact != "提醒一下" {
		return subject
	}
	return appName + "｜" + subject
}

func normalizeBulkMailContent(content, appName string) string {
	trimmed := strings.TrimSpace(content)
	compact := strings.Join(strings.Fields(trimmed), " ")
	if compact == "请更新一下" || compact == "通知一下" || compact == "通知" || compact == "提醒一下" {
		if strings.TrimSpace(appName) == "" {
			appName = "Forest"
		}
		return appName + " 服务通知\n\n通知内容：\n" + trimmed + "\n\n如需帮助，请登录网站后通过站内工单联系我们。"
	}
	return content
}
