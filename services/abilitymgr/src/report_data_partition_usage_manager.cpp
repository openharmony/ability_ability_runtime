/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "report_data_partition_usage_manager.h"

#include <sys/stat.h>
#include <sys/statfs.h>

#include "directory_ex.h"
#include "ffrt.h"
#include "global_constant.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
static const std::string COMPONENT_NAME = "ability_runtime";
static const std::string USER_DATA_DIR = "/data";
static const uint64_t UNITS = 1024;
static const uint64_t INVALID_SIZE = 0;
static const uint64_t SECONDS_PER_DAY = 24 * 60 * 60;
static const uint64_t ONE_DAY_US = SECONDS_PER_DAY * 1000 * 1000;
static std::vector<std::string> pathList_ = {
    "/data/service/el1/public/database/auto_startup_service",
    "/data/service/el1/public/database/app_exit_reason",
    "/data/service/el1/public/database/keep_alive_service",
    "/data/service/el1/public/database/ability_manager_service",
    "/data/service/el1/public/database/app_config_data"
};

void ReportDataPartitionUsageManager::SendReportDataPartitionUsageEvent()
{
    ffrt::submit(HandleSendReportDataPartitionUsageEvent,
        ffrt::task_attr().delay(ONE_DAY_US).name("SendReportDataPartitionUsageTask")
        .timeout(AbilityRuntime::GlobalConstant::DEFAULT_FFRT_TASK_TIMEOUT));
}

void ReportDataPartitionUsageManager::HandleSendReportDataPartitionUsageEvent()
{
    EventInfo eventInfo;
    GenerateEventInfo(eventInfo);
    EventReport::SendReportDataPartitionUsageEvent(EventName::USER_DATA_SIZE,
        HISYSEVENT_STATISTIC, eventInfo);

    ffrt::submit(HandleSendReportDataPartitionUsageEvent,
        ffrt::task_attr().delay(ONE_DAY_US).name("SendReportDataPartitionUsageTask")
        .timeout(AbilityRuntime::GlobalConstant::DEFAULT_FFRT_TASK_TIMEOUT));
}

void ReportDataPartitionUsageManager::SendReportDatabaseReadEvent(const std::string &dbPath)
{
    ffrt::submit([dbPath]() {
        HandleSendReportDatabaseWriteEvent(dbPath);
        }, ffrt::task_attr().name("SendReportDatabaseReadEventTask")
        .timeout(AbilityRuntime::GlobalConstant::DEFAULT_FFRT_TASK_TIMEOUT));
}

void ReportDataPartitionUsageManager::HandleSendReportDatabaseWriteEvent(const std::string &dbPath)
{
    EventInfo eventInfo;
    eventInfo.componentName = COMPONENT_NAME;
    eventInfo.partitionName = USER_DATA_DIR;
    eventInfo.remainPartitionSize = GetPartitionRemainSize(USER_DATA_DIR);
    eventInfo.fileOfFolderPath.push_back(dbPath);
    EventReport::SendReportDataPartitionUsageEvent(EventName::USER_DATA_SIZE,
        HISYSEVENT_STATISTIC, eventInfo);
}

void ReportDataPartitionUsageManager::GenerateEventInfo(EventInfo &eventInfo)
{
    std::vector<std::uint64_t> fileOrFolderSize;
    for (auto &path : pathList_) {
        fileOrFolderSize.emplace_back(GetFilePathSize(path));
    }

    eventInfo.componentName = COMPONENT_NAME;
    eventInfo.partitionName = USER_DATA_DIR;
    eventInfo.remainPartitionSize = GetPartitionRemainSize(USER_DATA_DIR);
    eventInfo.fileOfFolderPath = pathList_;
    eventInfo.fileOfFolderSize = fileOrFolderSize;
}

uint64_t ReportDataPartitionUsageManager::GetFilePathSize(const std::string &filePath)
{
    return OHOS::GetFolderSize(filePath);
}

uint64_t ReportDataPartitionUsageManager::GetPartitionRemainSize(const std::string &filePath)
{
    if (!IsExistPath(filePath)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "file path not exist");
        return INVALID_SIZE;
    }

    struct statvfs stst;
    if (statvfs(filePath.c_str(), &stst) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed to get space info for path %{public}s", filePath.c_str());
        return INVALID_SIZE;
    }
    return (static_cast<uint64_t>(stst.f_bfree) / UNITS) * (static_cast<uint64_t>(stst.f_bsize) / UNITS);
}

bool ReportDataPartitionUsageManager::IsExistPath(const std::string &filePath)
{
    if (filePath.empty()) {
        return false;
    }

    struct stat result = {};
    if (stat(filePath.c_str(), &result) != 0) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "fail stat error");
        return false;
    }

    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS