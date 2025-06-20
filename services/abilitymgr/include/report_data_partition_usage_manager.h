/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_REPORT_DATA_PARTITION_USAGE_MANAGER_H
#define OHOS_ABILITY_RUNTIME_REPORT_DATA_PARTITION_USAGE_MANAGER_H

#include "event_report.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AAFwk;
class ReportDataPartitionUsageManager {
public:
    static void SendReportDataPartitionUsageEvent();

private:
    static void HandleSendReportDataPartitionUsageEvent();
    static void GenerateEventInfo(EventInfo &eventInfo);
    static uint64_t GetFilePathSize(const std::string &filePath);
    static uint64_t GetPartitionRemainSize(const std::string &filePath);
    static bool IsExistPath(const std::string &filePath);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_REPORT_DATA_PARTITION_USAGE_MANAGER_H