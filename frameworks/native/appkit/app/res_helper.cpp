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

#include "res_helper.h"

#include "hilog_tag_wrapper.h"
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
#include "res_sched_client.h"
#include "res_type.h"
#endif

namespace OHOS {
namespace AppExecFwk {
constexpr const uint32_t MAX_BUF_SIZE = (1U << 19);
void ReportLoadAbcCompletedInfoToRss(int32_t uid, std::string bundleName)
{
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
    uint32_t resType = ResourceSchedule::ResType::RES_TYPE_RECV_ABC_LOAD_COMPLETED;
    std::unordered_map<std::string, std::string> eventParams {
        { "name", "abc_load_completed" },
        { "uid", std::to_string(uid) },
        { "bundleName", bundleName }
    };
    bool isColdStart = true;
    TAG_LOGD(AAFwkTag::APPKIT, "runtime callback and report load abc completed info to rss.");
    ResourceSchedule::ResSchedClient::GetInstance()::ReportData(resType, isColdStart, eventParams);
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS
