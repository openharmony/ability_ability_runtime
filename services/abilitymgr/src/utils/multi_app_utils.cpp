/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "multi_app_utils.h"

#include "app_mgr_util.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "running_multi_info.h"

namespace OHOS {
namespace AAFwk {
void MultiAppUtils::GetRunningMultiAppIndex(const std::string &bundleName, int32_t uid, int32_t &appIndex)
{
    AppExecFwk::RunningMultiAppInfo runningMultiAppInfo;
    auto appMgr = AppMgrUtil::GetAppMgr();
    if (appMgr == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "AppMgrUtil::GetAppMgr failed");
        return;
    }
    auto ret = IN_PROCESS_CALL(appMgr->GetRunningMultiAppInfoByBundleName(bundleName, runningMultiAppInfo));
    if (ret != ERR_OK) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "getAppInfo failed, bundle:%{public}s",
            bundleName.c_str());
    }
    for (auto &item : runningMultiAppInfo.runningAppClones) {
        if (item.uid == uid) {
            appIndex = item.appCloneIndex;
            break;
        }
    }
}
}  // namespace AAFwk
}  // namespace OHOS