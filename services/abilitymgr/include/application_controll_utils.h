/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_APPLICATION_CONTROLL_UTILS_H
#define OHOS_ABILITY_RUNTIME_APPLICATION_CONTROLL_UTILS_H

#include <chrono>
#include <string>

#include "ability_manager_service.h"
#include "ability_util.h"
#include "bundlemgr/bundle_mgr_interface.h"
#include "bundle_constants.h"
#include "hilog_wrapper.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
namespace ApplicationControllUtils {
using Want = OHOS::AAFwk::Want;
const std::string CROWDTEST_EXPEIRD_IMPLICIT_ACTION_NAME = "ohos.want.action.crowdtest";
const std::string CROWDTEST_EXPEIRD_IMPLICIT_BUNDLE_NAME = "com.demo.crowdtest";
const int32_t CROWDTEST_EXPEIRD_IMPLICIT_START_FAILED = 1;
const int32_t CROWDTEST_EXPEIRD_REFUSED = -1;

static bool IsCrowdtestExpired(const Want &want, int32_t userId)
{
    auto bms = AbilityUtil::GetBundleManager();
    if (!bms) {
        HILOG_ERROR("%{public}s fail to get bundle manager.", __func__);
    }
    std::string bundleName = want.GetBundle();
    AppExecFwk::ApplicationInfo callerAppInfo;
    bool result = IN_PROCESS_CALL(
        bms->GetApplicationInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
            userId, callerAppInfo)
    );
    if (!result) {
        HILOG_ERROR("%{public}s GetApplicaionInfo from bms failed.", __func__);
        return false;
    }

    auto appDistributionType = callerAppInfo.appDistributionType;
    auto appCrowdtestDeadline = callerAppInfo.crowdtestDeadline;
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (appDistributionType == AppExecFwk::Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING &&
        appCrowdtestDeadline <= now) {
        return true;
    }
    return false;
}

static int CheckCrowdtestForeground(Want &want, int32_t userId)
{
    if (IsCrowdtestExpired(want, userId)) {
        want.SetElementName(CROWDTEST_EXPEIRD_IMPLICIT_BUNDLE_NAME, "");
        want.SetAction(CROWDTEST_EXPEIRD_IMPLICIT_ACTION_NAME);
        return CROWDTEST_EXPEIRD_REFUSED;
    }
    return ERR_OK;
}

static int CheckCrowdtestBackground(const Want &want, int32_t userId)
{
    if (IsCrowdtestExpired(want, userId)) {
        return CROWDTEST_EXPEIRD_REFUSED;
    }
    return ERR_OK;
}
}  // namespace ApplicationControllUtils
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APPLICATION_CONTROLL_UTILS_H