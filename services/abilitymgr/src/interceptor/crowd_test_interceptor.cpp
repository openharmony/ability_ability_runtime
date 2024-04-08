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

#include "interceptor/crowd_test_interceptor.h"

#include "ability_util.h"
#include "hilog_wrapper.h"
#include "in_process_call_wrapper.h"
#include "start_ability_utils.h"

namespace OHOS {
namespace AAFwk {
namespace {
const std::string ACTION_MARKET_CROWDTEST = "ohos.want.action.marketCrowdTest";
}
ErrCode CrowdTestInterceptor::DoProcess(AbilityInterceptorParam param)
{
    if (CheckCrowdtest(param.want, param.userId)) {
        HILOG_ERROR("Crowdtest expired.");
#ifdef SUPPORT_GRAPHICS
        if (param.isWithUI) {
            int ret = IN_PROCESS_CALL(AbilityUtil::StartAppgallery(param.want.GetBundle(), param.requestCode,
                param.userId, ACTION_MARKET_CROWDTEST));
            if (ret != ERR_OK) {
                HILOG_ERROR("Crowdtest implicit start appgallery failed.");
                return ret;
            }
        }
#endif
        return ERR_CROWDTEST_EXPIRED;
    }
    return ERR_OK;
}

bool CrowdTestInterceptor::CheckCrowdtest(const Want &want, int32_t userId)
{
    // get crowdtest status and time
    AppExecFwk::ApplicationInfo appInfo;
    if (!StartAbilityUtils::GetApplicationInfo(want.GetBundle(), userId, appInfo)) {
        HILOG_ERROR("failed to get application info.");
        return false;
    }

    auto appDistributionType = appInfo.appDistributionType;
    auto appCrowdtestDeadline = appInfo.crowdtestDeadline;
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::
        system_clock::now().time_since_epoch()).count();
    if (appDistributionType == AppExecFwk::Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING &&
        appCrowdtestDeadline < now) {
        HILOG_INFO("The application is expired, expired time is %{public}s",
            std::to_string(appCrowdtestDeadline).c_str());
        return true;
    }
    return false;
}
} // namespace AAFwk
} // namespace OHOS