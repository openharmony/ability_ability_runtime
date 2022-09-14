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

#include "ability_interceptor.h"

#include <chrono>
#include <string>

#include "ability_manager_errors.h"
#include "bundlemgr/bundle_mgr_interface.h"
#include "bundle_constants.h"
#include "in_process_call_wrapper.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AAFwk {
const std::string ACTION_MARKET_CROWDTEST = "ohos.want.action.marketCrowdTest";
const std::string PERMISSION_MANAGE_DISPOSED_APP_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";

AbilityInterceptor::~AbilityInterceptor()
{}

CrowdTestInterceptor::CrowdTestInterceptor(const Want &want, int requestCode, int32_t userId, bool isForeground)
    : want_(want), requestCode_(requestCode), userId_(userId), isForeground_(isForeground)
{}

CrowdTestInterceptor::~CrowdTestInterceptor()
{}

ErrCode CrowdTestInterceptor::DoProcess()
{
    HILOG_INFO("[DEBUG] Do CrowdTest intercept");
    if (CheckCrowdtest()) {
        HILOG_INFO("[DEBUG] Crowdtest expired");
        HILOG_ERROR("Crowdtest expired.");
#ifdef SUPPORT_GRAPHICS
        if (isForeground_) {
            int ret = AbilityUtil::StartAppgallery(requestCode_, userId_, ACTION_MARKET_CROWDTEST);
            if (ret != ERR_OK) {
                HILOG_ERROR("Crowdtest implicit start appgallery failed.");
                return ret;
            }
        }
#endif
        return ERR_CROWDTEST_EXPIRED;
    }
    HILOG_INFO("[DEBUG] Not Crowdtest expired");
    return ERR_OK;
}

bool CrowdTestInterceptor::CheckCrowdtest()
{
    auto bms = AbilityUtil::GetBundleManager();
    if (!bms) {
        HILOG_ERROR("GetBundleManager failed");
        return false;
    }
    std::string bundleName = want_.GetBundle();
    AppExecFwk::ApplicationInfo callerAppInfo;
    bool result = IN_PROCESS_CALL(
        bms->GetApplicationInfo(bundleName, AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO,
            userId_, callerAppInfo)
    );
    if (!result) {
        HILOG_ERROR("GetApplicaionInfo from bms failed.");
        return false;
    }

    auto appDistributionType = callerAppInfo.appDistributionType;
    auto appCrowdtestDeadline = callerAppInfo.crowdtestDeadline;
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

DisposedInterceptor::DisposedInterceptor(const Want &want, int requestCode, int32_t userId, bool isForeground)
    : want_(want), requestCode_(requestCode), userId_(userId), isForeground_(isForeground)
{}

DisposedInterceptor::~DisposedInterceptor()
{}

ErrCode DisposedInterceptor::DoProcess()
{
    if (CheckDisposed()) {
        HILOG_ERROR("");
#ifdef SUPPORT_GRAPHICS
        if (isForeground_) {
            int ret = AbilityUtil::StartAppgallery(requestCode_, userId_, ACTION_MARKET_CROWDTEST);
            if (ret != ERR_OK) {
                HILOG_ERROR("Disposed implicit start appgallery failed.");
                return ret;
            }
        }
#endif
        return ERR_DISPOSED_STATUS;
    }
    return ERR_OK;
}

bool DisposedInterceptor::CheckDisposed()
{
    // get bms
    auto bms = AbilityUtil::GetBundleManager();
    if (!bms) {
        HILOG_ERROR("GetBundleManager failed");
        return false;
    }

    // get disposed status
    std::string bundleName = want_.GetBundle();
    int disposedStatus = bms->GetDisposedStatus(bundleName);

    if (disposedStatus != 0) {
        HILOG_DEBUG("The target app's status is abnormal, the status is: %{public}d", disposedStatus);
        return true;
    }
    return false;
}
} // namespace AAFwk
} // namespace OHOS