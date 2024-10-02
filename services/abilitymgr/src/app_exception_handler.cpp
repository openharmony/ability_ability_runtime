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

#include "app_exception_handler.h"

#include "ability_record.h"
#include "app_exception_callback_stub.h"
#include "app_mgr_util.h"
#include "freeze_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
using AppExecFwk::LifecycleException;
using AbilityRuntime::FreezeUtil;
namespace AAFwk {
namespace {
class AppExceptionCallback : public AppExecFwk::AppExceptionCallbackStub {
    /**
     * Notify abilityManager lifecycle exception.
     *
     * @param type lifecycle failed type
     * @param token associated ability
     */
    void OnLifecycleException(LifecycleException type, sptr<IRemoteObject> token) override
    {
        auto abilityRecord = Token::GetAbilityRecordByToken(token);
        if (abilityRecord == nullptr) {
            TAG_LOGW(AAFwkTag::ABILITYMGR, "abilityRecord null");
            return;
        }

        TAG_LOGI(AAFwkTag::ABILITYMGR, "lifecycle exception: %{public}s, %{public}d",
            abilityRecord->GetURI().c_str(), type);
        abilityRecord->SetFreezeStrategy(FreezeStrategy::NOTIFY_FREEZE_MGR);
    }
};
}

AppExceptionHandler &AppExceptionHandler::GetInstance()
{
    static AppExceptionHandler appExceptionHandler;
    return appExceptionHandler;
}

void AppExceptionHandler::RegisterAppExceptionCallback()
{
    auto appMgr = AppMgrUtil::GetAppMgr();
    if (appMgr == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "AppMgrUtil::GetAppMgr failed");
        return;
    }

    auto service = appMgr->GetAmsMgr();
    if (service == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "GetAmsMgr failed");
        return;
    }
    auto callback = sptr<AppExceptionCallback>(new AppExceptionCallback());
    service->SetAppExceptionCallback(callback->AsObject());
}

void AppExceptionHandler::AbilityForegroundFailed(sptr<IRemoteObject> token, const std::string &msg)
{
    auto abilityRecord = Token::GetAbilityRecordByToken(token);
    if (abilityRecord == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "abilityRecord null");
        return;
    }
    FreezeUtil::LifecycleFlow flow{token, FreezeUtil::TimeoutState::FOREGROUND};
    FreezeUtil::GetInstance().AppendLifecycleEvent(flow, std::string("AbilityForegroundFailed: " + msg));

    TAG_LOGI(AAFwkTag::ABILITYMGR, "AbilityForegroundFailed: %{public}s", abilityRecord->GetURI().c_str());
    abilityRecord->SetFreezeStrategy(FreezeStrategy::NOTIFY_FREEZE_MGR);
}
}  // namespace AAFwk
}  // namespace OHOS
