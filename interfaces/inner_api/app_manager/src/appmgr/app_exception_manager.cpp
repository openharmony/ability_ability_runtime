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

#include "app_exception_manager.h"

#include "freeze_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
using AbilityRuntime::FreezeUtil;
namespace AppExecFwk {
AppExceptionManager &AppExceptionManager::GetInstance()
{
    static AppExceptionManager appExceptionMgr;
    return appExceptionMgr;
}

void AppExceptionManager::LaunchAbilityFailed(sptr<IRemoteObject> token, const std::string &msg)
{
    FreezeUtil::LifecycleFlow flow{token, FreezeUtil::TimeoutState::LOAD};
    FreezeUtil::GetInstance().AppendLifecycleEvent(flow, std::string("LaunchAbilityFailed: " + msg));
    NotifyLifecycleException(LifecycleException::LAUNCH_ABILITY_FAIL, token);
}

void AppExceptionManager::ForegroundAppFailed(sptr<IRemoteObject> token, const std::string &msg)
{
    FreezeUtil::LifecycleFlow flow{token, FreezeUtil::TimeoutState::FOREGROUND};
    FreezeUtil::GetInstance().AppendLifecycleEvent(flow, std::string("ForegroundAppFailed: " + msg));
    NotifyLifecycleException(LifecycleException::FOREGROUND_APP_FAIL, token);
}

void AppExceptionManager::ForegroundAppWait(sptr<IRemoteObject> token, const std::string &msg)
{
    FreezeUtil::LifecycleFlow flow{token, FreezeUtil::TimeoutState::FOREGROUND};
    FreezeUtil::GetInstance().AppendLifecycleEvent(flow, std::string("ForegroundAppWait: " + msg));
    NotifyLifecycleException(LifecycleException::FOREGROUND_APP_WAIT, token);
}

void AppExceptionManager::NotifyLifecycleException(LifecycleException type, sptr<IRemoteObject> token)
{
    auto callback = GetExceptionCallback();
    if (callback != nullptr) {
        TAG_LOGI(AAFwkTag::APPMGR, "notify app exception");
        callback->OnLifecycleException(type, token);
    }
}

void AppExceptionManager::SetExceptionCallback(sptr<IAppExceptionCallback> exceptionCallback)
{
    if (exceptionCallback == nullptr) {
        TAG_LOGW(AAFwkTag::APPMGR, "callback null");
    }
    std::lock_guard lock(exceptionCallbackMutex_);
    if (exceptionCallback_ != nullptr) {
        TAG_LOGI(AAFwkTag::APPMGR, "inner callback not null");
    }
    exceptionCallback_ = exceptionCallback;
}

sptr<IAppExceptionCallback> AppExceptionManager::GetExceptionCallback() const
{
    std::lock_guard lock(exceptionCallbackMutex_);
    return exceptionCallback_;
}
}  // namespace AppExecFwk
}  // namespace OHOS