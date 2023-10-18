/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "app_running_status_module.h"

#include "app_running_status_proxy.h"
#include "cpp/mutex.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t AppRunningStausModule::RegisterListener(const sptr<IAppRunningStatusListener> &listener)
{
    listener_ = listener;
    return ERR_OK;
}

int32_t AppRunningStausModule::UnregisterListener(const sptr<IAppRunningStatusListener> &listener)
{
    if (listener != listener_) {
        HILOG_ERROR("Listener is null");
        return ERR_INVALID_OPERATION;
    }

    listener_ = nullptr;
    return ERR_OK;
}

void AppRunningStausModule::NotifyAppRunningStatusEvent(const std::string &bundle, int32_t &uid, int32_t runningStatus)
{
    if (listener_ == nullptr) {
        HILOG_ERROR("Listener is null");
        return;
    }

    listener_->NotifyAppRunningStatus(bundle, uid, runningStatus);
}
} // namespace AbilityRuntime
} // namespace OHOS
