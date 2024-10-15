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

#include "appfreeze_inner.h"
#include "appfreeze_state.h"
#include "hilog_tag_wrapper.h"
#include "xcollie/watchdog.h"

namespace OHOS {
namespace AbilityRuntime {
AppFreezeState::AppFreezeState()
{
    appFreezeStateFlag_ = 0;
}

void AppFreezeState::SetAppFreezeState(uint32_t flag)
{
    auto inner = AppExecFwk::AppfreezeInner::GetInstance();
    if (inner == nullptr) {
        TAG_LOGE(AAFwkTag::APPDFR, "null inner");
        return;
    }

    appFreezeStateFlag_ |= flag;
    if (appFreezeStateFlag_ > 0) {
        inner->SetAppDebug(true);
        OHOS::HiviewDFX::Watchdog::GetInstance().SetAppDebug(true);
    }
    TAG_LOGD(AAFwkTag::APPDFR, "App state flag: %{public}u, SetAppDebug true", appFreezeStateFlag_);
}

void AppFreezeState::CancelAppFreezeState(uint32_t flag)
{
    auto inner = AppExecFwk::AppfreezeInner::GetInstance();
    if (inner == nullptr) {
        TAG_LOGE(AAFwkTag::APPDFR, "null inner");
        return;
    }

    appFreezeStateFlag_ &= ~flag;
    if (appFreezeStateFlag_ == 0) {
        inner->SetAppDebug(false);
        OHOS::HiviewDFX::Watchdog::GetInstance().SetAppDebug(false);
    }
    TAG_LOGD(AAFwkTag::APPDFR, "App state flag: %{public}u, SetAppDebug false", appFreezeStateFlag_);
}
} // namespace AbilityRuntime
} // namespace OHOS