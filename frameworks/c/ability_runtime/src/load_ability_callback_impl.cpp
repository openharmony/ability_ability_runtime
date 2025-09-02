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

#include "load_ability_callback_impl.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
void LoadAbilityCallbackImpl::OnFinish(int32_t pid)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "call OnFinish");
    std::unique_lock<ffrt::mutex> lock(taskMutex_);
    if (task_) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "pid:%{public}d", pid);
        task_(pid);
    }
}

void LoadAbilityCallbackImpl::Cancel()
{
    TAG_LOGI(AAFwkTag::ABILITYMGR, "call Cancel");
    std::unique_lock<ffrt::mutex> lock(taskMutex_);
    task_ = nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS