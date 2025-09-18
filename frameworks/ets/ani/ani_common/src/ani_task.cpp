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

#include "ani_task.h"

#include <memory>
#include <thread>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
std::shared_ptr<OHOS::AppExecFwk::EventHandler> AniTask::mainHandler_ = nullptr;

ani_status AniTask::AniSendEvent(const std::function<void()> task)
{
    TAG_LOGD(AAFwkTag::ANI, "AniSendEvent");
    if (task == nullptr) {
        TAG_LOGD(AAFwkTag::ANI, "null task");
        return ani_status::ANI_INVALID_ARGS;
    }

    if (!mainHandler_) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        if (!runner) {
            TAG_LOGD(AAFwkTag::ANI, "null EventRunner");
            return ani_status::ANI_NOT_FOUND;
        }
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    if (mainHandler_ == nullptr) {
        TAG_LOGD(AAFwkTag::ANI, "null mainHandler");
        return ani_status::ANI_NOT_FOUND;
    }
    mainHandler_->PostTask(std::move(task));
    return ani_status::ANI_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS