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

#ifndef ABILITY_RUNTIME_LOAD_ABILITY_CALLBACK_IMPL_H
#define ABILITY_RUNTIME_LOAD_ABILITY_CALLBACK_IMPL_H

#include <functional>

#include "ffrt.h"
#include "load_ability_callback_stub.h"

namespace OHOS {
namespace AbilityRuntime {
using OHOS::AppExecFwk::LoadAbilityCallbackStub;
using OnFinishTask = std::function<void(int32_t)>;
class LoadAbilityCallbackImpl : public LoadAbilityCallbackStub {
public:
    explicit LoadAbilityCallbackImpl(OnFinishTask &&task) : task_(task) {}
    virtual ~LoadAbilityCallbackImpl() = default;

    /**
     * Callback to return pid.
     *
     * @param pid Process id.
     */
    virtual void OnFinish(int32_t pid) override;

    void Cancel();

private:
    ffrt::mutex taskMutex_;
    OnFinishTask task_;
};
}
}
#endif // ABILITY_RUNTIME_LOAD_ABILITY_CALLBACK_IMPL_H