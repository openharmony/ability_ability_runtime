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

#ifndef OHOS_ABILITY_RUNTIME_CJ_APPLICATION_STATE_CHANGE_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_CJ_APPLICATION_STATE_CHANGE_CALLBACK_H

#include <map>
#include "application_state_change_callback.h"

namespace OHOS {
namespace AbilityRuntime {

class CjApplicationStateChangeCallback : public ApplicationStateChangeCallback,
    public std::enable_shared_from_this<CjApplicationStateChangeCallback> {
public:
    explicit CjApplicationStateChangeCallback();
    virtual ~CjApplicationStateChangeCallback() = default;
    void NotifyApplicationForeground() override;
    void NotifyApplicationBackground() override;
    int32_t Register(std::function<void(void)> foregroundCallback, std::function<void(void)> backgroundCallback);
    bool UnRegister(int32_t callbackId);
    bool IsEmpty() const;
private:
    std::map<int32_t, std::function<void(void)>> foregroundCallbacks_;
    std::map<int32_t, std::function<void(void)>> backgroundCallbacks_;
    static int32_t serialNumber_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_APPLICATION_STATE_CHANGE_CALLBACK_H
