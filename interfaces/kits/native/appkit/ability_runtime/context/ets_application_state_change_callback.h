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

#ifndef OHOS_ABILITY_RUNTIME_ETS_APPLICATION_STATE_CHANGE_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_ETS_APPLICATION_STATE_CHANGE_CALLBACK_H

#include <memory>
#include <set>
#include <string>
#include <mutex>

#include "application_state_change_callback.h"
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsApplicationStateChangeCallback : public ApplicationStateChangeCallback,
    public std::enable_shared_from_this<EtsApplicationStateChangeCallback> {
public:
    explicit EtsApplicationStateChangeCallback(ani_env *env);
    virtual ~EtsApplicationStateChangeCallback() = default;
    void NotifyApplicationForeground() override;
    void NotifyApplicationBackground() override;
    void Register(ani_object aniCallback);

    /**
     * @brief Unregister application state change callback.
     * @param aniCallback, if jscallback is nullptr, delete all register jscallback.
     *                    or if jscallback is specified, delete prescribed jscallback.
     * @return Returns true on unregister success, others return false.
     */
    bool UnRegister(ani_object aniCallback = nullptr);
    bool IsEmpty() const;
private:
    void CallEtsMethod(const std::string &methodName);
    ani_env *env_ = nullptr;
    std::set<ani_ref> callbacks_;
    mutable std::mutex Mutex_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_APPLICATION_STATE_CHANGE_CALLBACK_H
