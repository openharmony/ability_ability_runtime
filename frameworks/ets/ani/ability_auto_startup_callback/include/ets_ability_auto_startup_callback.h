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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_AUTO_STARTUP_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_AUTO_STARTUP_CALLBACK_H

#include <chrono>
#include <iremote_object.h>
#include <vector>

#include "ani.h"
#include "ani_common_util.h"
#include "auto_startup_callback_stub.h"
#include "auto_startup_info.h"
#include "ets_native_reference.h"
#include "event_handler.h"
#include "parcel.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 *
 * @class EtsAbilityAutoStartupCallback
 */
class EtsAbilityAutoStartupCallback : public AutoStartupCallBackStub {
public:
    explicit EtsAbilityAutoStartupCallback(ani_vm *etsVm);
    virtual ~EtsAbilityAutoStartupCallback();
    void Register(ani_object value);
    void Unregister(ani_object value);
    void OnAutoStartupOn(const AutoStartupInfo &info) override;
    void OnAutoStartupOff(const AutoStartupInfo &info) override;
    bool IsCallbacksEmpty();

private:
    ani_status AniSendEvent(const std::function<void()> task);
    void EtsCallFunction(const AutoStartupInfo &info, const char *methodName);
    void EtsCallFunctionWorker(const AutoStartupInfo &info, const char *methodName);
    void GetCallbackVector(std::vector<ani_ref>& callbacks);
    ani_env* GetAniEnv();
    ani_env* AttachAniEnv();
    void DetachAniEnv();
    bool IsEtsCallbackEquals(ani_ref callback, ani_object value);

    ani_vm *etsVm_;
    std::vector<ani_ref> callbacks_;
    std::mutex mutexlock_;
    std::shared_ptr<AppExecFwk::EventHandler> mainHandler_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_AUTO_STARTUP_CALLBACK_H
