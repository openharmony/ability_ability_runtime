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

#ifndef OHOS_ABILITY_RUNTIME_ETS_SYSTEM_CONFIGURATION_UPDATED_CALLBACK_H
#define OHOS_ABILITY_RUNTIME_ETS_SYSTEM_CONFIGURATION_UPDATED_CALLBACK_H

#include <mutex>
#include <set>

#include "ani.h"
#include "system_configuration_updated_callback.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class EtsSystemConfigurationUpdatedCallback
    : public SystemConfigurationUpdatedCallback,
      public std::enable_shared_from_this<EtsSystemConfigurationUpdatedCallback> {
public:
    explicit EtsSystemConfigurationUpdatedCallback(ani_vm *etsVm);
    virtual ~EtsSystemConfigurationUpdatedCallback();

    void Register(ani_object aniCallback);
    bool UnRegister(ani_object aniCallback = nullptr);

    void NotifySystemConfigurationUpdated(const AppExecFwk::Configuration &configuration) override;
    void NotifyColorModeUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &colorMode);
    void NotifyFontSizeScaleUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyFontWeightScaleUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyLanguageUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyFontIdUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyMCCUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyMNCUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyLocaleUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    void NotifyHasPointerDeviceUpdated(ani_env *env, ani_ref callback, ani_ref method, const std::string &);
    bool IsEmpty() const;

private:
    bool IsEquel(ani_env *env, ani_object aniCallback, ani_ref refCallback);

    bool CheckAndGetAniMethod(ani_env *env, ani_ref callback, const char *methodName, ani_ref &method);
    template <class NATIVE_T, class ANI_T>
    void CallAniMethod(ani_env *env, ani_ref callback, ani_ref method, const NATIVE_T &value);
    ani_vm *etsVm_ = nullptr;
    std::set<ani_ref> callbacksRef_;
    mutable std::mutex mutex_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_SYSTEM_CONFIGURATION_UPDATED_CALLBACK_H
