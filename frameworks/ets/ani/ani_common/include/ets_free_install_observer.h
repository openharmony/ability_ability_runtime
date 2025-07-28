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
#ifndef OHOS_ABILITY_RUNTIME_ETS_FREE_INSTALL_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_ETS_FREE_INSTALL_OBSERVER_H

#include <memory>
#include <string>
#include <vector>

#include "ets_error_utils.h"
#include "ets_runtime.h"
#include "free_install_observer_stub.h"

namespace OHOS {
namespace AbilityRuntime {
struct EtsFreeInstallObserverObject {
    std::string bundleName;
    std::string abilityName;
    std::string startTime;
    std::string url;
    ani_object callback = nullptr;
    bool isAbilityResult = false;
};

class EtsFreeInstallObserver : public FreeInstallObserverStub {
public:
    explicit EtsFreeInstallObserver(ani_vm *etsVm);
    virtual ~EtsFreeInstallObserver();

    void OnInstallFinished(const std::string &bundleName, const std::string &abilityName, const std::string &startTime,
        int32_t resultCode) override;
    void OnInstallFinished(const std::string &bundleName, const std::string &abilityName, const std::string &startTime,
        ani_object abilityResult);
    void OnInstallFinishedByUrl(const std::string &startTime, const std::string &url, int32_t resultCode) override;
    void AddEtsObserverObject(ani_env *env, const std::string &bundleName, const std::string &abilityName,
        const std::string &startTime, ani_object callback, bool isAbilityResult = false);
    void AddEtsObserverObject(ani_env *env, const std::string &startTime,
        const std::string &url, ani_object callback, bool isAbilityResult = false);

private:
    void CallCallback(ani_object callback, int32_t resultCode);
    void CallCallback(ani_object callback, ani_object abilityResult);
    void HandleOnInstallFinished(const std::string &bundleName, const std::string &abilityName,
        const std::string &startTime, int32_t resultCode);
    void HandleOnInstallFinishedByUrl(const std::string &startTime, const std::string &url, int32_t resultCode);
    void AddEtsObserverCommon(ani_env *env, EtsFreeInstallObserverObject &object, ani_object callback);

    ani_vm *etsVm_ = nullptr;
    std::mutex etsObserverObjectListLock_;
    std::vector<EtsFreeInstallObserverObject> etsObserverObjectList_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ETS_FREE_INSTALL_OBSERVER_H