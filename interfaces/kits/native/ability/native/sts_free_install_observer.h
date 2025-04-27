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
#ifndef OHOS_ABILITY_RUNTIME_STS_FREE_INSTALL_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_STS_FREE_INSTALL_OBSERVER_H

#include <memory>
#include <string>
#include <vector>

#include "native_engine/native_engine.h"
#include "sts_runtime.h"
#include "sts_error_utils.h"
#include "free_install_observer_stub.h"

namespace OHOS {
namespace AbilityRuntime {
struct StsFreeInstallObserverObject {
    std::string bundleName;
    std::string abilityName;
    std::string startTime;
    std::string url;
    ani_object callBack;
    bool isAbilityResult = false;
};

class StsFreeInstallObserver : public FreeInstallObserverStub {
public:
    explicit StsFreeInstallObserver(ani_vm *etsVm);
    virtual ~StsFreeInstallObserver();

    void OnInstallFinished(const std::string &bundleName, const std::string &abilityName, const std::string &startTime,
        const int &resultCode) override;
    void OnInstallFinishedByUrl(const std::string &startTime, const std::string& url, const int &resultCode) override;
    void AddStsObserverObject(ani_env *env, const std::string &bundleName, const std::string &abilityName,
        const std::string &startTime, ani_object callBack);
    void AddStsObserverObject(ani_env *env, const std::string &startTime, const std::string &url, ani_object callBack);

private:
    void CallCallback(ani_object callback, int32_t resultCode);
    void HandleOnInstallFinished(const std::string &bundleName, const std::string &abilityName,
        const std::string &startTime, const int &resultCode);
    void HandleOnInstallFinishedByUrl(const std::string &startTime, const std::string& url, const int &resultCode);
    void AddStsObserverCommon(ani_env *env, StsFreeInstallObserverObject &object, ani_object callBack);

    ani_vm *etsVm_;
    std::mutex stsObserverObjectListLock_;
    std::vector<StsFreeInstallObserverObject> stsObserverObjectList_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_STS_FREE_INSTALL_OBSERVER_H