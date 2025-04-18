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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_RESULT_LISTENER_H
#define OHOS_ABILITY_RUNTIME_ABILITY_RESULT_LISTENER_H

#include <map>

#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
class AbilityResultListener {
public:
    AbilityResultListener() = default;
    virtual ~AbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) = 0;
    virtual bool IsMatch(int requestCode) = 0;
};

class AbilityResultListeners {
public:
    AbilityResultListeners() = default;
    virtual ~AbilityResultListeners() = default;
    void AddListener(const uint64_t &uiExtensionComponentId, std::shared_ptr<AbilityResultListener> listener);
    void RemoveListener(const uint64_t &uiExtensionComponentId);
    void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData);
private:
    std::map<uint64_t, std::shared_ptr<AbilityResultListener>> listeners_;
};

} // AbilityRuntime
} // OHOS

#endif // OHOS_ABILITY_RUNTIME_ABILITY_RESULT_LISTENER_H
