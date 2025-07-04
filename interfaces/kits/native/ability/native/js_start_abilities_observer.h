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

#ifndef OHOS_ABILITY_RUNTIME_JS_START_ABILITIES_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_JS_START_ABILITIES_OBSERVER_H

#include <functional>
#include <map>
#include <mutex>
#include <string>

namespace OHOS {
namespace AbilityRuntime {
class JsStartAbilitiesObserver {
public:
    static JsStartAbilitiesObserver &GetInstance();
    ~JsStartAbilitiesObserver() = default;
    void AddObserver(const std::string &requestKey, std::function<void(int32_t)> &&callback);
    void HandleFinished(const std::string &requestKey, int32_t resultCode);
protected:
    JsStartAbilitiesObserver() = default;
private:
    std::mutex jsObserverObjectListLock_;
    std::map<std::string, std::function<void(int32_t)>> jsObserverObjectList_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_JS_START_ABILITIES_OBSERVER_H