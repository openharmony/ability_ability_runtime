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

#include "js_start_abilities_observer.h"

#include "hilog_tag_wrapper.h"
 
namespace OHOS {
namespace AbilityRuntime {
JsStartAbilitiesObserver &JsStartAbilitiesObserver::GetInstance()
{
    static JsStartAbilitiesObserver instance;
    return instance;
}

void JsStartAbilitiesObserver::AddObserver(const std::string &requestKey, std::function<void(int32_t)> &&callback)
{
    std::lock_guard lock(jsObserverObjectListLock_);
    jsObserverObjectList_.emplace(requestKey, std::move(callback));
}

void JsStartAbilitiesObserver::HandleFinished(const std::string &requestKey, int32_t resultCode)
{
    std::function<void(int32_t)> callback;
    {
        std::lock_guard lock(jsObserverObjectListLock_);
        auto it = jsObserverObjectList_.find(requestKey);
        if (it != jsObserverObjectList_.end()) {
            callback = std::move(it->second);
            jsObserverObjectList_.erase(it);
        }
    }
    if (callback) {
        callback(resultCode);
        return;
    }
    TAG_LOGE(AAFwkTag::ABILITY, "null callback");
}
} // namespace AbilityRuntime
} // namespace OHOS