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

#ifndef OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_OBJECT_H
#define OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_OBJECT_H

#include "want.h"

#ifdef WINDOWS_PLATFORM
#define CJ_EXPORT __declspec(dllexport)
#else
#define CJ_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {

/**
 * @brief cj insightIntentExecutor object.
 */
class CJFormExtensionObject {
public:
    CJFormExtensionObject() : cjID_(0) {}
    ~CJFormExtensionObject() = default;

    int32_t Init(const std::string& abilityName);
    int64_t GetID() const
    {
        return cjID_;
    }
    
    void OnAddForm(const AAFwk::Want& want);

    void OnStop();

protected:
    int64_t cjID_;
};

using WantHandle = void*;

} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_OBJECT_H
