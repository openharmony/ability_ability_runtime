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

#ifndef OHOS_ABILITY_RUNTIME_CJ_UI_EXTENSION_OBJECT_H
#define OHOS_ABILITY_RUNTIME_CJ_UI_EXTENSION_OBJECT_H

#include "ability_handler.h"
#include "ability_local_record.h"
#include "configuration.h"
#include "ohos_application.h"
#include "want.h"
#include "window.h"

#ifdef WINDOWS_PLATFORM
#define CJ_EXPORT __declspec(dllexport)
#else
#define CJ_EXPORT __attribute__((visibility("default")))
#endif

enum class CJExtensionAbilityType {
    ACTION = 0,
    EMBEDDED,
    PHOTO_EDITOR,
    SHARE,
};

namespace OHOS {
namespace AbilityRuntime {
using ExtAbilityHandle = void*;
using Want = OHOS::AAFwk::Want;
class CJRuntime;
/**
 * @brief cj ui extension object.
 */
class CJUIExtensionObject {
public:
    CJUIExtensionObject() : cjID_(0) {}
    ~CJUIExtensionObject() = default;

    int32_t Init(const std::string& abilityName, CJExtensionAbilityType type, ExtAbilityHandle extAbility);
    int64_t GetID() const
    {
        return cjID_;
    }
    void Destroy();

    void OnCreate(const AAFwk::Want &want, AAFwk::LaunchParam &launchParam);
    void OnDestroy();
    void OnSessionCreate(const AAFwk::Want &want, int64_t sessionId);
    void OnSessionDestroy(int64_t sessionId);
    void OnForeground();
    void OnBackground();
    void OnConfigurationUpdate(std::shared_ptr<AppExecFwk::Configuration> fullConfig);
    void OnMemoryLevel(int level);
    void OnStartContentEditing(const std::string& imageUri, const AAFwk::Want &want, int64_t sessionId);
protected:
    int32_t GetType() const
    {
        return static_cast<int32_t>(type_);
    }
protected:
    int64_t cjID_;
    CJExtensionAbilityType type_;
};

using WantHandle = void*;

} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_UI_EXTENSION_OBJECT_H
