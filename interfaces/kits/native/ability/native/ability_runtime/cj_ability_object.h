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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_OBJECT_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_OBJECT_H

#include <memory>

#include "ability.h"
#include "cj_runtime.h"
#include "configuration.h"

#ifdef WINDOWS_PLATFORM
#define CJ_EXPORT __declspec(dllexport)
#else
#define CJ_EXPORT __attribute__((visibility("default")))
#endif

using AbilityHandle = void*;
using WantHandle = void*;
using WindowStagePtr = void*;
using VectorStringHandle = void*;

extern "C" {
struct CJConfiguration {
    bool isValid;
    const char* language;
    int32_t colorMode;
    int32_t direction;
    int32_t screenDensity;
    int32_t displayId;
};
}

extern "C" {
struct CJLaunchParam {
    int32_t launchReason;
    int32_t lastExitReason;
};

struct CJAbilityFuncs {
    int64_t (*cjAbilityCreate)(const char* name);
    void (*cjAbilityRelease)(int64_t id);
    void (*cjAbilityOnStart)(int64_t id, WantHandle want, CJLaunchParam launchParam);
    void (*cjAbilityOnStop)(int64_t id);
    void (*cjAbilityOnSceneCreated)(int64_t id, WindowStagePtr cjWindowStage);
    void (*cjAbilityOnSceneRestored)(int64_t id, WindowStagePtr cjWindowStage);
    void (*cjAbilityOnSceneDestroyed)(int64_t id);
    void (*cjAbilityOnForeground)(int64_t id, WantHandle want);
    void (*cjAbilityOnBackground)(int64_t id);
    void (*cjAbilityOnConfigurationUpdated)(int64_t id, CJConfiguration configuration);
    void (*cjAbilityOnNewWant)(int64_t id, WantHandle want, CJLaunchParam launchParam);
    VectorStringHandle (*cjAbilityDump)(int64_t id, VectorStringHandle params);
    int32_t (*cjAbilityOnContinue)(int64_t id, const char* params);
    void (*cjAbilityInit)(int64_t id, void* ability);
};

CJ_EXPORT void RegisterCJAbilityFuncs(void (*registerFunc)(CJAbilityFuncs*));
}

namespace OHOS {

namespace Rosen {
class CJWindowStageImpl;
}

namespace AbilityRuntime {
class CJAbilityObject {
public:
    static std::shared_ptr<CJAbilityObject> LoadModule(const std::string& name);

    explicit CJAbilityObject(int64_t id) : id_(id) {}
    ~CJAbilityObject();
    void OnStart(const AAFwk::Want& want, const AAFwk::LaunchParam& launchParam) const;
    void OnStop() const;
    void OnSceneCreated(OHOS::Rosen::CJWindowStageImpl* cjWindowStage) const;
    void OnSceneRestored(OHOS::Rosen::CJWindowStageImpl* cjWindowStage) const;
    void OnSceneDestroyed() const;
    void OnForeground(const AAFwk::Want& want) const;
    void OnBackground() const;
    void OnConfigurationUpdated(const std::shared_ptr<AppExecFwk::Configuration>& configuration) const;
    void OnNewWant(const AAFwk::Want& want, const AAFwk::LaunchParam& launchParam) const;
    void Dump(const std::vector<std::string>& params, std::vector<std::string>& info) const;
    int32_t OnContinue(AAFwk::WantParams &wantParams) const;
    void Init(AbilityHandle ability) const;

private:
    int64_t id_ = 0;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_ABILITY_OBJECT_H