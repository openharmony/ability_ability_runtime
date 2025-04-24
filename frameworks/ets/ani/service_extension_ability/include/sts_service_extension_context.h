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
#ifndef OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H

#include "sts_runtime.h"
#include <array>
#include <iostream>
#include <unistd.h>
#include "service_extension.h"
#include "service_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ohos_application.h"
#include "sts_free_install_observer.h"

[[maybe_unused]] static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object callback);
[[maybe_unused]] static void StartAbility([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object call);
[[maybe_unused]] static void StartAbilityWithOption([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call);
[[maybe_unused]] static void StartServiceExtensionAbilitySync([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object obj, [[maybe_unused]] ani_object wantObj, [[maybe_unused]] ani_object callbackobj);
ani_object CreateStsServiceExtensionContext(ani_env *env,
    std::shared_ptr<OHOS::AbilityRuntime::ServiceExtensionContext> context,
    const std::shared_ptr<OHOS::AppExecFwk::OHOSApplication> &application);

void StsCreatExtensionContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<OHOS::AbilityRuntime::ExtensionContext> context);

void BindExtensionInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo);

class StsServiceExtensionContext final {
public:
    static StsServiceExtensionContext &GetInstance()
    {
        static StsServiceExtensionContext instance;
        return instance;
    }
    void StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
        ani_object wantObj, ani_object opt, ani_object call);
    static OHOS::AbilityRuntime::ServiceExtensionContext* GetAbilityContext(ani_env *env, ani_object obj);
    void AddFreeInstallObserver(ani_env *env, const OHOS::AAFwk::Want &want, ani_object callback,
        OHOS::AbilityRuntime::ServiceExtensionContext* context);
private:
    OHOS::sptr<OHOS::AbilityRuntime::StsFreeInstallObserver> freeInstallObserver_ = nullptr;
};
#endif // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H