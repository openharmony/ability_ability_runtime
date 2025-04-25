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
#include "ui_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ohos_application.h"
#include "sts_free_install_observer.h"
namespace OHOS {
namespace AbilityRuntime {

[[maybe_unused]] static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object callback);
[[maybe_unused]] static void TerminateSelfWithResultSync([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object obj, [[maybe_unused]] ani_object abilityResult, [[maybe_unused]] ani_object callback);
ani_object CreateStsUIExtensionContext(ani_env *env, std::shared_ptr<UIExtensionContext> context,
    const std::shared_ptr<AppExecFwk::OHOSApplication> &application);

bool BindNativeMethods(ani_env *env, ani_class &cls);

class StsUIExtensionContext final {
public:
    static StsUIExtensionContext &GetInstance()
    {
        static StsUIExtensionContext instance;
        return instance;
    }
    void StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
        ani_object wantObj, ani_object opt, ani_object call);
    static UIExtensionContext* GetAbilityContext(ani_env *env, ani_object obj);
    void AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want,
        ani_object callback, UIExtensionContext* context);
private:
    sptr<StsFreeInstallObserver> freeInstallObserver_ = nullptr;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTEXT_H