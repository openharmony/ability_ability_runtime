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

#include "ets_extension_common.h"

#include "ani_common_configuration.h"
#include "ani_enum_convert.h"
#include "ets_extension_context.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *MEMORY_LEVEL_ENUM_NAME = "@ohos.app.ability.AbilityConstant.AbilityConstant.MemoryLevel";
} // namespace

using namespace OHOS::AppExecFwk;

std::shared_ptr<EtsExtensionCommon> EtsExtensionCommon::Create(ETSRuntime &etsRuntime,
    AppExecFwk::ETSNativeReference &etsObj, const std::shared_ptr<AppExecFwk::ETSNativeReference> &shellContextRef)
{
    return std::make_shared<EtsExtensionCommon>(etsRuntime, etsObj, shellContextRef);
}

EtsExtensionCommon::EtsExtensionCommon(ETSRuntime &etsRuntime, AppExecFwk::ETSNativeReference &etsObj,
    const std::shared_ptr<AppExecFwk::ETSNativeReference> &shellContextRef)
    : etsRuntime_(etsRuntime), etsObj_(etsObj), shellContextRef_(shellContextRef)
{}

EtsExtensionCommon::~EtsExtensionCommon() {}

void EtsExtensionCommon::OnConfigurationUpdated(const std::shared_ptr<AppExecFwk::Configuration> &fullConfig)
{
    TAG_LOGD(AAFwkTag::EXT, "OnConfigurationUpdated called");
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::EXT, "invalid config");
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "env null");
        return;
    }
    if (shellContextRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "shellContextRef_ null");
        return;
    }
    EtsExtensionContext::ConfigurationUpdated(env, shellContextRef_, fullConfig);

    ani_object aniConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    CallObjectMethod("onConfigurationUpdate", nullptr, aniConfiguration);
}

void EtsExtensionCommon::OnMemoryLevel(int level)
{
    TAG_LOGD(AAFwkTag::EXT, "OnMemoryLevel called");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "env null");
        return;
    }

    ani_enum_item levelEnum {};
    if (!OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, MEMORY_LEVEL_ENUM_NAME, level, levelEnum)) {
        TAG_LOGE(AAFwkTag::EXT, "levelEnum failed");
        return;
    }
    CallObjectMethod("onMemoryLevel", nullptr, levelEnum);
}

void EtsExtensionCommon::CallObjectMethod(const char *name, const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::EXT, "name: %{public}s", name);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null env");
        return;
    }
    ani_method method = nullptr;
    ani_status status = env->Class_FindMethod(etsObj_.aniCls, name, signature, &method);
    if (status != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "Class_FindMethod status: %{public}d, or null method", status);
        env->ResetError();
        return;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObj_.aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::EXT, "Object_CallMethod_Void_V status: %{public}d", status);
        etsRuntime_.HandleUncaughtError();
        return;
    }
    va_end(args);
    TAG_LOGI(AAFwkTag::EXT, "CallObjectMethod end, name: %{public}s", name);
}
} // namespace AbilityRuntime
} // namespace OHOS
