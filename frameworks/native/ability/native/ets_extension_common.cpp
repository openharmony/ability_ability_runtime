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
#include "hilog_tag_wrapper.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *MEMORY_LEVEL_ENUM_NAME = "L@ohos/app/ability/AbilityConstant/AbilityConstant/MemoryLevel;";
}

using namespace OHOS::AppExecFwk;

std::shared_ptr<EtsExtensionCommon> EtsExtensionCommon::Create(
    STSRuntime &stsRuntime, STSNativeReference &stsObj, const std::shared_ptr<STSNativeReference> &shellContextRef)
{
    return std::make_shared<EtsExtensionCommon>(stsRuntime, stsObj, shellContextRef);
}

EtsExtensionCommon::EtsExtensionCommon(
    STSRuntime &stsRuntime, STSNativeReference &stsObj, const std::shared_ptr<STSNativeReference> &shellContextRef)
    : stsRuntime_(stsRuntime), stsObj_(stsObj), shellContextRef_(shellContextRef)
{}

EtsExtensionCommon::~EtsExtensionCommon() {}

void EtsExtensionCommon::OnConfigurationUpdated(const std::shared_ptr<AppExecFwk::Configuration> &fullConfig)
{
    TAG_LOGD(AAFwkTag::EXT, "OnConfigurationUpdated called");
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::EXT, "invalid config");
        return;
    }
    auto env = stsRuntime_.GetAniEnv();
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
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "env null");
        return;
    }

    ani_enum_item levelEnum {};
    if (!OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(env, MEMORY_LEVEL_ENUM_NAME, level, levelEnum)) {
        TAG_LOGE(AAFwkTag::EXT, "levelEnum failed");
        return;
    }
    CallObjectMethod("onMemoryLevel", nullptr, levelEnum);
}

void EtsExtensionCommon::CallObjectMethod(const char *name, const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::EXT, "name: %{public}s", name);
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null env");
        return;
    }
    ani_method method {};
    ani_status status = env->Class_FindMethod(stsObj_.aniCls, name, signature, &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::EXT, "Class_FindMethod status: %{public}d", status);
        env->ResetError();
        return;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(stsObj_.aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::EXT, "Object_CallMethod_Void_V status: %{public}d", status);
        stsRuntime_.HandleUncaughtError();
        return;
    }
    va_end(args);
    TAG_LOGI(AAFwkTag::EXT, "CallObjectMethod end, name: %{public}s", name);
}
} // namespace AbilityRuntime
} // namespace OHOS
