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

#include "ets_vertical_panel_manager.h"

#include "ability_context.h"
#include "ani_base_context.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"
#include "ets_error_utils.h"
#include "ets_panel_start_callback.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "screen_config.h"
#include "start_vertical_panel.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* VERTICAL_PANEL_MANAGER_CLASS_NAME =
    "@ohos.app.ability.verticalPanelManager.verticalPanelManager";
constexpr const char* SIGNATURE_START_VERTICAL_PANEL =
    "C{application.UIAbilityContext.UIAbilityContext}C{std.core.Record}"
    "C{@ohos.app.ability.verticalPanelManager.verticalPanelManager.PanelConfig}"
    "C{@ohos.app.ability.verticalPanelManager.verticalPanelManager.PanelStartCallback}:C{@ohos.base.BusinessError}";
constexpr const char* VERTICAL_TOOL_CLASS = "@ohos.app.ability.Want.RecordSerializeTool";
}  // namespace
class EtsVerticalPanelManager {
public:
    EtsVerticalPanelManager() = default;
    ~EtsVerticalPanelManager() = default;

    static bool RecordToStdString(ani_env *env, ani_ref aniSourceAppInfo, std::string &dst)
    {
        ani_status status = ANI_ERROR;
        ani_class cls = nullptr;
        if ((status = env->FindClass(VERTICAL_TOOL_CLASS, &cls)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "FindClass RecordSerializeTool failed, status: %{public}d", status);
            return false;
        }
        if (cls == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "RecordSerializeTool class null");
            return false;
        }
        ani_static_method stringifyMethod = nullptr;
        status = env->Class_FindStaticMethod(cls, "stringifyNoThrow", nullptr, &stringifyMethod);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "failed to get stringifyNoThrow method, status: %{public}d", status);
            return false;
        }
        ani_ref wantParamsAniString;
        status = env->Class_CallStaticMethod_Ref(cls, stringifyMethod, &wantParamsAniString, aniSourceAppInfo);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "failed to call stringifyNoThrow method, status: %{public}d", status);
            return false;
        }
        std::string wantParamsString;
        if (!AppExecFwk::GetStdString(env, reinterpret_cast<ani_string>(wantParamsAniString), dst)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "GetStdString failed");
            return false;
        }
        return true;
    }

    static bool ConvertContext(ani_env *env, const ani_object &aniContext,
        std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> &abilityContext)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env");
            return false;
        }

        auto context = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
        if (context == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Get context failed");
            return false;
        }

        abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
        if (abilityContext == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ConvertTo failed");
            return false;
        }

        auto applicationInfo = abilityContext->GetApplicationInfo();
        if (applicationInfo == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Get applicationInfo failed");
            return false;
        }
        return true;
    }

    static bool UnwrapScreenConfig(ani_env *env, ani_object aniScreenConfig, AAFwk::ScreenConfig &screenConfig)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env");
            return false;
        }
        if (aniScreenConfig == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null param");
            return false;
        }

        // 1. ScreenConfig.config: CapabilityType
        ani_ref aniType = nullptr;
        if (ANI_OK != env->Object_GetPropertyByName_Ref(aniScreenConfig, "type", &aniType)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Object_GetField_Ref type");
            return false;
        }
        if (!AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env,
            static_cast<ani_enum_item>(aniType), screenConfig.type)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "GetStdString failed type");
            return false;
        }

        // 2. ScreenConfig.sourceAppInfo: Record<string, string>
        ani_ref aniSourceAppInfo = nullptr;
        if (ANI_OK != env->Object_GetPropertyByName_Ref(aniScreenConfig, "sourceAppInfo", &aniSourceAppInfo)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Object_GetField_Ref sourceAppInfo");
            return false;
        }
        std::string sourceAppInfoString;
        if (!RecordToStdString(env, aniSourceAppInfo, sourceAppInfoString)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "ScreenConfig.sourceAppInfo failed to std::string");
            return false;
        }

        nlohmann::json sourceAppInfoJson = nlohmann::json::parse(sourceAppInfoString, nullptr, false);
        if (sourceAppInfoJson.is_discarded()) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Failed to parse json sourceAppInfoJson");
            return false;
        }
        try {
            screenConfig.sourceAppInfo = sourceAppInfoJson.get<std::map<std::string, std::string>>();
        } catch (const std::exception& e) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Failed to parse sourceAppInfoJson to sourceAppInfo");
            return false;
        }
        return true;
    }

    static ani_object StartVerticalPanel(
        ani_env *env, ani_object aniContext, ani_ref aniWantParam, ani_object aniScreenConfig, ani_object startCallback)
    {
        TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "StartVerticalPanel call");
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env.");
            return nullptr;
        }
        ani_object aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);

        auto selfToken = IPCSkeleton::GetSelfTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "This application is not system-app,"
                "can not use system-api");
            EtsErrorUtil::ThrowNotSystemAppError(env);
            return aniObject;
        }

        std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext;
        if (!ConvertContext(env, aniContext, abilityContext)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Failed to ConvertContext.");
            EtsErrorUtil::ThrowInvalidParamError(env, "Parse param context failed, context must be UIAbilityContext.");
            return aniObject;
        }

        AAFwk::WantParams wantParam;
        if (!AppExecFwk::UnwrapWantParams(env, aniWantParam, wantParam)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "parse wantParam failed");
            EtsErrorUtil::ThrowInvalidParamError(env, "Parse param want failed, want must be Want.");
            return aniObject;
        }

        AAFwk::ScreenConfig screenConfig;
        if (!UnwrapScreenConfig(env, aniScreenConfig, screenConfig)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "UnwrapScreenConfig failed");
            EtsErrorUtil::ThrowInvalidParamError(
                env, "Parse param screenConfig failed, screenConfig must be ScreenConfig.");
            return aniObject;
        }

        ani_vm *vm = nullptr;
        if (env->GetVM(&vm) != ANI_OK) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "get vm failed");
            EtsErrorUtil::ThrowInvalidParamError(env, "Internal error.");
            return aniObject;
        }
        std::shared_ptr<EtsPanelStartCallback> callback = std::make_shared<EtsPanelStartCallback>(vm);
        callback->SetEtsCallbackObject(startCallback);
        ErrCode innerErrCode = ERR_OK;
#ifdef SUPPORT_SCREEN
        innerErrCode = OHOS::AbilityRuntime::StartVerticalPanel(abilityContext, wantParam, screenConfig, callback);
#endif
        if (innerErrCode == ERR_OK) {
            return EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
        }
        return EtsErrorUtil::CreateErrorByNativeErr(env, innerErrCode);
    }
};

void EtsVerticalPanelManagerInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "EtsVerticalPanelManagerInit called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env");
        return;
    }

    ani_namespace ns;
    ani_status status = env->FindNamespace(VERTICAL_PANEL_MANAGER_CLASS_NAME, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "FindNamespace verticalPanelManager failed status: %{public}d", status);
        return;
    }

    std::array kitFunctions = {
        ani_native_function{"nativeStartVerticalPanelSync",
            SIGNATURE_START_VERTICAL_PANEL,
            reinterpret_cast<void *>(EtsVerticalPanelManager::StartVerticalPanel)},
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "bind startVerticalPanel failed status: %{public}d", status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    EtsVerticalPanelManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "ANI_Constructor finish");
    return ANI_OK;
}
}
}  // namespace AbilityRuntime
}  // namespace OHOS
