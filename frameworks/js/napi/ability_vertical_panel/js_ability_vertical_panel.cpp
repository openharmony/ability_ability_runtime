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

#include "js_ability_vertical_panel.h"

#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "js_panel_start_callback.h"
#include "js_error_utils.h"
#include "js_runtime_utils.h"
#include "napi_base_context.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "native_engine/native_value.h"
#include "screen_config.h"
#include "start_vertical_panel.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
constexpr size_t ARGC_FOUR = 4;

static void SetNamedProperty(napi_env env, napi_value dstObj, const char *objName, const char *propName)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "SetNamedProperty called");
    napi_value prop = nullptr;
    napi_create_string_utf8(env, objName, NAPI_AUTO_LENGTH, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

class JsAbilityVerticalPanel {
public:
    JsAbilityVerticalPanel() = default;
    ~JsAbilityVerticalPanel() = default;

    static void Finalizer(napi_env env, void *data, void *hint)
    {
        TAG_LOGI(AAFwkTag::VERTICAL_PANEL, "finalizer");
        std::unique_ptr<JsAbilityVerticalPanel>(static_cast<JsAbilityVerticalPanel*>(data));
    }

    static napi_value StartVerticalPanel(napi_env env, napi_callback_info info)
    {
        GET_NAPI_INFO_AND_CALL(env, info, JsAbilityVerticalPanel, OnStartVerticalPanel);
    }

private:
    static bool GetContext(napi_env env, napi_value value,
        std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> &abilityContext)
    {
        bool stageMode = false;
        napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
        if (status != napi_ok || !stageMode) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Get context It is not a stage mode");
            return false;
        }

        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Get context GetStageModeContext failed");
            return false;
        }

        abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (abilityContext == nullptr || abilityContext->GetApplicationInfo() == nullptr) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "Get context failed");
            return false;
        }

        return true;
    }

    static bool UnwrapScreenConfig(napi_env env, napi_value param, AAFwk::ScreenConfig &screenConfig)
    {
        if (!AppExecFwk::IsTypeForNapiValue(env, param, napi_object)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "UnwrapScreenConfig param IsTypeForNapiValue failed");
            return false;
        }

        napi_value type = nullptr;
        napi_get_named_property(env, param, "type", &type);
        if (type == nullptr || !ConvertFromJsValue(env, type, screenConfig.type)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "parse UnwrapScreenConfig failed: type");
            return false;
        }

        napi_value sourceAppInfo = nullptr;
        napi_get_named_property(env, param, "sourceAppInfo", &sourceAppInfo);
        if (sourceAppInfo == nullptr || !AppExecFwk::IsTypeForNapiValue(env, sourceAppInfo, napi_object)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "parse UnwrapScreenConfig failed: sourceAppInfo");
            return false;
        }

        napi_valuetype jsValueType = napi_undefined;
        napi_value jsProNameList = nullptr;
        uint32_t jsProCount = 0;

        NAPI_CALL_BASE(env, napi_get_property_names(env, sourceAppInfo, &jsProNameList), false);
        NAPI_CALL_BASE(env, napi_get_array_length(env, jsProNameList, &jsProCount), false);

        napi_value jsProName = nullptr;
        napi_value jsProValue = nullptr;
        for (uint32_t index = 0; index < jsProCount; index++) {
            NAPI_CALL_BASE(env, napi_get_element(env, jsProNameList, index, &jsProName), false);

            std::string strProName = AppExecFwk::UnwrapStringFromJS(env, jsProName);
            TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "property name=%{public}s", strProName.c_str());
            NAPI_CALL_BASE(env, napi_get_named_property(env, sourceAppInfo, strProName.c_str(), &jsProValue), false);
            NAPI_CALL_BASE(env, napi_typeof(env, jsProValue, &jsValueType), false);

            std::string natValue = AppExecFwk::UnwrapStringFromJS(env, jsProValue);
            screenConfig.sourceAppInfo[strProName] = natValue;
        }
        return true;
    }

    napi_value ExecuteStartVerticalPanel(napi_env env,
        std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext,
        const AAFwk::WantParams &wantParam,
        const AAFwk::ScreenConfig &screenConfig,
        std::shared_ptr<JsPanelStartCallback> callback)
    {
        auto innerErrCode = std::make_shared<ErrCode>(ERR_OK);
        NapiAsyncTask::ExecuteCallback execute =
            [abilityContext, wantParamCopy = wantParam, screenConfig, callback, innerErrCode]() mutable {
#ifdef SUPPORT_SCREEN
                *innerErrCode = OHOS::AbilityRuntime::StartVerticalPanel(
                    abilityContext, wantParamCopy, screenConfig, callback);
#endif
            };
        NapiAsyncTask::CompleteCallback complete =
            [innerErrCode](napi_env env, NapiAsyncTask& task, int32_t status) {
                if (*innerErrCode == ERR_OK) {
                    task.ResolveWithNoError(env, CreateJsUndefined(env));
                } else {
                    task.Reject(env, CreateJsErrorByNativeErr(env, *innerErrCode));
                }
            };
        napi_value result = nullptr;
        NapiAsyncTask::ScheduleHighQos("JsAbilityVerticalPanel::OnStartVerticalPanel",
            env, CreateAsyncTaskWithLastParam(env, nullptr, std::move(execute), std::move(complete), &result));
        return result;
    }

    napi_value OnStartVerticalPanel(napi_env env, NapiCallbackInfo &info)
    {
        TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "OnStartVerticalPanel call");

        auto selfToken = IPCSkeleton::GetSelfTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "This application is not system-app,"
                "can not use system-api");
            ThrowNotSystemAppError(env);
            return CreateJsUndefined(env);
        }

        if (info.argc < ARGC_FOUR) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "OnStartVerticalPanel invalid params");
            ThrowTooFewParametersError(env);
            return CreateJsUndefined(env);
        }

        std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext;
        if (!GetContext(env, info.argv[INDEX_ZERO], abilityContext)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "OnStartVerticalPanel parse context failed");
            ThrowInvalidParamError(env, "Parse param context failed, context must be UIAbilityContext.");
            return CreateJsUndefined(env);
        }

        AAFwk::WantParams wantParam;
        if (!AppExecFwk::UnwrapWantParams(env, info.argv[INDEX_ONE], wantParam)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "OnStartVerticalPanel parse wantParam failed");
            ThrowInvalidParamError(env, "Parse param want failed, want must be Want.");
            return CreateJsUndefined(env);
        }

        AAFwk::ScreenConfig screenConfig;
        if (!UnwrapScreenConfig(env, info.argv[INDEX_TWO], screenConfig)) {
            TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "OnStartVerticalPanel parse screenConfig failed");
            ThrowInvalidParamError(env, "Parse param screenConfig failed, screenConfig must be ScreenConfig.");
            return CreateJsUndefined(env);
        }

        std::shared_ptr<JsPanelStartCallback> callback = std::make_shared<JsPanelStartCallback>(env);
        callback->SetJsCallbackObject(info.argv[INDEX_THREE]);
        return ExecuteStartVerticalPanel(env, abilityContext, wantParam, screenConfig, callback);
    }
};

napi_value JsAbilityVerticalPanelInit(napi_env env, napi_value exportObj)
{
    if (env == nullptr || exportObj == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env or exportObj");
        return nullptr;
    }

    napi_value verticalType = nullptr;
    napi_create_object(env, &verticalType);
    SetNamedProperty(env, verticalType, "navigation", "NAVIGATION");

    napi_value bundleName = nullptr;
    napi_create_string_utf8(env, "bundleName", NAPI_AUTO_LENGTH, &bundleName);
    napi_value moduleNameProp = nullptr;
    napi_create_string_utf8(env, "moduleName", NAPI_AUTO_LENGTH, &moduleNameProp);
    napi_value abilityName = nullptr;
    napi_create_string_utf8(env, "abilityName", NAPI_AUTO_LENGTH, &abilityName);
    napi_value windowId = nullptr;
    napi_create_string_utf8(env, "windowId", NAPI_AUTO_LENGTH, &windowId);
    napi_value screenMode = nullptr;
    napi_create_string_utf8(env, "screenMode", NAPI_AUTO_LENGTH, &screenMode);

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("VerticalType", verticalType),
        DECLARE_NAPI_PROPERTY("SOURCE_APP_BUNDLE_NAME", bundleName),
        DECLARE_NAPI_PROPERTY("SOURCE_APP_MODULE_NAME", moduleNameProp),
        DECLARE_NAPI_PROPERTY("SOURCE_APP_ABILITY_NAME", abilityName),
        DECLARE_NAPI_PROPERTY("SOURCE_APP_WINDOW_ID", windowId),
        DECLARE_NAPI_PROPERTY("SOURCE_APP_SCREEN_MODE", screenMode),
    };
    napi_define_properties(env, exportObj, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);

    auto jsAbilityVerticalPanel = std::make_unique<JsAbilityVerticalPanel>();
    napi_wrap(env, exportObj, jsAbilityVerticalPanel.release(),
        JsAbilityVerticalPanel::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsAbilityVerticalPanel";
    BindNativeFunction(env, exportObj, "startVerticalPanel", moduleName, JsAbilityVerticalPanel::StartVerticalPanel);
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "end");
    return CreateJsUndefined(env);
}
} // namespace AbilityRuntime
} // namespace OHOS