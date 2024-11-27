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

#include "cj_ability_context_object.h"

#include "accesstoken_kit.h"
#include "cj_ability_context.h"
#include "cj_ability_connect_callback_object.h"
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "hilog_tag_wrapper.h"
#include "napi_common_start_options.h"
#include "napi_common_util.h"
#include "pixel_map.h"
#include "js_ability_context.h"
#include "js_runtime_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int64_t NOT_SUPPORT = 1;
// g_cjAbilityCallbacks is used to save cangjie functions.
// It is assigned by the global variable REGISTER_ABILITY_CONTEXT_CALLBACK on the cangjie side which invokes
// RegisterCJAbilityCallbacks. And it is never released.
CJAbilityCallbacks* g_cjAbilityCallbacks = nullptr;
}

void UnWrapStartOption(CJStartOptions* source, AAFwk::StartOptions& target)
{
    if (source == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null source");
        return;
    }
    target.SetWindowMode(source->windowMode);
    target.SetDisplayID(source->displayId);
}

std::function<void(int32_t, CJAbilityResult*)> WrapCJAbilityResultTask(int64_t lambdaId)
{
    auto cjTask = [lambdaId](int32_t error, CJAbilityResult* abilityResult) {
        if (g_cjAbilityCallbacks == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null g_cjAbilityCallbacks");
            return;
        }
        g_cjAbilityCallbacks->invokeAbilityResultCallback(lambdaId, error, abilityResult);
        TAG_LOGD(AAFwkTag::CONTEXT, "error: %{public}d", error);
    };
    return cjTask;
}

RuntimeTask WrapRuntimeTask(std::function<void(int32_t, CJAbilityResult*)> cjTask, int32_t error)
{
    RuntimeTask task = [cjTask, error](int32_t resultCode, const AAFwk::Want& want, bool isInner) {
        WantHandle wantHandle = const_cast<AAFwk::Want*>(&want);
        CJAbilityResult abilityResult = { resultCode, wantHandle };
        cjTask(error, &abilityResult);
        TAG_LOGD(AAFwkTag::CONTEXT, "error: %{public}d", error);
    };
    return task;
}

extern "C" {
void RegisterCJAbilityCallbacks(void (*registerFunc)(CJAbilityCallbacks*))
{
    if (g_cjAbilityCallbacks != nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null g_cjAbilityCallbacks");
        return;
    }

    if (registerFunc == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null registerFunc");
        return;
    }

    g_cjAbilityCallbacks = new CJAbilityCallbacks();
    registerFunc(g_cjAbilityCallbacks);
}

bool FFIAbilityContextIsAbilityContextExisted(int64_t id)
{
    return FFIData::GetData<CJAbilityContext>(id) != nullptr;
}

int64_t FFIAbilityContextGetSizeOfStartOptions()
{
    return sizeof(CJStartOptions);
}

int64_t FFIAbilityContextGetAbilityInfo(int64_t id)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return INVALID_DATA_ID;
    }
    return NOT_SUPPORT;
}

int64_t FFIAbilityContextGetHapModuleInfo(int64_t id)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return INVALID_DATA_ID;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    return NOT_SUPPORT;
}

int64_t FFIAbilityContextGetConfiguration(int64_t id)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return INVALID_DATA_ID;
    }
    auto configuration = context->GetConfiguration();
    return NOT_SUPPORT;
}

int32_t FFIAbilityContextStartAbility(int64_t id, WantHandle want)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<Want*>(want);
    context->InheritWindowMode(*actualWant);
    return context->StartAbility(*actualWant);
}

int32_t FFIAbilityContextStartAbilityWithOption(int64_t id, WantHandle want, CJStartOptions* startOption)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    context->InheritWindowMode(*actualWant);
    AAFwk::StartOptions option;
    UnWrapStartOption(startOption, option);
    return context->StartAbility(*actualWant, option);
}

int32_t FFIAbilityContextStartAbilityWithAccount(int64_t id, WantHandle want, int32_t accountId)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    context->InheritWindowMode(*actualWant);
    return context->StartAbilityWithAccount(*actualWant, accountId);
}

int32_t FFIAbilityContextStartAbilityWithAccountAndOption(
    int64_t id, WantHandle want, int32_t accountId, CJStartOptions* startOption)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    context->InheritWindowMode(*actualWant);
    AAFwk::StartOptions option;
    UnWrapStartOption(startOption, option);
    return context->StartAbilityWithAccount(*actualWant, accountId, option);
}

int32_t FFIAbilityContextStartServiceExtensionAbility(int64_t id, WantHandle want)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    return context->StartServiceExtensionAbility(*actualWant);
}

int32_t FFIAbilityContextStartServiceExtensionAbilityWithAccount(int64_t id, WantHandle want, int32_t accountId)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    return context->StartServiceExtensionAbilityWithAccount(*actualWant, accountId);
}

int32_t FFIAbilityContextStopServiceExtensionAbility(int64_t id, WantHandle want)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    return context->StopServiceExtensionAbility(*actualWant);
}

int32_t FFIAbilityContextStopServiceExtensionAbilityWithAccount(int64_t id, WantHandle want, int32_t accountId)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    return context->StopServiceExtensionAbilityWithAccount(*actualWant, accountId);
}

int32_t FFIAbilityContextTerminateSelf(int64_t id)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context->TerminateSelf();
}

int32_t FFIAbilityContextTerminateSelfWithResult(int64_t id, WantHandle want, int32_t resultCode)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<Want*>(want);
    return context->TerminateSelfWithResult(*actualWant, resultCode);
}

RetDataBool FFIAbilityContextIsTerminating(int64_t id)
{
    RetDataBool res = { ERR_INVALID_INSTANCE_CODE, false };
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return res;
    }

    auto [code, data] = context->IsTerminating();
    res.code = code;
    res.data = data;
    return res;
}

int32_t FFIAbilityContextConnectAbility(int64_t id, WantHandle want, int64_t connection)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    auto res = context->ConnectAbility(*actualWant, connection);
    return res ? SUCCESS_CODE : ERR_INVALID_INSTANCE_CODE;
}

int32_t FFIAbilityContextConnectAbilityWithAccount(int64_t id, WantHandle want, int32_t accountId, int64_t connection)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    auto res = context->ConnectAbilityWithAccount(*actualWant, accountId, connection);
    return res ? SUCCESS_CODE : ERR_INVALID_INSTANCE_CODE;
}

int32_t FFIAbilityContextDisconnectAbility(int64_t id, WantHandle want, int64_t connection)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    context->ConnectAbility(*actualWant, connection);
    return SUCCESS_CODE;
}

int32_t FFIAbilityContextStartAbilityForResult(int64_t id, WantHandle want, int32_t requestCode, int64_t lambdaId)
{
    auto cjTask = WrapCJAbilityResultTask(lambdaId);
    RuntimeTask task = WrapRuntimeTask(cjTask, SUCCESS_CODE);

    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        cjTask(ERR_INVALID_INSTANCE_CODE, nullptr);
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    context->InheritWindowMode(*actualWant);
    return context->StartAbilityForResult(*actualWant, requestCode, std::move(task));
}

int32_t FFIAbilityContextStartAbilityForResultWithOption(
    int64_t id, WantHandle want, CJStartOptions* startOption, int32_t requestCode, int64_t lambdaId)
{
    auto cjTask = WrapCJAbilityResultTask(lambdaId);
    RuntimeTask task = WrapRuntimeTask(cjTask, SUCCESS_CODE);

    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        cjTask(ERR_INVALID_INSTANCE_CODE, nullptr);
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    context->InheritWindowMode(*actualWant);
    AAFwk::StartOptions option;
    UnWrapStartOption(startOption, option);
    return context->StartAbilityForResult(*actualWant, option, requestCode, std::move(task));
}

int32_t FFIAbilityContextStartAbilityForResultWithAccount(
    int64_t id, WantHandle want, int32_t accountId, int32_t requestCode, int64_t lambdaId)
{
    auto cjTask = WrapCJAbilityResultTask(lambdaId);
    RuntimeTask task = WrapRuntimeTask(cjTask, SUCCESS_CODE);

    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        cjTask(ERR_INVALID_INSTANCE_CODE, nullptr);
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    context->InheritWindowMode(*actualWant);
    return context->StartAbilityForResultWithAccount(*actualWant, accountId, requestCode, std::move(task));
}

int32_t FFIAbilityContextStartAbilityForResultWithAccountAndOption(
    int64_t id, WantHandle want, int32_t accountId, CJStartOptions* startOption, int32_t requestCode, int64_t lambdaId)
{
    auto cjTask = WrapCJAbilityResultTask(lambdaId);
    RuntimeTask task = WrapRuntimeTask(cjTask, SUCCESS_CODE);

    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        cjTask(ERR_INVALID_INSTANCE_CODE, nullptr);
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    context->InheritWindowMode(*actualWant);
    AAFwk::StartOptions option;
    UnWrapStartOption(startOption, option);
    return context->StartAbilityForResultWithAccount(*actualWant, accountId, option, requestCode, std::move(task));
}

int32_t FFIAbilityContextRequestPermissionsFromUser(
    int64_t id, VectorStringHandle permissions, int32_t requestCode, int64_t lambdaId)
{
    auto cjTask = [lambdaId](int32_t error, CJPermissionRequestResult* cjPermissionRequestResult) {
        if (g_cjAbilityCallbacks == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null g_cjAbilityCallbacks");
            return;
        }
        g_cjAbilityCallbacks->invokePermissionRequestResultCallback(lambdaId, error, cjPermissionRequestResult);
        TAG_LOGD(AAFwkTag::CONTEXT, "invoke, error is %{public}d", error);
    };
    PermissionRequestTask task = [cjTask](const std::vector<std::string>& permissions,
                                     const std::vector<int>& grantResults) {
        VectorStringHandle permissionList = const_cast<std::vector<std::string>*>(&permissions);
        VectorInt32Handle result = const_cast<std::vector<int>*>(&grantResults);
        CJPermissionRequestResult cjPermissionRequestResult = { permissionList, result };
        cjTask(SUCCESS_CODE, &cjPermissionRequestResult);
    };

    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        cjTask(ERR_INVALID_INSTANCE_CODE, nullptr);
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualPermissions = reinterpret_cast<std::vector<std::string>*>(permissions);
    if (actualPermissions->empty()) {
        TAG_LOGE(AAFwkTag::CONTEXT, "empty permissions");
        cjTask(ERR_INVALID_INSTANCE_CODE, nullptr);
        return ERR_INVALID_INSTANCE_CODE;
    }
    return true;
}

#ifdef SUPPORT_GRAPHICS
int32_t FFIAbilityContextSetMissionLabel(int64_t id, const char* label)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return context->SetMissionLabel(label);
}

int32_t FFIAbilityContextSetMissionIcon(int64_t id, int64_t pixelMapId)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return 0;
}
#endif

int32_t FFIAbilityContextRequestDialogService(int64_t id, WantHandle want, int64_t lambdaId)
{
    auto context = FFIData::GetData<CJAbilityContext>(id);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    RequestDialogResultTask task = [lambdaId](int32_t resultCode, const AAFwk::Want &resultWant) {
        if (g_cjAbilityCallbacks == nullptr) {
            TAG_LOGE(AAFwkTag::CONTEXT, "null g_cjAbilityCallbacks");
            return;
        }
        CJDialogRequestResult dialogRequestResult = {
            .resultCode = resultCode,
            .wantHandle = (WantHandle)&resultWant
        };
        g_cjAbilityCallbacks->invokeDialogRequestResultCallback(lambdaId, resultCode, &dialogRequestResult);
        TAG_LOGD(AAFwkTag::CONTEXT, "invoke, resultCode is %{public}d", resultCode);
    };
    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    return context->RequestDialogService(*actualWant, std::move(task));
}

#define EXPORT __attribute__((visibility("default")))
EXPORT AbilityContextBroker* FFIAbilityContextGetBroker()
{
    static AbilityContextBroker contextFuncs = {
        .isAbilityContextExisted = FFIAbilityContextIsAbilityContextExisted,
        .getSizeOfStartOptions = FFIAbilityContextGetSizeOfStartOptions,
        .getAbilityInfo = FFIAbilityContextGetAbilityInfo,
        .getHapModuleInfo = FFIAbilityContextGetHapModuleInfo,
        .getConfiguration = FFIAbilityContextGetConfiguration,
        .startAbility = FFIAbilityContextStartAbility,
        .startAbilityWithOption = FFIAbilityContextStartAbilityWithOption,
        .startAbilityWithAccount = FFIAbilityContextStartAbilityWithAccount,
        .startAbilityWithAccountAndOption = FFIAbilityContextStartAbilityWithAccountAndOption,
        .startServiceExtensionAbility = FFIAbilityContextStartServiceExtensionAbility,
        .startServiceExtensionAbilityWithAccount = FFIAbilityContextStartServiceExtensionAbilityWithAccount,
        .stopServiceExtensionAbility = FFIAbilityContextStopServiceExtensionAbility,
        .stopServiceExtensionAbilityWithAccount = FFIAbilityContextStopServiceExtensionAbilityWithAccount,
        .terminateSelf = FFIAbilityContextTerminateSelf,
        .terminateSelfWithResult = FFIAbilityContextTerminateSelfWithResult,
        .isTerminating = FFIAbilityContextIsTerminating,
        .connectAbility = FFIAbilityContextConnectAbility,
        .connectAbilityWithAccount = FFIAbilityContextConnectAbilityWithAccount,
        .disconnectAbility = FFIAbilityContextDisconnectAbility,
        .startAbilityForResult = FFIAbilityContextStartAbilityForResult,
        .startAbilityForResultWithOption = FFIAbilityContextStartAbilityForResultWithOption,
        .startAbilityForResultWithAccount = FFIAbilityContextStartAbilityForResultWithAccount,
        .startAbilityForResultWithAccountAndOption = FFIAbilityContextStartAbilityForResultWithAccountAndOption,
        .requestPermissionsFromUser = FFIAbilityContextRequestPermissionsFromUser,
        .setMissionLabel = FFIAbilityContextSetMissionLabel,
        .setMissionIcon = FFIAbilityContextSetMissionIcon };
    return &contextFuncs;
}

EXPORT void *FFIGetContext(int64_t id)
{
    if (auto cjContext = FFIData::GetData<CJAbilityContext>(id)) {
        return cjContext->GetAbilityContext().get();
    }
    return nullptr;
}

typedef struct napi_env__ *napi_env;
typedef struct napi_value__* napi_value;

void BindJsAbilityContextStartStop(napi_env env, napi_value result)
{
    const char *moduleName = "JsAbilityContext";
    BindNativeFunction((napi_env)env, result, "startAbility", moduleName, JsAbilityContext::StartAbility);
    BindNativeFunction((napi_env)env, result, "openLink", moduleName, JsAbilityContext::OpenLink);
    BindNativeFunction((napi_env)env, result, "startAbilityAsCaller", moduleName,
        JsAbilityContext::StartAbilityAsCaller);
    BindNativeFunction((napi_env)env, result, "startAbilityWithAccount", moduleName,
        JsAbilityContext::StartAbilityWithAccount);
    BindNativeFunction((napi_env)env, result, "startAbilityByCall", moduleName, JsAbilityContext::StartAbilityByCall);
    BindNativeFunction((napi_env)env, result, "startAbilityForResult",
        moduleName, JsAbilityContext::StartAbilityForResult);
    BindNativeFunction((napi_env)env, result, "startAbilityForResultWithAccount", moduleName,
        JsAbilityContext::StartAbilityForResultWithAccount);
    BindNativeFunction((napi_env)env, result, "startServiceExtensionAbility", moduleName,
        JsAbilityContext::StartServiceExtensionAbility);
    BindNativeFunction((napi_env)env, result, "startServiceExtensionAbilityWithAccount", moduleName,
        JsAbilityContext::StartServiceExtensionAbilityWithAccount);
    BindNativeFunction((napi_env)env, result, "stopServiceExtensionAbility", moduleName,
        JsAbilityContext::StopServiceExtensionAbility);
    BindNativeFunction((napi_env)env, result, "stopServiceExtensionAbilityWithAccount", moduleName,
        JsAbilityContext::StopServiceExtensionAbilityWithAccount);
}

void BindJsAbilityContextOther(napi_env env, napi_value result)
{
    const char *moduleName = "JsAbilityContext";
    BindNativeFunction((napi_env)env, result, "connectServiceExtensionAbility", moduleName,
        JsAbilityContext::ConnectAbility);
    BindNativeFunction((napi_env)env, result, "connectAbilityWithAccount", moduleName,
        JsAbilityContext::ConnectAbilityWithAccount);
    BindNativeFunction((napi_env)env, result, "connectServiceExtensionAbilityWithAccount", moduleName,
        JsAbilityContext::ConnectAbilityWithAccount);
    BindNativeFunction((napi_env)env, result, "disconnectAbility", moduleName, JsAbilityContext::DisconnectAbility);
    BindNativeFunction((napi_env)env, result, "disconnectServiceExtensionAbility", moduleName,
        JsAbilityContext::DisconnectAbility);
    BindNativeFunction((napi_env)env, result, "terminateSelf", moduleName, JsAbilityContext::TerminateSelf);
    BindNativeFunction((napi_env)env, result, "terminateSelfWithResult", moduleName,
        JsAbilityContext::TerminateSelfWithResult);
    BindNativeFunction((napi_env)env, result, "backToCallerAbilityWithResult", moduleName,
        JsAbilityContext::BackToCallerAbilityWithResult);
    BindNativeFunction((napi_env)env, result, "restoreWindowStage", moduleName, JsAbilityContext::RestoreWindowStage);
    BindNativeFunction((napi_env)env, result, "isTerminating", moduleName, JsAbilityContext::IsTerminating);
    BindNativeFunction((napi_env)env, result, "startRecentAbility", moduleName,
        JsAbilityContext::StartRecentAbility);
    BindNativeFunction((napi_env)env, result, "requestDialogService", moduleName,
        JsAbilityContext::RequestDialogService);
    BindNativeFunction((napi_env)env, result, "reportDrawnCompleted", moduleName,
        JsAbilityContext::ReportDrawnCompleted);
    BindNativeFunction((napi_env)env, result, "setMissionContinueState", moduleName,
        JsAbilityContext::SetMissionContinueState);
    BindNativeFunction((napi_env)env, result, "startAbilityByType", moduleName,
        JsAbilityContext::StartAbilityByType);
    BindNativeFunction((napi_env)env, result, "requestModalUIExtension", moduleName,
        JsAbilityContext::RequestModalUIExtension);
    BindNativeFunction((napi_env)env, result, "showAbility", moduleName,
        JsAbilityContext::ShowAbility);
    BindNativeFunction((napi_env)env, result, "hideAbility", moduleName,
        JsAbilityContext::HideAbility);
    BindNativeFunction((napi_env)env, result, "openAtomicService", moduleName,
        JsAbilityContext::OpenAtomicService);
    BindNativeFunction((napi_env)env, result, "moveAbilityToBackground", moduleName,
        JsAbilityContext::MoveAbilityToBackground);
    BindNativeFunction((napi_env)env, result, "setRestoreEnabled", moduleName, JsAbilityContext::SetRestoreEnabled);
    BindNativeFunction((napi_env)env, result, "startUIServiceExtensionAbility", moduleName,
        JsAbilityContext::StartUIServiceExtension);
    BindNativeFunction((napi_env)env, result, "connectUIServiceExtensionAbility", moduleName,
        JsAbilityContext::ConnectUIServiceExtension);
    BindNativeFunction((napi_env)env, result, "disconnectUIServiceExtensionAbility", moduleName,
        JsAbilityContext::DisconnectUIServiceExtension);
#ifdef SUPPORT_GRAPHICS
    BindNativeFunction((napi_env)env, result, "setMissionLabel", moduleName, JsAbilityContext::SetMissionLabel);
    BindNativeFunction((napi_env)env, result, "setMissionIcon", moduleName, JsAbilityContext::SetMissionIcon);
#endif
}

EXPORT napi_value FFICreateNapiValue(void *env, void *context)
{
    napi_value result = nullptr;
    napi_create_object((napi_env)env, &result);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null result");
        return nullptr;
    }
    auto nativeFinalize = [](napi_env env, void* data, void* hint) {
        auto tmp = reinterpret_cast<std::weak_ptr<Context> *>(data);
        delete tmp;
    };
    auto tmpContext = reinterpret_cast<AbilityContext*>(context);
    auto weakContext = new std::weak_ptr<Context>(tmpContext->weak_from_this());
    napi_wrap((napi_env)env, result, weakContext, nativeFinalize, nullptr, nullptr);
    napi_value value = nullptr;
    napi_get_boolean((napi_env)env, true, &value);
    napi_set_named_property((napi_env)env, result, "stageMode", value);

    return result;
}

EXPORT napi_value FFICreateNapiValueJsAbilityContext(void *env, void *context)
{
    napi_value result = FFICreateNapiValue(env, context);
    BindJsAbilityContextStartStop((napi_env)env, result);
    BindJsAbilityContextOther((napi_env)env, result);
    return result;
}

#undef EXPORT
}
} // namespace AbilityRuntime
} // namespace OHOS
