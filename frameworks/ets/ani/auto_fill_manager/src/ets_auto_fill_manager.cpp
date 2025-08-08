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

#include "ets_auto_fill_manager.h"

#include "ability_business_error.h"
#include "auto_fill_manager.h"
#include "core/common/container_scope.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AutoFillManagerEts {
namespace {
constexpr const char* AUTO_FILL_MANAGER_NAMESPACE = "L@ohos/app/ability/autoFillManager/autoFillManager;";
} // namespace

EtsAutoFillManager &EtsAutoFillManager::GetInstance()
{
    static EtsAutoFillManager instance;
    return instance;
}

void EtsAutoFillManager::RequestAutoSave(ani_env *env, ani_object autoSaveCallbackObj)
{
    GetInstance().OnRequestAutoSave(env, autoSaveCallbackObj);
}

void EtsAutoFillManager::OnRequestAutoSave(ani_env *env, ani_object autoSaveCallbackObj)
{
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "OnRequestAutoSave called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null env");
        return;
    }
    int32_t instanceId = Ace::ContainerScope::CurrentId();
    auto saveCallback = GetCallbackByInstanceId(instanceId);
    if (saveCallback != nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "there are other requests in progress");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    ani_vm *vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "get vm failed");
        AbilityRuntime::EtsErrorUtil::ThrowInvalidParamError(env, "get vm failed.");
        return;
    }
    auto autoSaveMangerFunc = [](const int32_t arg) { EtsAutoFillManager::GetInstance().OnRequestAutoSaveDone(arg); };
    saveCallback = std::make_shared<EtsAutoSaveRequestCallback>(vm, instanceId, autoSaveMangerFunc);
    if (saveCallback == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null saveCallback");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    ani_status status = ANI_OK;
    ani_boolean isCallbackUndefined;
    if ((status = env->Reference_IsUndefined(autoSaveCallbackObj, &isCallbackUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "Falied to check undefinde status: %{public}d", status);
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parameter error. The second parameter is not of type autoSaveCallbackObj.");
        return;
    }
    if (!isCallbackUndefined) {
        saveCallback->Register(autoSaveCallbackObj);
    }
    OnRequestAutoSaveInner(env, instanceId, saveCallback);
}

void EtsAutoFillManager::OnRequestAutoSaveInner(ani_env *env, int32_t instanceId,
    const std::shared_ptr<EtsAutoSaveRequestCallback> &saveRequestCallback)
{
#ifdef SUPPORT_GRAPHICS
    auto uiContent = Ace::UIContent::GetUIContent(instanceId);
    if (uiContent == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null uiContent");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    if (uiContent->CheckNeedAutoSave()) {
        AbilityRuntime::AutoFill::AutoFillRequest request;
        uiContent->DumpViewData(request.viewData, request.autoFillType);
        request.autoFillCommand = AbilityRuntime::AutoFill::AutoFillCommand::SAVE;
        AbilityRuntime::AutoFill::AutoFillResult result;
        auto ret = AbilityRuntime::AutoFillManager::GetInstance().RequestAutoSave(uiContent, request,
            saveRequestCallback, result);
        if (ret != ERR_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILLMGR, "RequestAutoSave error[%{public}d]", ret);
            AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env,
                static_cast<int32_t>(ret)));
            return;
        }
        std::lock_guard<std::mutex> lock(mutexLock_);
        saveRequestObject_.emplace(instanceId, saveRequestCallback);
    }
#endif // SUPPORT_GRAPHICS
}

std::shared_ptr<EtsAutoSaveRequestCallback> EtsAutoFillManager::GetCallbackByInstanceId(int32_t instanceId)
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    auto iter = saveRequestObject_.find(instanceId);
    if (iter != saveRequestObject_.end()) {
        return iter->second.lock();
    }
    return nullptr;
}

void EtsAutoFillManager::OnRequestAutoSaveDone(int32_t instanceId)
{
    std::lock_guard<std::mutex> lock(mutexLock_);
    auto iter = saveRequestObject_.find(instanceId);
    if (iter != saveRequestObject_.end()) {
        saveRequestObject_.erase(iter);
    }
}

void EtsAutoFillManagerInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "EtsAutoFillManagerInit call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null env");
        return;
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "ResetError failed");
    }
    ani_status status = ANI_ERROR;
    ani_namespace ns;
    status = env->FindNamespace(AUTO_FILL_MANAGER_NAMESPACE, &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "FindNamespace autoFillManager failed status : %{public}d", status);
        return;
    }
    std::array kitFunctions = {ani_native_function{
        "requestAutoSaveWithScope",
        "L@ohos/app/ability/autoFillManager/autoFillManager/AutoSaveCallback;:V",
        reinterpret_cast<void *>(EtsAutoFillManager::RequestAutoSave)}};
    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "Namespace_BindNativeFunctions failed status : %{public}d", status);
    }
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "EtsAutoFillManagerInit end");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "in AutoFillManagerEts.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "null vm or result");
        return ANI_INVALID_ARGS;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILLMGR, "GetEnv failed, status=%{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsAutoFillManagerInit(env);
    *result = ANI_VERSION_1;
    TAG_LOGD(AAFwkTag::AUTOFILLMGR, "AutoFillManagerEts.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AutoFillManagerEts
} // namespace OHOS