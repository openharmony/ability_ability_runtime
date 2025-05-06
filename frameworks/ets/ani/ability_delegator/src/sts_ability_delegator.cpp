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

#include "sts_ability_delegator.h"
#include "ability_delegator_registry.h"

#include <mutex>
#include "hilog_tag_wrapper.h"
#include "shell_cmd_result.h"
#include "ani_common_want.h"
#include "sts_error_utils.h"
#include "ani_enum_convert.h"
#include "sts_ability_monitor.h"
#include "sts_context_utils.h"
#include <sstream>
namespace OHOS {
namespace AbilityDelegatorSts {

using namespace OHOS::AbilityRuntime;

#ifdef ENABLE_ERRCODE
constexpr int COMMON_FAILED = 16000100;
#else
constexpr int COMMON_FAILED = -1;
#endif
ani_object CreateStsBaseContext(ani_env* aniEnv, ani_class contextClass,
    std::shared_ptr<AbilityRuntime::Context> context)
{
    if (aniEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv or context");
        return {};
    }
    ani_object contextObj = nullptr;
    ani_method method = nullptr;
    ani_status status = aniEnv->Class_FindMethod(contextClass, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status: %{public}d", status);
        return {};
    }
    if ((status = aniEnv->Object_New(contextClass, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status: %{public}d", status);
        return {};
    }
    ani_field areaField;
    if (aniEnv->Class_FindField(contextClass, "area", &areaField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find area failed");
        return {};
    }
    ani_enum_item areaModeItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(
        aniEnv, "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;", context->GetArea(), areaModeItem);
    if (aniEnv->Object_SetField_Ref(contextObj, areaField, (ani_ref)areaModeItem) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_SetField_Int failed");
        return {};
    }
    ani_field filesDirField;
    if (aniEnv->Class_FindField(contextClass, "filesDir", &filesDirField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find filesDir failed");
        return {};
    }
    auto filesDir = context->GetFilesDir();
    ani_string filesDir_string{};
    aniEnv->String_NewUTF8(filesDir.c_str(), filesDir.size(), &filesDir_string);
    if (aniEnv->Object_SetField_Ref(contextObj, filesDirField, reinterpret_cast<ani_ref>(filesDir_string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_SetField_Ref failed");
        return {};
    }
    ani_field tempDirField;
    if (aniEnv->Class_FindField(contextClass, "tempDir", &tempDirField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find find tempDir failed");
        return {};
    }
    auto tempDir = context->GetTempDir();
    ani_string tempDir_string{};
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDir_string);
    if (aniEnv->Object_SetField_Ref(contextObj, tempDirField, reinterpret_cast<ani_ref>(tempDir_string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_SetField_Ref failed");
        return {};
    }
    ContextUtil::BindApplicationInfo(aniEnv, contextClass, contextObj, context);
    ContextUtil::BindResourceManager(aniEnv, contextClass, contextObj, context);
    return contextObj;
}

ani_object GetAppContext(ani_env* env, [[maybe_unused]]ani_object object, ani_class clss)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAppContext call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return {};
    }
    ani_class cls;
    ani_object nullobj = nullptr;
    if (ANI_OK != env->FindClass("Lapplication/Context/Context;", &cls)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass Context Failed");
        return nullobj;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return nullobj;
    }
    std::shared_ptr<AbilityRuntime::Context> context = delegator->GetAppContext();
    if (!context) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null context");
        return nullobj;
    }
    ani_object objectContext = CreateStsBaseContext(env, cls, context);
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAppContext end");
    return objectContext;
}


ani_object wrapShellCmdResult(ani_env* env, std::unique_ptr<AppExecFwk::ShellCmdResult> result)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "wrapShellCmdResult called");
    if (result == nullptr || env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "result or env is null");
        return {};
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass("Lapplication/shellCmdResult/ShellCmdResultImpl;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegator failed status: %{public}d", status);
        return {};
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status: %{public}d", status);
        return {};
    }
    ani_object object = nullptr;
    if (env->Object_New(cls, method, &object) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status: %{public}d", status);
        return {};
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Object_New success");
    ani_field filed;
    status = env->Class_FindField(cls, "stdResult", &filed);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindField configObj failed");
    }
    ani_string aniStringVal {};
    std::string strResult = result->GetStdResult();
    status = env->String_NewUTF8(strResult.c_str(), strResult.size(), &aniStringVal);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 mcc failed");
    }
    if (env->Object_SetField_Ref(object, filed, aniStringVal) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_SetField_Ref mcc failed");
    }
    int32_t exitCode = result->GetExitCode();
    status = env->Class_FindField(cls, "exitCode", &filed);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindField configObj failed");
    }
    status = env->Object_SetField_Int(object, filed, exitCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_SetField_Int exitCode failed");
    }
    return object;
}

void ExecuteShellCommand(ani_env *env, [[maybe_unused]]ani_object object, ani_string cmd, ani_double timeoutSecs,
    ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "ExecuteShellCommand called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return;
    }
    std::string stdCmd = "";
    if (!OHOS::AppExecFwk::GetStdString(env, cmd, stdCmd)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GetStdString Failed");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    int resultCode = 0;
    auto result = delegator->ExecuteShellCommand(stdCmd, static_cast<int64_t>(timeoutSecs));
    if (!result) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ExecuteShellCommand result is null");
        resultCode = COMMON_FAILED;
    }
    ani_object objValue = wrapShellCmdResult(env, std::move(result));
    if (objValue == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null objValue");
        resultCode = COMMON_FAILED;
    }
    ani_ref callbackRef = nullptr;
    auto status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        objValue);
    return;
}

void FinishTestSync(ani_env* env, [[maybe_unused]]ani_object object, ani_string msg, ani_double code,
    ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return;
    }
    std::string stdMsg = "";
    if (!OHOS::AppExecFwk::GetStdString(env, msg, stdMsg)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GetStdString Failed");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    int resultCode = 0;
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "finishTestSync delegator is null");
        resultCode = COMMON_FAILED;
    }
    delegator->FinishUserTest(stdMsg, static_cast<int64_t>(code));
    ani_ref callbackRef = nullptr;
    auto status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    TAG_LOGD(AAFwkTag::DELEGATOR, "finishTestSync END");
    return;
}

void PrintSync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_string msg)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "PrintSync");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::string msgStr;
    ani_size sz {};
    env->String_GetUTF8Size(msg, &sz);
    msgStr.resize(sz + 1);
    env->String_GetUTF8SubString(msg, 0, sz, msgStr.data(), msgStr.size(), &sz);
    TAG_LOGD(AAFwkTag::DELEGATOR, "PrintSync %{public}s", msgStr.c_str());

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }

    delegator->Print(msgStr);
    return;
}

void RetrieveStringFromAni(ani_env *env, ani_string str, std::string &res)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "status: %{public}d", status);
        return;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "status: %{public}d", status);
        return;
    }
    res.resize(sz);
}

void AddAbilityMonitorASync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_object monitorObj,
    ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    ani_class monitorCls;
    ani_status status = env->FindClass("Lapplication/AbilityMonitor/AbilityMonitorInner;", &monitorCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status: %{public}d", status);
        return;
    }
    ani_ref moduleNameRef;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "moduleName", &moduleNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    std::string strModuleName;
    ani_string aniModuleString = static_cast<ani_string>(moduleNameRef);
    RetrieveStringFromAni(env, aniModuleString, strModuleName);
    ani_ref abilityNameRef;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "abilityName", &abilityNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    std::string strAbilityName;
    ani_string aniAbilityName = static_cast<ani_string>(abilityNameRef);
    RetrieveStringFromAni(env, aniAbilityName, strAbilityName);
    TAG_LOGD(AAFwkTag::DELEGATOR, "abilityName %{public}s ", strAbilityName.c_str());
    std::shared_ptr<STSAbilityMonitor> monitor = std::make_shared<STSAbilityMonitor>(strAbilityName);
    if (monitor == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null monitor");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    monitor->SetSTSAbilityMonitor(env, monitorObj);
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    }
    ani_ref callbackRef = nullptr;
    status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Create Gloabl ref for delegator failed %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    delegator->AddAbilityMonitor(monitor);
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void StartAbility(ani_env* env, [[maybe_unused]]ani_object object, ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "null env");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "UnwrapWant  failed");
        AbilityRuntime::ThrowStsError(env, (int32_t)AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM,
            "Parse want failed, want must be Want.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, COMMON_FAILED);
        return;
    }
    int resultCode = 0;
    int result = delegator->StartAbility(want);
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "start ability failed: %{public}d", result);
        resultCode = result;
    }
    ani_ref callbackRef = nullptr;
    auto status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

ani_ref GetCurrentTopAbilitySync(ani_env* env)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    ani_object objValue = nullptr;
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator != nullptr) {
        auto property = delegator->GetCurrentTopAbility();
        if (!property || property->stsObject_.expired()) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "invalid property");
            return {};
        }
        return property->stsObject_.lock()->aniRef;
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
        return {};
    }
    return objValue;
}
} // namespace AbilityDelegatorSts
} // namespace OHOS
