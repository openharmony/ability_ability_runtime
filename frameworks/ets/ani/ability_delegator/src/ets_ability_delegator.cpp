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

#include "ets_ability_delegator.h"

#include "ability_delegator_registry.h"
#include "ability_stage_monitor.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"
#include "ets_ability_monitor.h"
#include "ets_ability_stage_monitor.h"
#include "hilog_tag_wrapper.h"
#include "shell_cmd_result.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"
#include <mutex>
#include <sstream>
namespace OHOS {
namespace AbilityDelegatorEts {

using namespace OHOS::AbilityRuntime;

std::map<std::shared_ptr<STSNativeReference>, std::shared_ptr<EtsAbilityMonitor>> g_monitorRecord;
std::map<std::shared_ptr<STSNativeReference>, std::shared_ptr<EtsAbilityStageMonitor>> g_stageMonitorRecord;
std::map<std::weak_ptr<STSNativeReference>, sptr<IRemoteObject>, std::owner_less<>> g_abilityRecord;
std::mutex g_mtxMonitorRecord;
std::mutex g_mtxStageMonitorRecord;
std::mutex g_mutexAbilityRecord;

enum ERROR_CODE {
    INCORRECT_PARAMETERS    = 401,
};

#ifdef ENABLE_ERRCODE
constexpr int COMMON_FAILED = 16000100;
#else
constexpr int COMMON_FAILED = -1;
#endif

namespace {
constexpr const char* AREA_MODE_ENUM_NAME = "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;";
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
constexpr const char* SHELL_CMD_RESULT_CLASS_NAME = "Lapplication/shellCmdResult/ShellCmdResultImpl;";
constexpr const char* ABILITY_MONITOR_INNER_CLASS_NAME = "Lapplication/AbilityMonitor/AbilityMonitorInner;";
constexpr const char* ABILITY_STAGE_MONITOR_INNER_CLASS_NAME =
    "Lapplication/AbilityStageMonitor/AbilityStageMonitorInner;";
constexpr const char* ABILITY_STAGE_CLASS_NAME = "L@ohos/app/ability/AbilityStage/AbilityStage;";
}

EtsAbilityDelegator::EtsAbilityDelegator()
{
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        auto clearFunc = [](const std::shared_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &baseProperty) {
            auto property = std::static_pointer_cast<AppExecFwk::ETSDelegatorAbilityProperty>(baseProperty);
            if (!property) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "invalid property type");
                return;
            }

            std::unique_lock<std::mutex> lck(g_mutexAbilityRecord);
            for (auto it = g_abilityRecord.begin(); it != g_abilityRecord.end();) {
                if (it->second == property->token_) {
                    it = g_abilityRecord.erase(it);
                    continue;
                }
                ++it;
            }
        };

        delegator->RegisterClearFunc(clearFunc);
    }
}

EtsAbilityDelegator::~EtsAbilityDelegator() = default;

ani_object EtsAbilityDelegator::CreateEtsBaseContext(ani_env* aniEnv, ani_class contextClass,
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
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(aniEnv,
        AREA_MODE_ENUM_NAME, context->GetArea(), areaModeItem);
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

ani_object EtsAbilityDelegator::WrapShellCmdResult(ani_env* env, std::unique_ptr<AppExecFwk::ShellCmdResult> result)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "WrapShellCmdResult called");
    if (result == nullptr || env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "result or env is null");
        return {};
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass(SHELL_CMD_RESULT_CLASS_NAME, &cls);
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
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindField failed status: %{public}d", status);
    }
    ani_string aniStringVal {};
    std::string strResult = result->GetStdResult();
    status = env->String_NewUTF8(strResult.c_str(), strResult.size(), &aniStringVal);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status: %{public}d", status);
    }
    status = env->Object_SetField_Ref(object, filed, aniStringVal);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "set strResult failed status: %{public}d", status);
    }
    int32_t exitCode = result->GetExitCode();
    status = env->Object_SetPropertyByName_Double(object, "exitCode", exitCode);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "set exitCode failed status: %{public}d", status);
    }
    return object;
}

ani_object EtsAbilityDelegator::GetAppContext(ani_env* env, [[maybe_unused]]ani_object object, ani_class clss)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAppContext call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return {};
    }
    ani_class cls;
    ani_object nullobj = nullptr;
    if (ANI_OK != env->FindClass(CONTEXT_CLASS_NAME, &cls)) {
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
    ani_object objectContext = CreateEtsBaseContext(env, cls, context);
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAppContext end");
    return objectContext;
}

void EtsAbilityDelegator::ExecuteShellCommand(ani_env *env, [[maybe_unused]]ani_object object,
    ani_string cmd, ani_double timeoutSecs, ani_object callback)
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
    ani_object objValue = GetInstance().WrapShellCmdResult(env, std::move(result));
    if (objValue == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null objValue");
        resultCode = COMMON_FAILED;
        ani_class cls = nullptr;
        ani_status status = env->FindClass(SHELL_CMD_RESULT_CLASS_NAME, &cls);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegator failed status: %{public}d", status);
        }
        ani_method method = nullptr;
        status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status: %{public}d", status);
        }
        if (env->Object_New(cls, method, &objValue) != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status: %{public}d", status);
        }
    }
    ani_ref callbackRef = nullptr;
    ani_status createStatus = env->GlobalReference_Create(callback, &callbackRef);
    if (createStatus != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", createStatus);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        objValue);
    return;
}

void EtsAbilityDelegator::FinishTest(ani_env* env, [[maybe_unused]]ani_object object,
    ani_string msg, ani_double code, ani_object callback)
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
        TAG_LOGE(AAFwkTag::DELEGATOR, "FinishTest delegator is null");
        resultCode = COMMON_FAILED;
    } else {
        delegator->FinishUserTest(stdMsg, static_cast<int64_t>(code));
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
    TAG_LOGD(AAFwkTag::DELEGATOR, "FinishTest END");
    return;
}

void EtsAbilityDelegator::PrintSync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_string msg)
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

void EtsAbilityDelegator::RetrieveStringFromAni(ani_env *env, ani_string str, std::string &res)
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

void EtsAbilityDelegator::AddAbilityMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!GetInstance().ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse param monitor failed, monitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->AddAbilityMonitor(monitorImpl);
    }
    ani_ref callbackRef = nullptr;
    ani_status status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Create Gloabl ref for delegator failed %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::AddAbilityMonitorSync(ani_env* env, [[maybe_unused]]ani_class aniClass, ani_object monitorObj)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "AddAbilityMonitorSync");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!GetInstance().ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse param monitor failed, monitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        delegator->AddAbilityMonitor(monitorImpl);
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, COMMON_FAILED, "Calling AddAbilityMonitorSync failed.");
    }
    return;
}

void EtsAbilityDelegator::StartAbility(ani_env* env, [[maybe_unused]]ani_object object,
    ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "StartAbility");
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

ani_ref EtsAbilityDelegator::GetCurrentTopAbility(ani_env* env)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    ani_object objValue = nullptr;
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator != nullptr) {
        auto property = delegator->GetCurrentTopAbility();
        auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::ETSDelegatorAbilityProperty>(property);
        if (!etsbaseProperty || etsbaseProperty->object_.expired()) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "invalid property");
            return {};
        }
        std::unique_lock<std::mutex> lck(g_mutexAbilityRecord);
        g_abilityRecord.emplace(etsbaseProperty->object_, etsbaseProperty->token_);
        return etsbaseProperty->object_.lock()->aniRef;
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
        return {};
    }
    return objValue;
}

void EtsAbilityDelegator::RemoveAbilityMonitor(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "RemoveAbilityMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!GetInstance().ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->RemoveAbilityMonitor(monitorImpl);
        std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
        for (auto iter = g_monitorRecord.begin(); iter != g_monitorRecord.end(); ++iter) {
            std::shared_ptr<STSNativeReference> etsMonitor = iter->first;
            ani_boolean result = false;
            ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(monitorObj),
            reinterpret_cast<ani_ref>(etsMonitor->aniObj), &result);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "Reference_StrictEquals failed status: %{public}d", status);
            }
            if (result) {
                g_monitorRecord.erase(iter);
                break;
            }
        }
    }
    ani_ref callbackRef = nullptr;
    auto status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed: %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::RemoveAbilityMonitorSync(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "RemoveAbilityMonitorSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!GetInstance().ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse monitor failed, RemoveAbilityMonitorSync must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, COMMON_FAILED, "Calling RemoveAbilityMonitorSync failed.");
        return;
    }
    delegator->RemoveAbilityMonitor(monitorImpl);
    {
        std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
        for (auto iter = g_monitorRecord.begin(); iter != g_monitorRecord.end(); ++iter) {
            std::shared_ptr<STSNativeReference> etsMonitor = iter->first;
            ani_boolean result = false;
            ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(monitorObj),
            reinterpret_cast<ani_ref>(etsMonitor->aniObj), &result);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "Reference_StrictEquals failed status: %{public}d", status);
            }
            if (result) {
                g_monitorRecord.erase(iter);
                break;
            }
        }
    }
    return;
}

void EtsAbilityDelegator::WaitAbilityMonitor(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj, ani_double timeout, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "WaitAbilityMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!GetInstance().ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse monitor want failed, WaitAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    std::shared_ptr<BaseDelegatorAbilityProperty> property = (static_cast<int64_t>(timeout) > 0) ?
            delegator->WaitAbilityMonitor(monitorImpl, static_cast<int64_t>(timeout)) :
            delegator->WaitAbilityMonitor(monitorImpl);
    int resultCode = 0;
    ani_object resultAniOj = nullptr;
    auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::ETSDelegatorAbilityProperty>(property);
    if (!etsbaseProperty || etsbaseProperty->object_.expired()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid etsbaseProperty");
        resultCode = COMMON_FAILED;
    } else {
        std::unique_lock<std::mutex> lck(g_mutexAbilityRecord);
        g_abilityRecord.emplace(etsbaseProperty->object_, etsbaseProperty->token_);
        resultAniOj = etsbaseProperty->object_.lock()->aniObj;
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
        resultAniOj);
    return;
}

void EtsAbilityDelegator::AddAbilityStageMonitor(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "AddAbilityStageMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!GetInstance().ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse parameters failed, monitor must be Monitor and isExited must be boolean.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->AddAbilityStageMonitor(stageMonitor);
        if (!isExisted) {
            GetInstance().AddStageMonitorRecord(env, stageMonitorObj, stageMonitor);
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
    }
    return;
}

void EtsAbilityDelegator::AddAbilityStageMonitorSync(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "AddAbilityStageMonitorSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!GetInstance().ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse parameters failed, monitor must be Monitor and isExited must be boolean.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        delegator->AddAbilityStageMonitor(stageMonitor);
        if (!isExisted) {
        GetInstance().AddStageMonitorRecord(env, stageMonitorObj, stageMonitor);
    }
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, COMMON_FAILED, "Calling AddAbilityStageMonitorSync failed.");
    }
    return;
}

void EtsAbilityDelegator::RemoveAbilityStageMonitor(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "RemoveAbilityStageMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!GetInstance().ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->RemoveAbilityStageMonitor(stageMonitor);
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
    if (isExisted) {
        GetInstance().RemoveStageMonitorRecord(env, stageMonitorObj);
    }
    return;
}

void EtsAbilityDelegator::RemoveAbilityStageMonitorSync(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "RemoveAbilityStageMonitorSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!GetInstance().ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        delegator->RemoveAbilityStageMonitor(stageMonitor);
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, COMMON_FAILED, "Calling RemoveAbilityStageMonitorSync failed.");
    }

    if (isExisted) {
        GetInstance().RemoveStageMonitorRecord(env, stageMonitorObj);
    }
    return;
}

void EtsAbilityDelegator::WaitAbilityStageMonitor(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj, ani_double timeout, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "WaitAbilityStageMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!GetInstance().ParseWaitAbilityStageMonitorPara(env, stageMonitorObj, stageMonitor)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    std::shared_ptr<BaseDelegatorAbilityStageProperty> result;
    result = (static_cast<int64_t>(timeout) > 0) ?
            delegator->WaitAbilityStageMonitor(stageMonitor, static_cast<int64_t>(timeout)) :
            delegator->WaitAbilityStageMonitor(stageMonitor);
    int resultCode = 0;
    ani_object resultAniOj = nullptr;
    auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::ETSDelegatorAbilityStageProperty>(result);
    if (GetInstance().CheckPropertyValue(env, resultCode, resultAniOj, etsbaseProperty)) {
        resultAniOj = etsbaseProperty->object_.lock()->aniObj;
    }
    ani_ref callbackRef = nullptr;
    ani_status createStatus = env->GlobalReference_Create(callback, &callbackRef);
    if (createStatus != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", createStatus);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        resultAniOj);
    return;
}

void EtsAbilityDelegator::DoAbilityForeground(ani_env* env, [[maybe_unused]]ani_object object,
    ani_object abilityObj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "DoAbilityForeground called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    if (!GetInstance().ParseAbilityCommonPara(env, abilityObj, remoteObject)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse remoteObject failed, remoteObject must be RemoteObject.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        if (!delegator->DoAbilityForeground(remoteObject)) {
            resultCode = COMMON_FAILED;
        }
    }
    ani_ref callbackRef = nullptr;
    ani_status createStatus = env->GlobalReference_Create(callback, &callbackRef);
    if (createStatus != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", createStatus);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::DoAbilityBackground(ani_env* env, [[maybe_unused]]ani_object object,
    ani_object abilityObj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "DoAbilityBackground called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    if (!GetInstance().ParseAbilityCommonPara(env, abilityObj, remoteObject)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse remoteObject failed, remoteObject must be RemoteObject.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        if (!delegator->DoAbilityBackground(remoteObject)) {
            resultCode = COMMON_FAILED;
        }
    }
    ani_ref callbackRef = nullptr;
    ani_status createStatus = env->GlobalReference_Create(callback, &callbackRef);
    if (createStatus != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", createStatus);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::Print(ani_env* env, [[maybe_unused]]ani_object object,
    ani_string msg, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "Print called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::string strMsg = "";
    if (!OHOS::AppExecFwk::GetStdString(env, msg, strMsg)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GetStdString Failed");
        AbilityRuntime::ThrowStsError(env, INCORRECT_PARAMETERS,
            "Parse msg failed, msg must be string.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int resultCode = 0;
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->Print(strMsg);
    }
    ani_ref callbackRef = nullptr;
    ani_status createStatus = env->GlobalReference_Create(callback, &callbackRef);
    if (createStatus != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", createStatus);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

ani_double EtsAbilityDelegator::GetAbilityState(ani_env* env, [[maybe_unused]]ani_object object, ani_object abilityObj)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAbilityState called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return COMMON_FAILED;
    }
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    if (!GetInstance().ParseAbilityCommonPara(env, abilityObj, remoteObject)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        return COMMON_FAILED;
    }

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return  COMMON_FAILED;
    }
    AbilityDelegator::AbilityState lifeState = delegator->GetAbilityState(remoteObject);
    AbilityLifecycleState abilityLifeState = AbilityLifecycleState::UNINITIALIZED;
    GetInstance().AbilityLifecycleStateToEts(lifeState, abilityLifeState);
    int  res = static_cast<int>(abilityLifeState);
    return res;
}

void EtsAbilityDelegator::AbilityLifecycleStateToEts(
    const AbilityDelegator::AbilityState &lifeState, AbilityLifecycleState &abilityLifeState)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "lifeState: %{public}d", static_cast<int32_t>(lifeState));
    switch (lifeState) {
        case AbilityDelegator::AbilityState::STARTED:
            abilityLifeState = AbilityLifecycleState::CREATE;
            break;
        case AbilityDelegator::AbilityState::FOREGROUND:
            abilityLifeState = AbilityLifecycleState::FOREGROUND;
            break;
        case AbilityDelegator::AbilityState::BACKGROUND:
            abilityLifeState = AbilityLifecycleState::BACKGROUND;
            break;
        case AbilityDelegator::AbilityState::STOPPED:
            abilityLifeState = AbilityLifecycleState::DESTROY;
            break;
        default:
            abilityLifeState = AbilityLifecycleState::UNINITIALIZED;
            break;
    }
}

bool EtsAbilityDelegator::ParseMonitorPara(ani_env *env, ani_object monitorObj,
    std::shared_ptr<EtsAbilityMonitor> &monitorImpl)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "monitorRecord size: %{public}zu", g_monitorRecord.size());
    if (env == nullptr || monitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or monitorObj is nullptr");
        return false;
    }
    {
        std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
        for (auto iter = g_monitorRecord.begin(); iter != g_monitorRecord.end(); ++iter) {
            std::shared_ptr<STSNativeReference> etsMonitor = iter->first;
            ani_boolean result = false;
            ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(monitorObj),
                reinterpret_cast<ani_ref>(etsMonitor->aniObj), &result);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "Reference_StrictEquals failed status: %{public}d", status);
            }
            if (result) {
                monitorImpl = iter->second;
                return monitorImpl ? true : false;
            }
        }
    }
    if (!ParseMonitorParaInner(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorParaInner failed");
        return false;
    }
    return true;
}

bool EtsAbilityDelegator::ParseMonitorParaInner(ani_env *env, ani_object monitorObj,
    std::shared_ptr<EtsAbilityMonitor> &monitorImpl)
{
    if (env == nullptr || monitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or monitorObj is nullptr");
        return false;
    }
    ani_class monitorCls;
    ani_status status = env->FindClass(ABILITY_MONITOR_INNER_CLASS_NAME, &monitorCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status: %{public}d", status);
        return false;
    }
    ani_ref moduleNameRef;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "moduleName", &moduleNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strModuleName;
    ani_string aniModuleString = static_cast<ani_string>(moduleNameRef);
    GetInstance().RetrieveStringFromAni(env, aniModuleString, strModuleName);
    ani_ref abilityNameRef;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "abilityName", &abilityNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strAbilityName;
    ani_string aniAbilityName = static_cast<ani_string>(abilityNameRef);
    GetInstance().RetrieveStringFromAni(env, aniAbilityName, strAbilityName);

    std::shared_ptr<EtsAbilityMonitor> abilityMonitor = nullptr;
    if (strModuleName.empty()) {
        abilityMonitor = std::make_shared<EtsAbilityMonitor>(strAbilityName);
        abilityMonitor->SetEtsAbilityMonitor(env, monitorObj);
    } else {
        abilityMonitor = std::make_shared<EtsAbilityMonitor>(strAbilityName, strModuleName);
        abilityMonitor->SetEtsAbilityMonitor(env, monitorObj);
    }
    monitorImpl = abilityMonitor;
    std::shared_ptr<STSNativeReference> reference = std::make_shared<STSNativeReference>();
    if (reference != nullptr) {
        reference->aniObj = monitorObj;
    }
    std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
    g_monitorRecord.emplace(reference, monitorImpl);
    return true;
}

bool EtsAbilityDelegator::ParseStageMonitorPara(ani_env *env, ani_object stageMonitorObj,
    std::shared_ptr<EtsAbilityStageMonitor> &stageMonitor, bool &isExisted)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "stageMonitorRecord size: %{public}zu", g_stageMonitorRecord.size());
    if (env == nullptr || stageMonitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or stageMonitorObj is nullptr");
        return false;
    }
    isExisted = false;
    {
        std::unique_lock<std::mutex> lck(g_mtxStageMonitorRecord);
        for (auto iter = g_stageMonitorRecord.begin(); iter != g_stageMonitorRecord.end(); ++iter) {
            std::shared_ptr<STSNativeReference> etsMonitor = iter->first;
            ani_boolean result = false;
            if (etsMonitor == nullptr) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "etsMonitor is nullptr");
            }
            if (env == nullptr) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "env  is nullptr");
            }
            ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(stageMonitorObj),
                reinterpret_cast<ani_ref>(etsMonitor->aniObj), &result);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "Reference_StrictEquals failed status: %{public}d", status);
            }
            if (result) {
                TAG_LOGW(AAFwkTag::DELEGATOR, "abilityStage monitor exist");
                isExisted = true;
                stageMonitor = iter->second;
                return stageMonitor ? true : false;
            }
        }
    }
    if (!ParseStageMonitorParaInner(env, stageMonitorObj, stageMonitor)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseStageMonitorParaInner failed");
        return false;
    }
    return true;
}

bool EtsAbilityDelegator::ParseStageMonitorParaInner(ani_env *env, ani_object stageMonitorObj,
    std::shared_ptr<EtsAbilityStageMonitor> &stageMonitor)
{
    if (env == nullptr || stageMonitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or stageMonitorObj is nullptr");
        return false;
    }
    ani_class monitorCls;
    ani_status status = env->FindClass(ABILITY_STAGE_MONITOR_INNER_CLASS_NAME, &monitorCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status: %{public}d", status);
        return false;
    }
    ani_ref moduleNameRef;
    status = env->Object_GetPropertyByName_Ref(stageMonitorObj, "moduleName", &moduleNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref failed status: %{public}d", status);
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strModuleName;
    ani_string aniModuleString = static_cast<ani_string>(moduleNameRef);
    GetInstance().RetrieveStringFromAni(env, aniModuleString, strModuleName);
    TAG_LOGD(AAFwkTag::DELEGATOR, "strModuleName %{public}s ", strModuleName.c_str());
    ani_ref srcEntranceRef;
    status = env->Object_GetPropertyByName_Ref(stageMonitorObj, "srcEntrance", &srcEntranceRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string srcEntrance;
    ani_string aniSrcEntranceRef = static_cast<ani_string>(srcEntranceRef);
    GetInstance().RetrieveStringFromAni(env, aniSrcEntranceRef, srcEntrance);
    TAG_LOGD(AAFwkTag::DELEGATOR, "srcEntrance %{public}s ", srcEntrance.c_str());
    stageMonitor = std::make_shared<EtsAbilityStageMonitor>(strModuleName, srcEntrance);
    return true;
}

void EtsAbilityDelegator::AddStageMonitorRecord(ani_env *env, ani_object stageMonitorObj,
    const std::shared_ptr<EtsAbilityStageMonitor> &stageMonitor)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "AddStageMonitorRecord called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    if (!AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }
    std::shared_ptr<STSNativeReference> reference = nullptr;
    ani_ref objRef = nullptr;
    ani_status status = env->GlobalReference_Create(stageMonitorObj, &objRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GlobalReference_Create failed status:  %{public}d", status);
        return;
    }
    reference.reset(reinterpret_cast<STSNativeReference*>(objRef));
    {
        std::unique_lock<std::mutex> lck(g_mtxStageMonitorRecord);
        if (reference == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "null reference");
        }
        if (stageMonitor == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "null reference");
        }
        TAG_LOGE(AAFwkTag::DELEGATOR, "Add g_stageMonitorRecord test");
        g_stageMonitorRecord.emplace(reference, stageMonitor);
    }
    TAG_LOGI(AAFwkTag::DELEGATOR, "end, size: %{public}zu", g_stageMonitorRecord.size());
}

void EtsAbilityDelegator::RemoveStageMonitorRecord(ani_env *env, ani_object stageMonitorObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    if (!AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }
    std::unique_lock<std::mutex> lck(g_mtxStageMonitorRecord);
    for (auto iter = g_stageMonitorRecord.begin(); iter != g_stageMonitorRecord.end(); ++iter) {
        std::shared_ptr<STSNativeReference> etsMonitor = iter->first;
        ani_boolean result = false;
        ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(stageMonitorObj),
        reinterpret_cast<ani_ref>(etsMonitor->aniObj), &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Reference_StrictEquals failed status: %{public}d", status);
        }
        if (result) {
            g_stageMonitorRecord.erase(iter);
            TAG_LOGI(AAFwkTag::DELEGATOR, "end, size: %{public}zu", g_stageMonitorRecord.size());
            break;
        }
    }
}

bool EtsAbilityDelegator::ParseWaitAbilityStageMonitorPara(ani_env *env, ani_object stageMonitorObj,
    std::shared_ptr<EtsAbilityStageMonitor> &stageMonitor)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ParseWaitAbilityStageMonitorPara called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return false;
    }
    bool isExisted = false;
    if (!ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        return false;
    }
    if (!isExisted) {
        AddStageMonitorRecord(env, stageMonitorObj, stageMonitor);
    }
    return true;
}

bool EtsAbilityDelegator::ParseAbilityCommonPara(ani_env *env, ani_object abilityObj,
    sptr<OHOS::IRemoteObject> &remoteObject)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "g_abilityRecord size: %{public}zu", g_abilityRecord.size());
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return false;
    }
    std::unique_lock<std::mutex> lck(g_mutexAbilityRecord);
    for (auto iter = g_abilityRecord.begin(); iter != g_abilityRecord.end();) {
        if (iter->first.expired()) {
            iter = g_abilityRecord.erase(iter);
            continue;
        }
        ani_boolean result = false;
        ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(iter->first.lock()->aniObj),
        reinterpret_cast<ani_ref>(abilityObj), &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Reference_StrictEquals failed status: %{public}d", status);
        }
        if (result) {
            remoteObject = iter->second;
            TAG_LOGI(AAFwkTag::DELEGATOR, "ability exist");
            return remoteObject ? true : false;
        }
        ++iter;
    }
    TAG_LOGE(AAFwkTag::DELEGATOR, "ability not exist");
    remoteObject = nullptr;
    return false;
}

bool EtsAbilityDelegator::CheckPropertyValue(ani_env *env, int &resultCode, ani_object &resultAniOj,
    std::shared_ptr<AppExecFwk::ETSDelegatorAbilityStageProperty> etsProperty)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return false;
    }
    if (!etsProperty || etsProperty->object_.expired()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "waitAbilityStageMonitor failed");
        resultCode = COMMON_FAILED;
        ani_class cls = nullptr;
        ani_status status = env->FindClass(ABILITY_STAGE_CLASS_NAME, &cls);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegator failed status: %{public}d", status);
        }
        ani_method method = nullptr;
        status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status: %{public}d", status);
        }
        if (env->Object_New(cls, method, &resultAniOj) != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status: %{public}d", status);
        }
        return false;
    }
    return  true;
}
} // namespace AbilityDelegatorEts
} // namespace OHOS
