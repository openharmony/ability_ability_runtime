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

#include <mutex>
#include <sstream>
#include "ability_delegator_registry.h"
#include "ability_stage_monitor.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"
#include "ets_ability_monitor.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_native_reference.h"
#include "hilog_tag_wrapper.h"
#include "shell_cmd_result.h"

namespace OHOS {
namespace AbilityDelegatorEts {

using namespace OHOS::AbilityRuntime;

std::map<std::shared_ptr<AppExecFwk::ETSNativeReference>, std::shared_ptr<EtsAbilityMonitor>> g_monitorRecord;
std::map<std::weak_ptr<AppExecFwk::ETSNativeReference>, sptr<IRemoteObject>, std::owner_less<>> g_abilityRecord;
std::mutex g_mtxMonitorRecord;
std::mutex g_mutexAbilityRecord;

#ifdef ENABLE_ERRCODE
constexpr int COMMON_FAILED = 16000100;
#else
constexpr int COMMON_FAILED = -1;
#endif

namespace {
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
constexpr const char* SHELL_CMD_RESULT_CLASS_NAME = "Lapplication/shellCmdResult/ShellCmdResultImpl;";
constexpr const char* ABILITY_MONITOR_INNER_CLASS_NAME = "Lapplication/AbilityMonitor/AbilityMonitorInner;";
}

EtsAbilityDelegator::EtsAbilityDelegator()
{
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        auto clearFunc = [](const std::shared_ptr<AppExecFwk::BaseDelegatorAbilityProperty> &baseProperty) {
            auto property = std::static_pointer_cast<AppExecFwk::EtsDelegatorAbilityProperty>(baseProperty);
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

ani_object EtsAbilityDelegator::SetAppContext(ani_env *env, const std::shared_ptr<AbilityRuntime::Context> &context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env or context");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_object contextObj = nullptr;
    ani_method method = nullptr;
    ani_status status = env->FindClass(CONTEXT_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New status: %{public}d", status);
        return nullptr;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::Context>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null workContext");
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)workContext;
    if ((status = env->Object_SetFieldByName_Long(contextObj, "nativeContext", nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Object_SetFieldByName_Long status: %{public}d", status);
        delete workContext;
        workContext = nullptr;
        return nullptr;
    }
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
    ani_field filed  = nullptr;
    status = env->Class_FindField(cls, "stdResult", &filed);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindField failed status: %{public}d", status);
    }
    ani_string aniStringVal = nullptr;
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
    ani_class cls = nullptr;
    ani_object nullobj = nullptr;
    if (ANI_OK != env->FindClass(CONTEXT_CLASS_NAME, &cls)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass Context Failed");
        return nullobj;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return nullobj;
    }
    std::shared_ptr<AbilityRuntime::Context> context = delegator->GetAppContext();
    if (!context) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null context");
        return nullobj;
    }
    ani_object contextObj = SetAppContext(env, context);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null contextObj");
        return nullobj;
    }
    ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAppContext end");
    return contextObj;
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    OHOS::AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    int resultCode = 0;
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    OHOS::AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
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
    std::string msgStr = "";
    ani_size sz {};
    env->String_GetUTF8Size(msg, &sz);
    msgStr.resize(sz + 1);
    env->String_GetUTF8SubString(msg, 0, sz, msgStr.data(), msgStr.size(), &sz);
    TAG_LOGD(AAFwkTag::DELEGATOR, "PrintSync %{public}s", msgStr.c_str());

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    OHOS::AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse want failed, want must be Want.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, COMMON_FAILED);
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
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    OHOS::AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
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
            std::shared_ptr<AppExecFwk::ETSNativeReference> etsMonitor = iter->first;
            ani_boolean result = ANI_FALSE;
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
    ani_class monitorCls = nullptr;
    ani_status status = env->FindClass(ABILITY_MONITOR_INNER_CLASS_NAME, &monitorCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status: %{public}d", status);
        return false;
    }
    ani_ref moduleNameRef = nullptr;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "moduleName", &moduleNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strModuleName = "";
    ani_string aniModuleString = static_cast<ani_string>(moduleNameRef);
    GetInstance().RetrieveStringFromAni(env, aniModuleString, strModuleName);
    ani_ref abilityNameRef = nullptr;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "abilityName", &abilityNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strAbilityName = "";
    ani_string aniAbilityName = static_cast<ani_string>(abilityNameRef);
    GetInstance().RetrieveStringFromAni(env, aniAbilityName, strAbilityName);

    std::shared_ptr<EtsAbilityMonitor> abilityMonitor = nullptr;
    if (strModuleName.empty()) {
        abilityMonitor = std::make_shared<EtsAbilityMonitor>(strAbilityName);
    } else {
        abilityMonitor = std::make_shared<EtsAbilityMonitor>(strAbilityName, strModuleName);
    }
    abilityMonitor->SetEtsAbilityMonitor(env, monitorObj);
    monitorImpl = abilityMonitor;
    std::shared_ptr<AppExecFwk::ETSNativeReference> reference = std::make_shared<AppExecFwk::ETSNativeReference>();
    if (reference != nullptr) {
        reference->aniObj = monitorObj;
    }
    std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
    g_monitorRecord.emplace(reference, monitorImpl);
    return true;
}

} // namespace AbilityDelegatorEts
} // namespace OHOS
