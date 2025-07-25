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

std::map<std::weak_ptr<ETSNativeReference>,
    std::shared_ptr<EtsAbilityMonitor>,
    std::owner_less<std::weak_ptr<ETSNativeReference>>> g_monitorRecord;
std::map<std::weak_ptr<ETSNativeReference>,
    std::shared_ptr<EtsAbilityStageMonitor>,
    std::owner_less<std::weak_ptr<ETSNativeReference>>> g_stageMonitorRecord;
std::map<std::weak_ptr<ETSNativeReference>, sptr<IRemoteObject>, std::owner_less<>> g_abilityRecord;
std::mutex g_mtxMonitorRecord;
std::mutex g_mtxStageMonitorRecord;
std::mutex g_mutexAbilityRecord;

namespace {
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
constexpr const char* SHELL_CMD_RESULT_CLASS_NAME = "Lapplication/shellCmdResult/ShellCmdResultImpl;";
constexpr const char* ABILITY_MONITOR_INNER_CLASS_NAME = "Lapplication/AbilityMonitor/AbilityMonitorInner;";
constexpr const char* ABILITY_STAGE_MONITOR_INNER_CLASS_NAME =
    "Lapplication/AbilityStageMonitor/AbilityStageMonitorInner;";
constexpr const char* ABILITY_STAGE_CLASS_NAME = "L@ohos/app/ability/AbilityStage/AbilityStage;";
constexpr int COMMON_FAILED = 16000100;
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
    ani_long nativeContextLong = reinterpret_cast<ani_long>(workContext);
    if (!ContextUtil::SetNativeContextLong(env, contextObj, nativeContextLong)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "SetNativeContextLong failed");
        delete workContext;
        workContext = nullptr;
        return nullptr;
    }
    return contextObj;
}
ani_object EtsAbilityDelegator::WrapShellCmdResult(ani_env *env, std::unique_ptr<AppExecFwk::ShellCmdResult> result)
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
    ani_field filed = nullptr;
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

ani_object EtsAbilityDelegator::GetAppContext(ani_env *env, [[maybe_unused]]ani_object object, ani_class clss)
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
    if (!AppExecFwk::GetStdString(env, cmd, stdCmd)) {
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
    ani_object objValue = WrapShellCmdResult(env, std::move(result));
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
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        objValue);
    return;
}

void EtsAbilityDelegator::FinishTest(ani_env *env, [[maybe_unused]]ani_object object,
    ani_string msg, ani_double code, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
        return;
    }
    std::string stdMsg = "";
    if (!AppExecFwk::GetStdString(env, msg, stdMsg)) {
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
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
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
    if (!ParseMonitorPara(env, monitorObj, monitorImpl)) {
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
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::AddAbilityMonitorSync(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "AddAbilityMonitorSync");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse param monitor failed, monitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        delegator->AddAbilityMonitor(monitorImpl);
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, COMMON_FAILED, "Calling AddAbilityMonitorSync failed.");
    }
    return;
}
void EtsAbilityDelegator::StartAbility(ani_env *env, [[maybe_unused]]ani_object object,
    ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "StartAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "UnwrapWant failed");
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
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

ani_ref EtsAbilityDelegator::GetCurrentTopAbility(ani_env* env, [[maybe_unused]]ani_class aniClass,
    ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    ani_object objValue = nullptr;
    int32_t resultCode = COMMON_FAILED;
    std::string resultMsg = "Calling GetCurrentTopAbility failed.";
    do {
        auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
            AbilityRuntime::Runtime::Language::ETS);
        if (delegator == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
            break;
        }
        auto property = delegator->GetCurrentTopAbility();
        auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::EtsDelegatorAbilityProperty>(property);
        if (etsbaseProperty == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "property is nullptr");
            break;
        }
        auto ability = etsbaseProperty->object_.lock();
        if (ability == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "invalid property");
            break;
        }
        resultCode = 0;
        resultMsg = "";
        std::unique_lock<std::mutex> lck(g_mutexAbilityRecord);
        g_abilityRecord.emplace(etsbaseProperty->object_, etsbaseProperty->token_);
        objValue = ability->aniObj;
    } while (0);
    ani_ref callbackRef = nullptr;
    auto status = env->GlobalReference_Create(callback, &callbackRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Create Gloabl ref for delegator failed %{public}d", status);
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return objValue;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
        AbilityRuntime::EtsErrorUtil::CreateError(env, resultCode, resultMsg), objValue);
    return objValue;
}

void EtsAbilityDelegator::RemoveAbilityMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "RemoveAbilityMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->RemoveAbilityMonitor(monitorImpl);
        CleanAndFindMonitorRecord(env, monitorObj);
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::RemoveAbilityMonitorSync(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "RemoveAbilityMonitorSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "ParseMonitorPara failed");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse monitor failed, RemoveAbilityMonitorSync must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, COMMON_FAILED, "Calling RemoveAbilityMonitorSync failed.");
        return;
    }
    delegator->RemoveAbilityMonitor(monitorImpl);
    CleanAndFindMonitorRecord(env, monitorObj);
    return;
}

void EtsAbilityDelegator::WaitAbilityMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object monitorObj, ani_double timeout, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "WaitAbilityMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityMonitor> monitorImpl = nullptr;
    if (!ParseMonitorPara(env, monitorObj, monitorImpl)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse monitor want failed, WaitAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    std::shared_ptr<BaseDelegatorAbilityProperty> property = (static_cast<int64_t>(timeout) > 0) ?
            delegator->WaitAbilityMonitor(monitorImpl, static_cast<int64_t>(timeout)) :
            delegator->WaitAbilityMonitor(monitorImpl);
    int resultCode = 0;
    ani_object resultAniOj = nullptr;
    auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::EtsDelegatorAbilityProperty>(property);
    if (!etsbaseProperty || etsbaseProperty->object_.expired()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid etsbaseProperty");
        resultCode = COMMON_FAILED;
    } else {
        std::unique_lock<std::mutex> lck(g_mutexAbilityRecord);
        g_abilityRecord.emplace(etsbaseProperty->object_, etsbaseProperty->token_);
        resultAniOj = etsbaseProperty->object_.lock()->aniObj;
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        resultAniOj);
    return;
}

void EtsAbilityDelegator::AddAbilityStageMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "AddAbilityStageMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse parameters failed, monitor must be Monitor and isExited must be boolean.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->AddAbilityStageMonitor(stageMonitor);
        if (!isExisted) {
            AddStageMonitorRecord(env, stageMonitorObj, stageMonitor);
        }
        AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
            nullptr);
    }
    return;
}

void EtsAbilityDelegator::AddAbilityStageMonitorSync(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "AddAbilityStageMonitorSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse parameters failed, monitor must be Monitor and isExited must be boolean.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        delegator->AddAbilityStageMonitor(stageMonitor);
        if (!isExisted) {
        AddStageMonitorRecord(env, stageMonitorObj, stageMonitor);
    }
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, COMMON_FAILED, "Calling AddAbilityStageMonitorSync failed.");
    }
    return;
}

void EtsAbilityDelegator::RemoveAbilityStageMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "RemoveAbilityStageMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    int resultCode = 0;
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->RemoveAbilityStageMonitor(stageMonitor);
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    if (isExisted) {
        RemoveStageMonitorRecord(env, stageMonitorObj);
    }
    return;
}

void EtsAbilityDelegator::RemoveAbilityStageMonitorSync(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "RemoveAbilityStageMonitorSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    bool isExisted = false;
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!ParseStageMonitorPara(env, stageMonitorObj, stageMonitor, isExisted)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        delegator->RemoveAbilityStageMonitor(stageMonitor);
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, COMMON_FAILED, "Calling RemoveAbilityStageMonitorSync failed.");
    }

    if (isExisted) {
        RemoveStageMonitorRecord(env, stageMonitorObj);
    }
    return;
}

void EtsAbilityDelegator::WaitAbilityStageMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
    ani_object stageMonitorObj, ani_double timeout, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "WaitAbilityStageMonitor called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::shared_ptr<EtsAbilityStageMonitor> stageMonitor = nullptr;
    if (!ParseWaitAbilityStageMonitorPara(env, stageMonitorObj, stageMonitor)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse monitor failed, removeAbilityMonitor must be Monitor.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    std::shared_ptr<BaseDelegatorAbilityStageProperty> result;
    result = (static_cast<int64_t>(timeout) > 0) ?
            delegator->WaitAbilityStageMonitor(stageMonitor, static_cast<int64_t>(timeout)) :
            delegator->WaitAbilityStageMonitor(stageMonitor);
    int resultCode = 0;
    ani_object resultAniOj = nullptr;
    auto etsbaseProperty = std::static_pointer_cast<AppExecFwk::EtsDelegatorAbilityStageProperty>(result);
    if (CheckPropertyValue(env, resultCode, resultAniOj, etsbaseProperty)) {
        resultAniOj = etsbaseProperty->object_.lock()->aniObj;
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        resultAniOj);
    return;
}

void EtsAbilityDelegator::DoAbilityForeground(ani_env *env, [[maybe_unused]]ani_object object,
    ani_object abilityObj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "DoAbilityForeground called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    if (!ParseAbilityCommonPara(env, abilityObj, remoteObject)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse remoteObject failed, remoteObject must be RemoteObject.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    int resultCode = 0;
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        if (!delegator->DoAbilityForeground(remoteObject)) {
            resultCode = COMMON_FAILED;
        }
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::DoAbilityBackground(ani_env *env, [[maybe_unused]]ani_object object,
    ani_object abilityObj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "DoAbilityBackground called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    if (!ParseAbilityCommonPara(env, abilityObj, remoteObject)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse remoteObject failed, remoteObject must be RemoteObject.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    int resultCode = 0;
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        if (!delegator->DoAbilityBackground(remoteObject)) {
            resultCode = COMMON_FAILED;
        }
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

void EtsAbilityDelegator::Print(ani_env *env, [[maybe_unused]]ani_object object,
    ani_string msg, ani_object callback)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "Print called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    std::string strMsg = "";
    if (!AppExecFwk::GetStdString(env, msg, strMsg)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "GetStdString Failed");
        AbilityRuntime::EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM),
            "Parse msg failed, msg must be string.");
        return;
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    int resultCode = 0;
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        resultCode = COMMON_FAILED;
    } else {
        delegator->Print(strMsg);
    }
    AppExecFwk::AsyncCallback(env, callback, AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, resultCode),
        nullptr);
    return;
}

ani_double EtsAbilityDelegator::GetAbilityState(ani_env *env, [[maybe_unused]]ani_object object, ani_object abilityObj)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "GetAbilityState called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return COMMON_FAILED;
    }
    sptr<OHOS::IRemoteObject> remoteObject = nullptr;
    if (!ParseAbilityCommonPara(env, abilityObj, remoteObject)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid params");
        return COMMON_FAILED;
    }

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return COMMON_FAILED;
    }
    AbilityDelegator::AbilityState lifeState = delegator->GetAbilityState(remoteObject);
    AbilityLifecycleState abilityLifeState = AbilityLifecycleState::UNINITIALIZED;
    AbilityLifecycleStateToEts(lifeState, abilityLifeState);
    return static_cast<ani_double>(abilityLifeState);
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
    if (env == nullptr || monitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or monitorObj is nullptr");
        return false;
    }
    {
        std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
        TAG_LOGI(AAFwkTag::DELEGATOR, "monitorRecord size: %{public}zu", g_monitorRecord.size());
        for (auto iter = g_monitorRecord.begin(); iter != g_monitorRecord.end();) {
            if (iter->first.expired()) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "g_monitorRecord expired");
                iter = g_monitorRecord.erase(iter);
                continue;
            }
            std::shared_ptr<ETSNativeReference> etsMonitor = iter->first.lock();
            if (etsMonitor == nullptr) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "etsMonitor is nullptr");
                iter = g_monitorRecord.erase(iter);
                continue;
            }
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
            ++iter;
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
    RetrieveStringFromAni(env, aniModuleString, strModuleName);
    ani_ref abilityNameRef = nullptr;
    status = env->Object_GetPropertyByName_Ref(monitorObj, "abilityName", &abilityNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strAbilityName = "";
    ani_string aniAbilityName = static_cast<ani_string>(abilityNameRef);
    RetrieveStringFromAni(env, aniAbilityName, strAbilityName);

    std::shared_ptr<EtsAbilityMonitor> abilityMonitor = nullptr;
    if (strModuleName.empty()) {
        abilityMonitor = std::make_shared<EtsAbilityMonitor>(strAbilityName);
        abilityMonitor->SetEtsAbilityMonitor(env, monitorObj);
    } else {
        abilityMonitor = std::make_shared<EtsAbilityMonitor>(strAbilityName, strModuleName);
        abilityMonitor->SetEtsAbilityMonitor(env, monitorObj);
    }
    monitorImpl = abilityMonitor;
    std::shared_ptr<ETSNativeReference> reference = std::make_shared<ETSNativeReference>();
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
    if (env == nullptr || stageMonitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or stageMonitorObj is nullptr");
        return false;
    }
    isExisted = false;
    {
        std::unique_lock<std::mutex> lck(g_mtxStageMonitorRecord);
        TAG_LOGI(AAFwkTag::DELEGATOR, "stageMonitorRecord size: %{public}zu", g_stageMonitorRecord.size());
        for (auto iter = g_stageMonitorRecord.begin(); iter != g_stageMonitorRecord.end();) {
            if (iter->first.expired()) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "g_stageMonitorRecord expired");
                iter = g_stageMonitorRecord.erase(iter);
                continue;
            }
            std::shared_ptr<ETSNativeReference> etsMonitor = iter->first.lock();
            if (etsMonitor == nullptr) {
                TAG_LOGE(AAFwkTag::DELEGATOR, "etsMonitor is nullptr");
                iter = g_stageMonitorRecord.erase(iter);
                continue;
            }
            ani_boolean result = false;
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
            ++iter;
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
    ani_class monitorCls = nullptr;
    ani_status status = env->FindClass(ABILITY_STAGE_MONITOR_INNER_CLASS_NAME, &monitorCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status: %{public}d", status);
        return false;
    }
    ani_ref moduleNameRef = nullptr;
    status = env->Object_GetPropertyByName_Ref(stageMonitorObj, "moduleName", &moduleNameRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref failed status: %{public}d", status);
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string strModuleName = "";
    ani_string aniModuleString = static_cast<ani_string>(moduleNameRef);
    RetrieveStringFromAni(env, aniModuleString, strModuleName);
    TAG_LOGD(AAFwkTag::DELEGATOR, "strModuleName %{public}s ", strModuleName.c_str());
    ani_ref srcEntranceRef = nullptr;
    status = env->Object_GetPropertyByName_Ref(stageMonitorObj, "srcEntrance", &srcEntranceRef);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        AbilityRuntime::EtsErrorUtil::ThrowError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
        return false;
    }
    std::string srcEntrance = "";
    ani_string aniSrcEntranceRef = static_cast<ani_string>(srcEntranceRef);
    RetrieveStringFromAni(env, aniSrcEntranceRef, srcEntrance);
    TAG_LOGD(AAFwkTag::DELEGATOR, "srcEntrance %{public}s ", srcEntrance.c_str());
    stageMonitor = std::make_shared<EtsAbilityStageMonitor>(strModuleName, srcEntrance);
    return true;
}

void EtsAbilityDelegator::AddStageMonitorRecord(ani_env *env, ani_object stageMonitorObj,
    const std::shared_ptr<EtsAbilityStageMonitor> &stageMonitor)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "AddStageMonitorRecord called");
    if (env == nullptr || stageMonitor == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or stageMonitor is nullptr");
        return;
    }
    if (!AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }
    std::shared_ptr<ETSNativeReference> reference = std::make_shared<ETSNativeReference>();
    reference->aniObj = stageMonitorObj;
    {
        std::unique_lock<std::mutex> lck(g_mtxStageMonitorRecord);
        g_stageMonitorRecord.emplace(reference, stageMonitor);
        TAG_LOGI(AAFwkTag::DELEGATOR, "end, size: %{public}zu", g_stageMonitorRecord.size());
    }
}

void EtsAbilityDelegator::RemoveStageMonitorRecord(ani_env *env, ani_object stageMonitorObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env is nullptr");
        return;
    }
    if (!AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }
    std::unique_lock<std::mutex> lck(g_mtxStageMonitorRecord);
    for (auto iter = g_stageMonitorRecord.begin(); iter != g_stageMonitorRecord.end();) {
        if (iter->first.expired()) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "g_stageMonitorRecord expired");
            iter = g_stageMonitorRecord.erase(iter);
            continue;
        }
        std::shared_ptr<ETSNativeReference> etsMonitor = iter->first.lock();
        if (etsMonitor == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "etsMonitor is nullptr");
            iter = g_stageMonitorRecord.erase(iter);
            continue;
        }
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
        ++iter;
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
            TAG_LOGE(AAFwkTag::DELEGATOR, "g_abilityRecord expired");
            iter = g_abilityRecord.erase(iter);
            continue;
        }
        std::shared_ptr<ETSNativeReference> etsMonitor = iter->first.lock();
        if (etsMonitor == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "etsMonitor is null");
            iter = g_abilityRecord.erase(iter);
            continue;
        }
        ani_boolean result = false;
        ani_status status = env->Reference_StrictEquals(reinterpret_cast<ani_ref>(etsMonitor->aniObj),
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
    std::shared_ptr<AppExecFwk::EtsDelegatorAbilityStageProperty> etsProperty)
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
    return true;
}

void EtsAbilityDelegator::CleanAndFindMonitorRecord(ani_env *env, ani_object monitorObj)
{
    if (env == nullptr || monitorObj == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "env or monitorObj is nullptr");
        return;
    }
    std::unique_lock<std::mutex> lck(g_mtxMonitorRecord);
    for (auto iter = g_monitorRecord.begin(); iter != g_monitorRecord.end();) {
        if (iter->first.expired()) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "g_monitorRecord expired");
            iter = g_monitorRecord.erase(iter);
            continue;
        }
        std::shared_ptr<ETSNativeReference> etsMonitor = iter->first.lock();
        if (etsMonitor == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "etsMonitor is null");
            iter = g_monitorRecord.erase(iter);
            continue;
        }
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
        ++iter;
    }
}
} // namespace AbilityDelegatorEts
} // namespace OHOS
