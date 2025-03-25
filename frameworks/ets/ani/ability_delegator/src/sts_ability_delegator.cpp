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
namespace OHOS {
namespace AbilityDelegatorSts {

using namespace OHOS::AbilityRuntime;

ani_object CreateStsBaseContext(ani_env* aniEnv, ani_class contextClass,
    std::shared_ptr<AbilityRuntime::Context> context)
{
    // bind parent context property
    ani_status status = ANI_ERROR;
    ani_method areaSetter;
    ani_object contextObj = nullptr;
    ani_method method = nullptr;

    status = aniEnv->Class_FindMethod(contextClass, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status : %{public}d", status);
        return {};
    }
    status = aniEnv->Object_New(contextClass, method, &contextObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status : %{public}d", status);
        return {};
    }
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>area", nullptr, &areaSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set area failed");
    }
    auto area = context->GetArea();
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, areaSetter, ani_int(area))) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set area failed");
    }
    ani_method filesDirSetter;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>filesDir", nullptr, &filesDirSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set filesDir failed");
    }
    std::string filesDir = context->GetFilesDir();
    ani_string filesDir_string{};
    aniEnv->String_NewUTF8(filesDir.c_str(), filesDir.size(), &filesDir_string);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, filesDirSetter, filesDir_string)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set filesDir failed");
    }
    ani_method tempDirSetter;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>tempDir", nullptr, &tempDirSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set tempDir failed");
    }
    auto tempDir = context->GetTempDir();
    ani_string tempDir_string{};
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDir_string);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, tempDirSetter, tempDir_string)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set tempDir failed");
    }
    return contextObj;
}

ani_object GetAppContext(ani_env* env, ani_class clss)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "GetAppContext call");
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
    ani_object object = CreateStsBaseContext(env, cls, context);
    TAG_LOGI(AAFwkTag::DELEGATOR, "GetAppContext end");
    return object;
}


ani_object wrapShellCmdResult(ani_env* env, std::unique_ptr<AppExecFwk::ShellCmdResult> result)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "wrapShellCmdResult called");
    if (result == nullptr) {
        return {};
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    status = env->FindClass("LAbilityDelegator/ShellCmdResult;", &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegator failed status : %{public}d", status);
        return {};
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status : %{public}d", status);
        return {};
    }
    ani_object object = nullptr;
    if (env->Object_New(cls, method, &object) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status : %{public}d", status);
        return {};
    }
    TAG_LOGI(AAFwkTag::DELEGATOR, "Object_New success");

    //stdResult
    ani_field filed;
    status = env->Class_FindField(cls, "stdResult", &filed);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindField configObj failed");
    }

    ani_string aniStringVal {};
    std::string strResult = result->GetStdResult();
    status = env->String_NewUTF8(strResult.c_str(), strResult.size(), &aniStringVal);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "String_NewUTF8 mcc failed");
    }
    if (env->Object_SetField_Ref(object, filed, aniStringVal) != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Object_SetField_Ref mcc failed");
    }

    //exitCode
    int32_t exitCode = result->GetExitCode();
    status = env->Class_FindField(cls, "exitCode", &filed);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindField configObj failed");
    }
    status = env->Object_SetField_Int(object, filed, exitCode);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Object_SetField_Int exitCode failed");
    }

    return object;
}

ani_object ExecuteShellCommand(ani_env* env, std::string &cmd, double timeoutSecs)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ExecuteShellCommand called");
    ani_object objValue = nullptr;
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator != nullptr) {
        auto result = delegator->ExecuteShellCommand(cmd, static_cast<int64_t>(timeoutSecs));
        objValue = wrapShellCmdResult(env, std::move(result));
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
        return {};
    }
    return objValue;
}

ani_int FinishTestSync(std::string &msg, double &code)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "finishTestSync delegator is null");
        return 0;
    }
    delegator->FinishUserTest(msg, static_cast<int64_t>(code));
    TAG_LOGI(AAFwkTag::DELEGATOR, "finishTestSync END");
    return 1;
}

void PrintSync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_string msg)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "PrintSync");
    std::string msgStr;
    ani_size sz {};
    env->String_GetUTF8Size(msg, &sz);
    msgStr.resize(sz + 1);
    env->String_GetUTF8SubString(msg, 0, sz, msgStr.data(), msgStr.size(), &sz);
    TAG_LOGI(AAFwkTag::DELEGATOR, "PrintSync %{public}s", msgStr.c_str());

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }

    delegator->Print(msgStr);
    return;
}

void RetrieveStringFromAni(ani_env *env, ani_string string, std::string &resString)
{
    ani_status status = ANI_OK;
    ani_size result = 0U;
    status = env->String_GetUTF8Size(string, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_GetUTF8Size failed status : %{public}d", status);
        return;
    }
    ani_size substrOffset = 0U;
    ani_size substrSize = result;
    const ani_size bufferExtension = 10U;
    resString.resize(substrSize + bufferExtension);
    ani_size resSize = resString.size();
    result = 0U;
    status = env->String_GetUTF8SubString(string, substrOffset, substrSize, resString.data(), resSize, &result);
}

void AddAbilityMonitorASync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_object monitorObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "AddAbilityMonitorASync");
    ani_class monitorCls;
    ani_status status = env->FindClass("L@ohos/ability/AbilityDelegator/AbilityMonitor;", &monitorCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status : %{public}d", status);
        return;
    }

    ani_field fieldModuleName = nullptr;
    status = env->Class_FindField(monitorCls, "moduleName", &fieldModuleName);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "Class_GetField failed");
        return;
    }

    ani_ref moduleNameRef;
    status = env->Object_GetField_Ref(monitorObj, fieldModuleName, &moduleNameRef);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        return;
    }
    std::string strModuleName;
    ani_string aniModuleString = static_cast<ani_string>(moduleNameRef);
    RetrieveStringFromAni(env, aniModuleString, strModuleName);

    ani_field fieldAbilityName = nullptr;
    status = env->Class_FindField(monitorCls, "abilityName", &fieldAbilityName);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "Class_GetField failed");
        return;
    }

    ani_ref abilityNameRef;
    status = env->Object_GetField_Ref(monitorObj, fieldAbilityName, &abilityNameRef);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "Object_GetField_Ref ");
        return;
    }

    std::string strAbilityName;
    ani_string aniAbilityName = static_cast<ani_string>(abilityNameRef);
    RetrieveStringFromAni(env, aniAbilityName, strAbilityName);

    std::shared_ptr<AppExecFwk::IAbilityMonitor> monitor =
        std::make_shared<AppExecFwk::IAbilityMonitor>(strAbilityName, strModuleName);

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        return;
    }
    delegator->AddAbilityMonitor(monitor);
}

ani_int StartAbility(ani_env* env, ani_class aniClass, ani_object wantObj)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "StartAbility call");
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "UnwrapWant  failed");
        return ani_int(-1);
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    int result = delegator->StartAbility(want);
    return ani_int(result);
}

} // namespace AbilityDelegatorSts
} // namespace OHOS
