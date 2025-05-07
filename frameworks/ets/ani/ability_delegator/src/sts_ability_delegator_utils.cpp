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

#include "sts_ability_delegator_utils.h"

#include <map>
#include "hilog_tag_wrapper.h"
#include "sts_ability_delegator.h"

namespace OHOS {
namespace AbilityDelegatorSts {
namespace {
constexpr const char* ABILITY_DELEGATOR_CLASS_NAME = "Lapplication/AbilityDelegator/AbilityDelegatorInner;";
constexpr const char* RECORD_CLASS_NAME = "Lescompat/Record;";
constexpr const char* ARGS_ABILITY_DELEGATOR_CLASS_NAME =
    "Lapplication/abilityDelegatorArgs/AbilityDelegatorArgsInner;";
}

ani_object CreateStsAbilityDelegator(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CreateJsAbilityDelegator");
    if (aniEnv ==nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv");
        return {};
    }
    ani_class abilityDelegator = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass(ABILITY_DELEGATOR_CLASS_NAME, &abilityDelegator);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegatorInner failed status: %{public}d", status);
        return {};
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "find AbilityDelegator success");

    std::array delegatorFunctions = {
        ani_native_function {"getAppContext", nullptr, reinterpret_cast<void *>(GetAppContext)},
        ani_native_function {"executeShellCommandsync", nullptr, reinterpret_cast<void *>(ExecuteShellCommand)},
        ani_native_function {"finishTestSync", nullptr, reinterpret_cast<void *>(FinishTestSync)},
        ani_native_function {"printSync", nullptr, reinterpret_cast<void *>(PrintSync)},
        ani_native_function {"addAbilityMonitorAsync", nullptr, reinterpret_cast<void *>(AddAbilityMonitorASync)},
        ani_native_function {"startAbilityAsync",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(StartAbility)},
        ani_native_function {"GetCurrentTopAbilitySync", nullptr, reinterpret_cast<void *>(GetCurrentTopAbilitySync)}
    };
    status = aniEnv->Class_BindNativeMethods(abilityDelegator, delegatorFunctions.data(), delegatorFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_BindNativeMethods failed status: %{public}d", status);
        return {};
    }

    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(abilityDelegator, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status: %{public}d", status);
        return {};
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Class_FindMethod ctor success");

    ani_object object = nullptr;
    if (aniEnv->Object_New(abilityDelegator, method, &object) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status: %{public}d", status);
        return {};
    }

    TAG_LOGD(AAFwkTag::DELEGATOR, "CreateStsAbilityDelegator success");
    return object;
}

void SetBundleName(ani_env *aniEnv, ani_class arguments, ani_object argumentObject, const std::string &bundleName)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    // Get a ani_string from std::string
    status = aniEnv->String_NewUTF8(bundleName.c_str(), bundleName.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "String_NewUTF8 success");

    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(arguments, "<set>bundleName", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Class_FindMethod success");

    // call set bundleName(n:string)
    status = aniEnv->Object_CallMethod_Void(argumentObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Object_CallMethod_Void success");
}

void SetParameters(ani_env *aniEnv, ani_class arguments, ani_object argumentObject,
    const std::map<std::string, std::string> &paras)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "SetParameters begin");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    // get getter and setter methond of Record
    ani_class recordCls;
    status = aniEnv->FindClass(RECORD_CLASS_NAME, &recordCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status: %{public}d", status);
        return;
    }

    ani_method recordGetMethod;
    status = aniEnv->Class_FindMethod(recordCls, "$_get", "Lstd/core/Object;:Lstd/core/Object;", &recordGetMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status: %{public}d", status);
        return;
    }

    ani_method recordSetMethod;
    status = aniEnv->Class_FindMethod(recordCls, "$_set", "Lstd/core/Object;Lstd/core/Object;:V", &recordSetMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status: %{public}d", status);
        return;
    }

    // get parameters ref of object
    ani_ref parameterRef;
    status = aniEnv->Object_CallMethodByName_Ref(argumentObject, "<get>parameters", ":Lescompat/Record;",
        &parameterRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethodByName_Ref failed status: %{public}d", status);
        return;
    }
    ani_object parameterObject = static_cast<ani_object>(parameterRef);

    for (auto iter = paras.begin(); iter != paras.end(); ++iter) {
        std::string key = iter->first;
        std::string value = iter->second;
        ani_string ani_key;
        ani_string ani_value;

        status = aniEnv->String_NewUTF8(key.c_str(), key.length(), &ani_key);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 key failed status: %{public}d", status);
            return;
        }

        status = aniEnv->String_NewUTF8(value.c_str(), value.length(), &ani_value);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 value failed status: %{public}d", status);
            return;
        }

        // 调用set方法给Record类型的property赋值
        status = aniEnv->Object_CallMethod_Void(parameterObject, recordSetMethod, ani_key, ani_value);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status: %{public}d", status);
            return;
        }
    }

    TAG_LOGD(AAFwkTag::DELEGATOR, "SetParameters end");
}

void SetTestCaseNames(ani_env *aniEnv, ani_class arguments, ani_object argumentObject, const std::string &testcaseNames)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    status = aniEnv->String_NewUTF8(testcaseNames.c_str(), testcaseNames.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "String_NewUTF8 success");

    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(arguments, "<set>testCaseNames", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Class_FindMethod success");

    // call set testcaseNames(n:string)
    status = aniEnv->Object_CallMethod_Void(argumentObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Object_CallMethod_Void success");
}

void SetTestRunnerClassName(ani_env *aniEnv, ani_class arguments, ani_object argumentObject,
    const std::string &className)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    status = aniEnv->String_NewUTF8(className.c_str(), className.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "String_NewUTF8 success");

    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(arguments, "<set>testRunnerClassName", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Class_FindMethod success");

    // call set testRunnerClassName(n:string)
    status = aniEnv->Object_CallMethod_Void(argumentObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status: %{public}d", status);
        return;
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Object_CallMethod_Void success");
}

ani_object CreateStsAbilityDelegatorArguments(
    ani_env *aniEnv, const std::shared_ptr<AppExecFwk::AbilityDelegatorArgs> abilityDelegatorArgs)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "CreateJsAbilityDelegatorArguments");
    if (aniEnv == nullptr || abilityDelegatorArgs == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null aniEnv or abilityDelegatorArgs");
        return {};
    }
    ani_class arguments = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass(ARGS_ABILITY_DELEGATOR_CLASS_NAME, &arguments);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find abilityDelegatorArgs failed status: %{public}d", status);
        return {};
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "find AbilityDelegatorArgs success");

    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(arguments, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status: %{public}d", status);
        return {};
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Class_FindMethod ctor success");

    ani_object argumentObject = nullptr;
    status = aniEnv->Object_New(arguments, method, &argumentObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status: %{public}d", status);
        return {};
    }
    TAG_LOGD(AAFwkTag::DELEGATOR, "Object_New success");

    std::string bundleName = abilityDelegatorArgs->GetTestBundleName();
    SetBundleName(aniEnv, arguments, argumentObject, bundleName);

    std::string testcaseName = abilityDelegatorArgs->GetTestCaseName();
    SetTestCaseNames(aniEnv, arguments, argumentObject, testcaseName);

    std::string className = abilityDelegatorArgs->GetTestRunnerClassName();
    SetTestRunnerClassName(aniEnv, arguments, argumentObject, className);

    auto parameters = abilityDelegatorArgs->GetTestParam();
    SetParameters(aniEnv, arguments, argumentObject, parameters);

    return argumentObject;
}
} // namespace AbilityDelegatorSts
} // namespace OHOS
