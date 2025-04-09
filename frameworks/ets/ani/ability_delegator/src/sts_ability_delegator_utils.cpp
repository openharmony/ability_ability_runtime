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
ani_object CreateStsAbilityDelegator(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    ani_class abilityDelegator = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass("Lapplication/AbilityDelegator/AbilityDelegatorInner;", &abilityDelegator);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegator failed status : %{public}d", status);
        return {};
    }

    std::array delegatorFunctions = {
        ani_native_function {"getAppContext", nullptr, reinterpret_cast<void *>(GetAppContext)},
        ani_native_function {"executeShellCommandsync", nullptr, reinterpret_cast<void *>(ExecuteShellCommand)},
        ani_native_function {"finishTestSync", nullptr, reinterpret_cast<void *>(FinishTestSync)},
        ani_native_function {"printSync", "Lstd/core/String;:V", reinterpret_cast<void *>(PrintSync)},
        ani_native_function {"addAbilityMonitorAsync", nullptr, reinterpret_cast<void *>(AddAbilityMonitorASync)},
        ani_native_function {"startAbilityAsync", nullptr, reinterpret_cast<void *>(StartAbility)}
    };
    status = aniEnv->Class_BindNativeMethods(abilityDelegator, delegatorFunctions.data(), delegatorFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_BindNativeMethods failed status : %{public}d", status);
        return {};
    }

    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(abilityDelegator, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status : %{public}d", status);
        return {};
    }

    ani_object object = nullptr;
    if (aniEnv->Object_New(abilityDelegator, method, &object) != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status : %{public}d", status);
        return {};
    }

    return object;
}

void SetBundleName(ani_env *aniEnv, ani_class arguments, ani_object argumentObject, const std::string &bundleName)
{
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    // Get a ani_string from std::string
    status = aniEnv->String_NewUTF8(bundleName.c_str(), bundleName.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status : %{public}d", status);
        return;
    }

    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(arguments, "<set>bundleName", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status : %{public}d", status);
        return;
    }

    // call set bundleName(n:string)
    status = aniEnv->Object_CallMethod_Void(argumentObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }
}

void SetParameters(ani_env *aniEnv, ani_class arguments, ani_object argumentObject,
    const std::map<std::string, std::string> &paras)
{
    ani_status status = ANI_ERROR;
    // get getter and setter methond of Record
    ani_class recordCls;
    status = aniEnv->FindClass("Lescompat/Record;", &recordCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "FindClass failed status : %{public}d", status);
        return;
    }

    ani_method recordGetMethod;
    status = aniEnv->Class_FindMethod(recordCls, "$_get", "Lstd/core/Object;:Lstd/core/Object;", &recordGetMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status : %{public}d", status);
        return;
    }

    ani_method recordSetMethod;
    status = aniEnv->Class_FindMethod(recordCls, "$_set", "Lstd/core/Object;Lstd/core/Object;:V", &recordSetMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status : %{public}d", status);
        return;
    }

    // get parameters ref of object
    ani_ref parameterRef;
    status = aniEnv->Object_CallMethodByName_Ref(argumentObject, "<get>parameters", ":Lescompat/Record;",
        &parameterRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethodByName_Ref failed status : %{public}d", status);
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
            TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 key failed status : %{public}d", status);
            return;
        }

        status = aniEnv->String_NewUTF8(value.c_str(), value.length(), &ani_value);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 value failed status : %{public}d", status);
            return;
        }

        // 调用set方法给Record类型的property赋值
        status = aniEnv->Object_CallMethod_Void(parameterObject, recordSetMethod, ani_key, ani_value);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status : %{public}d", status);
            return;
        }
    }
}

void SetTestCaseNames(ani_env *aniEnv, ani_class arguments, ani_object argumentObject, const std::string &testcaseNames)
{
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    status = aniEnv->String_NewUTF8(testcaseNames.c_str(), testcaseNames.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status : %{public}d", status);
        return;
    }
    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(arguments, "<set>testCaseNames", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status : %{public}d", status);
        return;
    }
    // call set testcaseNames(n:string)
    status = aniEnv->Object_CallMethod_Void(argumentObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }
}

void SetTestRunnerClassName(ani_env *aniEnv, ani_class arguments, ani_object argumentObject,
    const std::string &className)
{
    ani_status status = ANI_ERROR;
    ani_string aniStr;
    status = aniEnv->String_NewUTF8(className.c_str(), className.length(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "String_NewUTF8 failed status : %{public}d", status);
        return;
    }
    // find the setter method
    ani_method nameSetter;
    status = aniEnv->Class_FindMethod(arguments, "<set>testRunnerClassName", nullptr, &nameSetter);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod failed status : %{public}d", status);
        return;
    }
    // call set testRunnerClassName(n:string)
    status = aniEnv->Object_CallMethod_Void(argumentObject, nameSetter, aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }
}

ani_object CreateStsAbilityDelegatorArguments(
    ani_env *aniEnv, const std::shared_ptr<AppExecFwk::AbilityDelegatorArgs> abilityDelegatorArgs)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");
    ani_class arguments = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass("Lapplication/AbilityDelegatorArgs/AbilityDelegatorArgsInner;", &arguments);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "find AbilityDelegatorArgs failed status : %{public}d", status);
        return {};
    }
    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(arguments, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status : %{public}d", status);
        return {};
    }
    ani_object argumentObject = nullptr;
    status = aniEnv->Object_New(arguments, method, &argumentObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status : %{public}d", status);
        return {};
    }
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
