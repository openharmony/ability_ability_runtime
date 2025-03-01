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
namespace OHOS {
namespace AbilityDelegatorSts {

using namespace OHOS::AbilityRuntime;

ani_object CreateStsBaseContext(ani_env* aniEnv, ani_class contextClass,
    std::shared_ptr<AbilityRuntime::Context> context)
{
    // bind parent context property
    ani_method areaSetter;
    ani_object contextObj = nullptr;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>area", nullptr, &areaSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set area failed");
    }
    auto area = context->GetArea();
    TAG_LOGI(AAFwkTag::APPKIT, "ani area:%{public}d", area);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, areaSetter, ani_int(area))) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set area failed");
    }
    ani_method filesDirSetter;
    if (ANI_OK != aniEnv->Class_FindMethod(contextClass, "<set>filesDir", nullptr, &filesDirSetter)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find set filesDir failed");
    }
    std::string filesDir = context->GetFilesDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani filesDir:%{public}s", filesDir.c_str());
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
    TAG_LOGI(AAFwkTag::APPKIT, "ani tempDir:%{public}s", tempDir.c_str());
    ani_string tempDir_string{};
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDir_string);
    if (ANI_OK != aniEnv->Object_CallMethod_Void(contextObj, tempDirSetter, tempDir_string)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call set tempDir failed");
    }
    return contextObj;
}

ani_object GetAppContext(ani_env* env, ani_class clss)
{
    TAG_LOGE(AAFwkTag::DELEGATOR, "GetAppContext call");
    ani_class cls;
    if (ANI_OK != env->FindClass("L@ohos/ability/AbilityDelegator/Context;", &cls)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "CreateStsBaseContext FindClass");
    }
    auto delegator = OHOS::AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator();
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null delegator");
        ani_object nullobj = nullptr;
        return nullobj;
    }
    std::shared_ptr<AbilityRuntime::Context> context = delegator->GetAppContext();
    if (!context) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null context");
        ani_object nullobj = nullptr;
        return nullobj;
    }
    ani_object object = CreateStsBaseContext(env, cls, context);
    TAG_LOGE(AAFwkTag::DELEGATOR, "GetAppContext end");
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

ani_object ExecuteShellCommand(ani_env* env, std::string &cmd, int timeoutSecs)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");
    ani_object objValue = nullptr;
    auto delegator = OHOS::AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator();
    if (delegator != nullptr) {
        auto result = delegator->ExecuteShellCommand(cmd, timeoutSecs);
        objValue = wrapShellCmdResult(env, std::move(result));
    } else {
        TAG_LOGE(AAFwkTag::DELEGATOR, "delegator is nullptr");
        return {};
    }
    return objValue;
}

ani_int FinishTestSync(std::string &msg, int64_t &code)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");
    auto delegator = OHOS::AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator();
    if (!delegator) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "finishTestSync delegator is null");
        return 0;
    }
    delegator->FinishUserTest(msg, code);
    TAG_LOGI(AAFwkTag::DELEGATOR, "finishTestSync END");
    return 1;
}

} // namespace AbilityDelegatorSts
} // namespace OHOS
