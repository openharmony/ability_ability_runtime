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

#include "ani_common_child_process_param.h"

#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CLASSNAME_CHILDPROCESSARGS = "@ohos.app.ability.ChildProcessArgs.ChildProcessArgsImpl";
constexpr const char* RECORD_CLASS_NAME = "std.core.Record";
}

bool SetFds(ani_env* env, ani_object object, std::map<std::string, int32_t> &fds)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "null aniEnv");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class recordCls = nullptr;
    status = env->FindClass(RECORD_CLASS_NAME, &recordCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "FindClass failed status: %{public}d", status);
        return false;
    }
    ani_method objectMethod = nullptr;
    status = env->Class_FindMethod(recordCls, "<ctor>", ":", &objectMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Class_FindMethod constructor failed: %{public}d", status);
        return false;
    }
    ani_object recordObject = nullptr;
    status = env->Object_New(recordCls, objectMethod, &recordObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Object_New failed: %{public}d", status);
        return false;
    }
    ani_method recordSetMethod = nullptr;
    status = env->Class_FindMethod(recordCls, "$_set",
        "X{C{std.core.Numeric}C{std.core.String}C{std.core.BaseEnum}}Y:", &recordSetMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Class_FindMethod failed status: %{public}d", status);
        return false;
    }
    for (auto iter = fds.begin(); iter != fds.end(); ++iter) {
        std::string key = iter->first;
        ani_string aniKey = GetAniString(env, key);
        int32_t value = iter->second;
        ani_object aniValueObj = AppExecFwk::CreateInt(env, value);
        status = env->Object_CallMethod_Void(recordObject, recordSetMethod, aniKey, aniValueObj);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "Object_CallMethod_Void failed status: %{public}d", status);
            return false;
        }
    }
    status = env->Object_SetPropertyByName_Ref(object, "fds", recordObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "set property failed status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetFds(ani_env* env, ani_string aniKey, ani_object aniValue, std::map<std::string, int32_t> &map)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "env null");
        return false;
    }
    std::string mapKey = "";
    if (!GetStdString(env, aniKey, mapKey)) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "GetStdString failed");
        return false;
    }
    ani_int value;
    ani_status status = env->Object_CallMethodByName_Int(aniValue, "intValue", nullptr, &value);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Object_CallMethodByName_Int failed status: %{public}d", status);
        return false;
    }
    auto mapValue = static_cast<int32_t>(value);
    map.emplace(mapKey, mapValue);
    return true;
}

bool UnwrapChildProcessArgs(ani_env* env, ani_object object, ChildProcessArgs &args,
    std::string &errorMsg)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "env null");
        return false;
    }
    if (!GetStringProperty(env, object, "entryParams", args.entryParams)) {
        TAG_LOGI(AAFwkTag::PROCESSMGR, "parameter error");
        errorMsg = "Parameter error. The type of args.entryParams must be string.";
        return false;
    }
    ani_ref fdsRef;
    if (GetRefProperty(env, object, "fds", fdsRef)) {
        ani_object fdsObject = static_cast<ani_object>(fdsRef);
        if (fdsObject == nullptr) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "fds must be Record<string, int>");
            errorMsg = "The type of args.fds must be Record<string, int>.";
            return false;
        }
        if (!UnwrapChildProcessFds(env, fdsObject, args.fds, errorMsg)) {
            return false;
        }
    }
    return true;
}

bool UnwrapChildProcessFds(ani_env* env, ani_object object, std::map<std::string, int32_t> &map, std::string &errorMsg)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "env null");
        return false;
    }
    ani_ref iter;
    ani_status status = ANI_ERROR;
    status = env->Object_CallMethodByName_Ref(object, "$_iterator", nullptr, &iter);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "Failed to get keys iterator status: %{public}d", status);
        return false;
    }
    ani_ref next;
    ani_boolean done;
    while (ANI_OK == env->Object_CallMethodByName_Ref(static_cast<ani_object>(iter), "next", nullptr, &next)) {
        status = env->Object_GetFieldByName_Boolean(static_cast<ani_object>(next), "done", &done);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "Failed to check iterator done status: %{public}d", status);
            return false;
        }
        if (done) {
            TAG_LOGD(AAFwkTag::PROCESSMGR, "[forEachMapEntry] done break");
            return true;
        }
        ani_ref keyValue;
        status = env->Object_GetFieldByName_Ref(static_cast<ani_object>(next), "value", &keyValue);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "Failed to get key value status: %{public}d", status);
            return false;
        }
        ani_ref aniKey;
        status = env->TupleValue_GetItem_Ref(static_cast<ani_tuple_value>(keyValue), 0, &aniKey);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "Failed to get key Item status: %{public}d", status);
            errorMsg = "The type of args.fds must be Record<string, int>.";
            return false;
        }
        ani_ref aniVal;
        status = env->TupleValue_GetItem_Ref(static_cast<ani_tuple_value>(keyValue), 1, &aniVal);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::PROCESSMGR, "Failed to get key Item status: %{public}d", status);
            errorMsg = "The type of args.fds must be Record<string, int>.";
            return false;
        }
        if (!GetFds(env, static_cast<ani_string>(aniKey), static_cast<ani_object>(aniVal), map)) {
            return false;
        }
    }
    return true;
}

ani_object WrapChildProcessArgs(ani_env* env, ChildProcessArgs &args)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "env null");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class className = nullptr;
    status = env->FindClass(CLASSNAME_CHILDPROCESSARGS, &className);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "FindClass failed status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(className, "<ctor>", ":", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "find method failed status: %{public}d", status);
        return nullptr;
    }
    ani_object object = nullptr;
    status = env->Object_New(className, method, &object);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "new object failed status: %{public}d", status);
        return nullptr;
    }
    status = env->Object_SetPropertyByName_Ref(object, "entryParams", GetAniString(env, args.entryParams));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "set property failed status: %{public}d", status);
        return nullptr;
    }
    if (!SetFds(env, object, args.fds)) {
        return nullptr;
    }
    return object;
}

bool UnwrapChildProcessOptions(ani_env* env, ani_object object, ChildProcessOptions &options, std::string &errorMsg)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "env null");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref isolationModeRef = nullptr;
    ani_boolean isolationModeValue = ANI_FALSE;
    if (GetRefProperty(env, object, "isolationMode", isolationModeRef) &&
        (status = env->Object_CallMethodByName_Boolean(reinterpret_cast<ani_object>(isolationModeRef),
        "valueOf", ":z", &isolationModeValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "parameter error");
        errorMsg = "Parameter error. The type of options.isolationMode must be boolean.";
        return false;
    }
    options.isolationMode = static_cast<bool>(isolationModeValue);
    ani_ref isolationUidRef = nullptr;
    ani_boolean isolationUidValue = ANI_FALSE;
    if (GetRefProperty(env, object, "isolationUid", isolationUidRef) &&
        (status = env->Object_CallMethodByName_Boolean(reinterpret_cast<ani_object>(isolationUidRef),
        "valueOf", ":z", &isolationUidValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::PROCESSMGR, "parameter error");
        errorMsg = "Parameter error. The type of options.isolationUid must be boolean.";
        return false;
    }
    options.isolationUid = static_cast<bool>(isolationUidValue);
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
