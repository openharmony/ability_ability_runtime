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

#include "ani_common_util.h"

#include <cstring>
#include "hilog_tag_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char* CLASSNAME_DOUBLE = "Lstd/core/Double;";
constexpr const char* CLASSNAME_BOOL = "Lstd/core/Boolean;";
constexpr const char* CLASSNAME_INT = "Lstd/core/Int;";
constexpr const char* CLASSNAME_ARRAY = "Lescompat/Array;";
constexpr const char* CLASSNAME_ASYNC_CALLBACK_WRAPPER = "Lutils/AbilityUtils/AsyncCallbackWrapper;";

bool GetFieldDoubleByName(ani_env *env, ani_object object, const char *name, double &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref field = nullptr;
    if ((status = env->Object_GetFieldByName_Ref(object, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(field, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s: undefined", name);
        return false;
    }
    ani_double aniValue = 0.0;
    if ((status = env->Object_CallMethodByName_Double(
        reinterpret_cast<ani_object>(field), "doubleValue", nullptr, &aniValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    value = static_cast<double>(aniValue);
    return true;
}

bool SetFieldDoubleByName(ani_env *env, ani_class cls, ani_object object, const char *name, double value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_object obj = CreateDouble(env, value);
    if (obj == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "CreateDouble failed");
        return false;
    }
    if ((status = env->Object_SetField_Ref(object, field, reinterpret_cast<ani_ref>(obj))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetFieldBoolByName(ani_env *env, ani_object object, const char *name, bool &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref field = nullptr;
    if ((status = env->Object_GetFieldByName_Ref(object, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(field, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s: undefined", name);
        return false;
    }
    ani_boolean aniValue = ANI_FALSE;
    if ((status = env->Object_CallMethodByName_Boolean(
        reinterpret_cast<ani_object>(field), "booleanValue", nullptr, &aniValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    value = static_cast<bool>(aniValue);
    return true;
}

bool SetFieldBoolByName(ani_env *env, ani_class cls, ani_object object, const char *name, bool value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_SetField_Boolean(object, field, value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetFieldStringByName(ani_env *env, ani_object object, const char *name, std::string &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref field = nullptr;
    if ((status = env->Object_GetFieldByName_Ref(object, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(field, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s: undefined", name);
        return false;
    }
    if (!GetStdString(env, reinterpret_cast<ani_string>(field), value)) {
        TAG_LOGE(AAFwkTag::ANI, "GetStdString failed");
        return false;
    }
    return true;
}

bool SetFieldStringByName(ani_env *env, ani_class cls, ani_object object, const char *name,
    const std::string &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }

    if (value.empty()) {
        ani_ref nullRef = nullptr;
        if ((status = env->GetNull(&nullRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
            return false;
        }
        if ((status = env->Object_SetField_Ref(object, field, nullRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
            return false;
        }
        return true;
    }
    ani_string aniStr = nullptr;
    if ((status = env->String_NewUTF8(value.c_str(), value.size(), &aniStr)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_SetField_Ref(object, field, aniStr)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetFieldIntByName(ani_env *env, ani_object object, const char *name, int &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_int aniInt = 0;
    if ((status = env->Object_GetFieldByName_Int(object, name, &aniInt)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    value = static_cast<int>(aniInt);
    return true;
}

bool SetFieldIntByName(ani_env *env, ani_class cls, ani_object object, const char *name, int value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_SetField_Int(object, field, value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetFieldStringArrayByName(ani_env *env, ani_object object, const char *name, std::vector<std::string> &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref arrayObj = nullptr;
    if ((status = env->Object_GetFieldByName_Ref(object, name, &arrayObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(arrayObj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s: undefined", name);
        return false;
    }
    ani_double length = 0;
    if ((status = env->Object_GetPropertyByName_Double(reinterpret_cast<ani_object>(arrayObj),
        "length", &length)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(reinterpret_cast<ani_object>(arrayObj),
            "$_get", "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::ANI, "status: %{public}d, index: %{public}d", status, i);
            return false;
        }
        std::string str = "";
        if (!GetStdString(env, reinterpret_cast<ani_string>(stringEntryRef), str)) {
            TAG_LOGE(AAFwkTag::ANI, "GetStdString failed, index: %{public}d", i);
            return false;
        }
        value.emplace_back(str);
        TAG_LOGD(AAFwkTag::ANI, "GetStdString index: %{public}d %{public}s", i, str.c_str());
    }
    return true;
}

bool SetFieldArrayStringByName(ani_env *env, ani_class cls, ani_object object, const char *name,
    const std::vector<std::string> &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_class arrayCls = nullptr;
    if ((status = env->FindClass(CLASSNAME_ARRAY, &arrayCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_method arrayCtor = nullptr;
    if ((status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_object arrayObj = nullptr;
    if ((status = env->Object_New(arrayCls, arrayCtor, &arrayObj, value.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    for (size_t i = 0; i < value.size(); i++) {
        ani_string str = nullptr;
        if ((status = env->String_NewUTF8(value[i].c_str(), value[i].size(), &str)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
            return false;
        }
        if ((status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V",
            i, str)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
            return false;
        }
    }
    if ((status = env->Object_SetField_Ref(object, field, arrayObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetFieldRefByName(ani_env *env, ani_object object, const char *name, ani_ref &ref)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Ref(object, name, &ref)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(ref, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s is undefined", name);
        return false;
    }
    return true;
}

bool SetFieldRefByName(ani_env *env, ani_class cls, ani_object object, const char *name, ani_ref value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(cls, name, &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    if ((status = env->Object_SetField_Ref(object, field, value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetStdString(ani_env *env, ani_string str, std::string &value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_size sz = 0;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    value.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, value.data(), value.size(), &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    value.resize(sz);
    return true;
}

ani_string GetAniString(ani_env *env, const std::string &str)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return nullptr;
    }
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_object CreateDouble(ani_env *env, ani_double value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(CLASSNAME_DOUBLE, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return nullptr;
    }
    ani_method ctor = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "D:V", &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, ctor, &obj, value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object CreateBoolean(ani_env *env, ani_boolean value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(CLASSNAME_BOOL, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return nullptr;
    }
    ani_method ctor = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Z:V", &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, ctor, &obj, value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object CreateInt(ani_env *env, ani_int value)
{
    ani_class cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_INT, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "FindClass status : %{public}d", status);
        return nullptr;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor)) != ANI_OK || ctor == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Class_FindMethod status : %{public}d", status);
        return nullptr;
    }
    ani_object object;
    if ((status = env->Object_New(cls, ctor, &object, value)) != ANI_OK || object == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Object_New status : %{public}d", status);
        return nullptr;
    }
    return object;
}

bool SetOptionalFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK || field == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Class_FindField failed or null field, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    ani_object intObj = CreateInt(env, value);
    if (intObj == nullptr) {
        TAG_LOGE(AAFwkTag::JSNAPI, "null intObj");
        return false;
    }
    status = env->Object_SetField_Ref(object, field, intObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Object_SetField_Ref failed, status=%{public}d, fieldName=%{public}s",
            status, fieldName.c_str());
        return false;
    }
    return true;
}

bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(CLASSNAME_ASYNC_CALLBACK_WRAPPER, &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "Class_FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if (error == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        error = reinterpret_cast<ani_object>(nullRef);
    }
    if (result == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        result = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}

bool GetDoubleOrUndefined(ani_env *env, ani_object param, const char *name, ani_double &value)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if  (env == nullptr || param == nullptr || name == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env or param or name");
        return false;
    }

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s : undefined", name);
        return false;
    }
    if ((status = env->Object_CallMethodByName_Double(
        reinterpret_cast<ani_object>(obj), "doubleValue", nullptr, &value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
        return false;
    }
    return true;
}

bool GetStringOrUndefined(ani_env *env, ani_object param, const char *name, std::string &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if (env == nullptr || param == nullptr || name == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env or param or name");
        return false;
    }

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::ANI, "%{public}s : undefined", name);
        return false;
    }
    if (!GetStdString(env, reinterpret_cast<ani_string>(obj), res)) {
        TAG_LOGE(AAFwkTag::ANI, "GetStdString failed");
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
