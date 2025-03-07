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

int GetIntOrUndefined(ani_env *env, ani_object param, const char *name)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_int res = 0;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    if (isUndefined){
        TAG_LOGE(AAFwkTag::JSNAPI, "%{public}s : undefined", name);
        return res;
    } 
    if ((status = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(obj), "intValue", nullptr, &res)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    return res;
}

bool GetIntByName(ani_env *env, ani_object param, const char *name, int &value)
{
    ani_int res;
    ani_status status;

    status = env->Object_GetFieldByName_Int(param, name, &res);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    value = static_cast<int>(res);
    return true;
}

double GetDoubleOrUndefined(ani_env *env, ani_object param, const char *name)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_double res = 0.0;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    if (isUndefined){
        TAG_LOGE(AAFwkTag::JSNAPI, "%{public}s : undefined", name);
        return res;
    } 
    if ((status = env->Object_CallMethodByName_Double(reinterpret_cast<ani_object>(obj), "doubleValue", nullptr, &res)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    return res;
}

bool GetBoolOrUndefined(ani_env *env, ani_object param, const char *name)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_boolean res = 0.0;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::JSNAPI, "%{public}s : undefined", name);
        return res;
    }
    if ((status = env->Object_CallMethodByName_Boolean(reinterpret_cast<ani_object>(obj), "booleanValue", nullptr, &res)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return res;
    }
    return res;
}

bool GetStringOrUndefined(ani_env *env, ani_object param, const char *name, std::string &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::JSNAPI, "%{public}s : undefined", name);
        return false;
    }
    if (!GetStdString(env, reinterpret_cast<ani_string>(obj), res)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "GetStdString failed");
        return false;
    }
    return true;
}

bool GetStringArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<std::string> &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_size size = 0;
    ani_size i;
    ani_ref ref;
    std::string str;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::JSNAPI, "%{public}s : undefined", name);
        return false;
    }

    if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(obj), &size)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    for (i = 0; i < size; i++) {
        if ((status = env->Array_Get_Ref(reinterpret_cast<ani_array_ref>(obj), i, &ref)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d, index: %{public}zu", status, i);
            return false;
        }

        str = "";
        if (!GetStdString(env, reinterpret_cast<ani_string>(ref), str)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "GetStdString failed, index: %{public}zu", i);
            return false;
        }

        res.push_back(str);
    }

    return true;
}

bool GetStdString(ani_env *env, ani_string str, std::string &res)
{
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    res.resize(sz);
    return true;
}

ani_string GetAniString(ani_env *env, const std::string &str)
{
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_array_ref GetAniArrayString(ani_env *env, const std::vector<std::string> &values)
{
    // ani_size length = values.size();
    ani_array_ref aArrayRef = nullptr;
    // ani_class aStringcls = nullptr;
    // ani_status status = ANI_ERROR;
    // if ((status = env->FindClass("Lstd/core/String;", &aStringcls)) != ANI_OK) {
    //     TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    //     return nullptr;
    // }
    // if ((status = env->Array_New_Ref(aStringcls, length, nullptr, &aArrayRef)) != ANI_OK) {
    //     TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    //     return nullptr;
    // }
    // ani_string aString = nullptr;
    // for (ani_size i = 0; i < length; ++i) {
    //     env->String_NewUTF8(values[i].c_str(), values[i].size(), &aString);
    //     env->Array_Set_Ref(aArrayRef, i, aString);
    // }
    return aArrayRef;
}

bool SetFieldString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, const std::string &value)
{
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);

    TAG_LOGE(AAFwkTag::JSNAPI, "fieldName : %{public}s", fieldName.c_str());

    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    if (value.empty()) {
        ani_ref nullRef = nullptr;
        if ((status = env->GetNull(&nullRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
            return false;
        }
        if ((status = env->Object_SetField_Ref(object, field, nullRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
            return false;
        }
        return true;
    }

    if ((status = env->String_NewUTF8(value.c_str(), value.size(), &string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    
    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    return true;
}


bool SetFieldDouble(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, double value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    status = env->Object_SetField_Double(object, field, value);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldBoolean(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, bool value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    status = env->Object_SetField_Boolean(object, field, value);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    status = env->Object_SetField_Int(object, field, value);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldArrayString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, const std::vector<std::string> &values)
{
    ani_field field = nullptr;
    ani_array_ref array = nullptr;
    ani_class stringCls = nullptr;
    ani_string string = nullptr;
    ani_ref undefinedRef = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    status = env->FindClass("Lstd/core/String;", &stringCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    status = env->GetUndefined(&undefinedRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    status = env->Array_New_Ref(stringCls, values.size(), undefinedRef, &array);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }

    for (size_t i = 0; i < values.size(); ++i) {
        string = nullptr;
        status = env->String_NewUTF8(values[i].c_str(), values[i].size(), &string);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
            return false;
        }
        status = env->Array_Set_Ref(array, i, string);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
            return false;
        }
    }
    status = env->Object_SetField_Ref(object, field, array);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return false;
    }
    return true;
}

void ClassSetter(
    ani_env* env, ani_class cls, ani_object object, const char* setterName, ...)
{
    ani_status status = ANI_ERROR;
    ani_method setter;
    if ((status = env->Class_FindMethod(cls, setterName, nullptr, &setter)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    va_list args;
    va_start(args, setterName);
    if ((status = env->Object_CallMethod_Void_V(object, setter, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
    }
    va_end(args);
}
}  // namespace AppExecFwk
}  // namespace OHOS
