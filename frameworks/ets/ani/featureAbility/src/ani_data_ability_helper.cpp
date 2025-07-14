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
#include "ani_data_ability_helper.h"

#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"
namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CLASSNAME_DOUBLE = "Lstd/core/Double;";
constexpr const char* CLASSNAME_BOOL = "Lstd/core/Boolean;";
constexpr const char* CLASSNAME_STRING = "Lstd/core/String;";
constexpr const char* CLASSNAME_ARRAY = "Lescompat/Array;";
}
bool IsInstanceOf(ani_env* env, const char* name, ani_object aniValue)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FA, "env null");
        return false;
    }

    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(name, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf;
    if ((status = env->Object_InstanceOf(aniValue, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FA, "Object_InstanceOf status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

void SetPacMapObject(AppExecFwk::PacMap &pacMap, ani_env* env, std::string keyStr, ani_object aniValue)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FA, "env null");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isNull = ANI_FALSE;
    if ((status = env->Reference_IsNull(aniValue, &isNull)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FA, "Reference_IsNull status: %{public}d", status);
        return;
    }
    if (IsInstanceOf(env, CLASSNAME_DOUBLE, aniValue)) {
        ani_double value = 0;
        if ((status = env->Object_CallMethodByName_Double(aniValue, "doubleValue", nullptr, &value)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FA, "Object_CallMethodByName_Double status: %{public}d", status);
            return;
        }
        pacMap.PutDoubleValue(keyStr, static_cast<double>(value));
    } else if (IsInstanceOf(env, CLASSNAME_BOOL, aniValue)) {
        ani_boolean value = ANI_FALSE;
        if ((status = env->Object_CallMethodByName_Boolean(aniValue, "unboxed", nullptr, &value)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::FA, "Object_CallMethodByName_Boolean status: %{public}d", status);
            return;
        }
        pacMap.PutBooleanValue(keyStr, static_cast<bool>(value));
    } else if (IsInstanceOf(env, CLASSNAME_STRING, aniValue)) {
        ani_string aniString = static_cast<ani_string>(aniValue);
        std::string value = "";
        if (!GetStdString(env, aniString, value)) {
            TAG_LOGE(AAFwkTag::FA, "GetStdString failed");
            return;
        }
        pacMap.PutStringValue(keyStr, value);
    } else if (IsInstanceOf(env, CLASSNAME_ARRAY, aniValue)) {
        std::vector<std::string> stringList;
        if (!UnwrapArrayString(env, aniValue, stringList)) {
            TAG_LOGE(AAFwkTag::FA, "UnwrapArrayString failed");
            return;
        }
        pacMap.PutStringValueArray(keyStr, stringList);
    } else if (isNull) {
        pacMap.PutObject(keyStr, nullptr);
    } else {
        TAG_LOGE(AAFwkTag::FA, "pacMap type error");
    }
}

void AnalysisPacMap(AppExecFwk::PacMap &pacMap, ani_env* env, const ani_object &aniObject)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FA, "env null");
        return;
    }
    ani_ref iter = nullptr;
    ani_status status = ANI_ERROR;
    status = env->Object_CallMethodByName_Ref(aniObject, "$_iterator", nullptr, &iter);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::FA, "Failed to get keys iterator status: %{public}d", status);
        return;
    }
    ani_ref next = nullptr;
    ani_boolean done = ANI_FALSE;
    while (ANI_OK == env->Object_CallMethodByName_Ref(static_cast<ani_object>(iter), "next", nullptr, &next)) {
        status = env->Object_GetFieldByName_Boolean(static_cast<ani_object>(next), "done", &done);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::FA, "Failed to check iterator done status: %{public}d", status);
            return;
        }
        if (done) {
            TAG_LOGD(AAFwkTag::FA, "[forEachMapEntry] done break");
            return;
        }
        ani_ref keyValue = nullptr;
        status = env->Object_GetFieldByName_Ref(static_cast<ani_object>(next), "value", &keyValue);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::FA, "Failed to get key value status: %{public}d", status);
            return;
        }
        ani_ref aniKey = nullptr;
        status = env->TupleValue_GetItem_Ref(static_cast<ani_tuple_value>(keyValue), 0, &aniKey);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::FA, "Failed to get key Item status: %{public}d", status);
            return;
        }
        ani_ref aniVal = nullptr;
        status = env->TupleValue_GetItem_Ref(static_cast<ani_tuple_value>(keyValue), 1, &aniVal);
        if (ANI_OK != status) {
            TAG_LOGE(AAFwkTag::FA, "Failed to get key Item status: %{public}d", status);
            return;
        }
        std::string mapKey = "";
        if (!GetStdString(env, static_cast<ani_string>(aniKey), mapKey)) {
            TAG_LOGE(AAFwkTag::FA, "GetStdString failed");
            return;
        }
        SetPacMapObject(pacMap, env, mapKey, static_cast<ani_object>(aniVal));
    }
}
} // namespace AppExecFwk
} // namespace OHOS