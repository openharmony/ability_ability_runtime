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

#include "ani_want_module.h"

#include "ani_common_util.h"
#include "ani_remote_object.h"
#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "double_wrapper.h"
#include "hilog_tag_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "long_wrapper.h"
#include "remote_object_wrapper.h"
#include "string_wrapper.h"
#include "tokenid_kit.h"
#include "want_params.h"
#include "want_params_wrapper.h"

namespace OHOS::AppExecFwk {
namespace {
constexpr const char *ETS_NATIVE_WANT_PARAMS_CLASS_NAME = "L@ohos/app/ability/Want/NativeWantParams;";
constexpr const char *ETS_NATIVE_WANT_PARAMS_CLEANER_CLASS_NAME = "L@ohos/app/ability/Want/NativeWantParamsCleaner;";
} // namespace

ani_long EtsWantParams::NativeCreate(ani_env *env, ani_object)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return 0;
    }
    auto *params = new(std::nothrow) AAFwk::WantParams();
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null params");
        return 0;
    }

    return reinterpret_cast<ani_long>(params);
}

void EtsWantParams::NativeDestroy(ani_env *env, ani_object, ani_long nativeWantParams)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return;
    }

    delete params;
}

ani_boolean EtsWantParams::NativeSetStringParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
    ani_string value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }
    std::string valueString;
    if (!GetStdString(env, value, valueString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }
    params->SetParam(keyString, AAFwk::String::Box(valueString));
    return true;
}

ani_boolean EtsWantParams::NativeSetDoubleParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
    ani_double value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    params->SetParam(keyString, AAFwk::Double::Box(value));
    return true;
}

ani_boolean EtsWantParams::NativeSetIntParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
    ani_int value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    params->SetParam(keyString, AAFwk::Integer::Box(value));
    return true;
}

ani_boolean EtsWantParams::NativeSetLongParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
    ani_long value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    params->SetParam(keyString, AAFwk::Long::Box(value));
    return true;
}

ani_boolean EtsWantParams::NativeSetBooleanParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
    ani_boolean value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    params->SetParam(keyString, AAFwk::Boolean::Box(value));
    return true;
}

ani_boolean EtsWantParams::NativeSetWantParams(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
    ani_long value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    auto *valueWantParams = reinterpret_cast<AAFwk::WantParams *>(value);
    if (valueWantParams == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null valueWantParams");
        return false;
    }

    params->SetParam(keyString, AAFwk::WantParamWrapper::Box(*valueWantParams));
    return true;
}

bool EtsWantParams::SetArrayString(ani_env *env, const std::string &key, ani_object value,
    AAFwk::WantParams &wantParams)
{
    ani_boolean isUndefined = true;
    ani_status status = env->Reference_IsUndefined(value, &isUndefined);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Reference_IsUndefined status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::WANT, "value is undefined");
        return false;
    }

    ani_double valLength = 0.0;
    status = env->Object_GetPropertyByName_Double(value, "length", &valLength);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Object_GetPropertyByName_Double status: %{public}d", status);
        return false;
    }
    int32_t length = static_cast<int32_t>(valLength);
    sptr<AAFwk::IArray> ao = sptr<AAFwk::Array>::MakeSptr(length, AAFwk::g_IID_IString);

    for (int i = 0; i < length; i++) {
        ani_ref itemRef;
        status = env->Object_CallMethodByName_Ref(value, "$_get", "I:Lstd/core/Object;", &itemRef, i);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::WANT, "status: %{public}d, index: %{public}d", status, i);
            return false;
        }

        std::string item;
        if (!GetStdString(env, reinterpret_cast<ani_string>(itemRef), item)) {
            TAG_LOGE(AAFwkTag::WANT, "GetStdString failed, index: %{public}d", i);
            return false;
        }
        ao->Set(i, AAFwk::String::Box(item));
    }
    wantParams.SetParam(key, ao);
    return true;
}

ani_boolean EtsWantParams::NativeSetArrayStringParam(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    return SetArrayString(env, keyString, value, *params);
}

bool EtsWantParams::SetArrayDouble(ani_env *env, const std::string &key, ani_object value,
    AAFwk::WantParams &wantParams)
{
    ani_boolean isUndefined = true;
    ani_status status = env->Reference_IsUndefined(value, &isUndefined);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Reference_IsUndefined status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::WANT, "value is undefined");
        return false;
    }

    ani_double valLength = 0.0;
    status = env->Object_GetPropertyByName_Double(value, "length", &valLength);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Object_GetPropertyByName_Double status: %{public}d", status);
        return false;
    }
    int32_t length = static_cast<int32_t>(valLength);

    auto array = reinterpret_cast<ani_array_double>(value);
    std::vector<ani_double> nativeArray(length);
    status = env->Array_GetRegion_Double(array, 0, length, nativeArray.data());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Array_GetRegion_Double status: %{public}d", status);
        return false;
    }

    sptr<AAFwk::IArray> ao = sptr<AAFwk::Array>::MakeSptr(length, AAFwk::g_IID_IDouble);
    for (int i = 0; i < length; i++) {
        ao->Set(i, AAFwk::Double::Box(nativeArray[i]));
    }
    wantParams.SetParam(key, ao);
    return true;
}

ani_boolean EtsWantParams::NativeSetArrayDoubleParam(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    return SetArrayDouble(env, keyString, value, *params);
}

bool EtsWantParams::SetArrayInt(ani_env *env, const std::string &key, ani_object value,
    AAFwk::WantParams &wantParams)
{
    ani_boolean isUndefined = true;
    ani_status status = env->Reference_IsUndefined(value, &isUndefined);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Reference_IsUndefined status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::WANT, "value is undefined");
        return false;
    }

    ani_double valLength = 0.0;
    status = env->Object_GetPropertyByName_Double(value, "length", &valLength);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Object_GetPropertyByName_Double status: %{public}d", status);
        return false;
    }
    int32_t length = static_cast<int32_t>(valLength);

    auto array = reinterpret_cast<ani_array_int>(value);
    std::vector<ani_int> nativeArray(length);
    status = env->Array_GetRegion_Int(array, 0, length, nativeArray.data());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Array_GetRegion_Int status: %{public}d", status);
        return false;
    }

    sptr<AAFwk::IArray> ao = sptr<AAFwk::Array>::MakeSptr(length, AAFwk::g_IID_IInteger);
    for (int i = 0; i < length; i++) {
        ao->Set(i, AAFwk::Integer::Box(nativeArray[i]));
    }
    wantParams.SetParam(key, ao);
    return true;
}

ani_boolean EtsWantParams::NativeSetArrayIntParam(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    return SetArrayInt(env, keyString, value, *params);
}

bool EtsWantParams::SetArrayLong(ani_env *env, const std::string &key, ani_object value,
    AAFwk::WantParams &wantParams)
{
    ani_boolean isUndefined = true;
    ani_status status = env->Reference_IsUndefined(value, &isUndefined);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Reference_IsUndefined status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::WANT, "value is undefined");
        return false;
    }

    ani_double valLength = 0.0;
    status = env->Object_GetPropertyByName_Double(value, "length", &valLength);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Object_GetPropertyByName_Double status: %{public}d", status);
        return false;
    }
    int32_t length = static_cast<int32_t>(valLength);

    auto array = reinterpret_cast<ani_array_long>(value);
    std::vector<ani_long> nativeArray(length);
    status = env->Array_GetRegion_Long(array, 0, length, nativeArray.data());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Array_GetRegion_Long status: %{public}d", status);
        return false;
    }

    sptr<AAFwk::IArray> ao = sptr<AAFwk::Array>::MakeSptr(length, AAFwk::g_IID_ILong);
    for (int i = 0; i < length; i++) {
        ao->Set(i, AAFwk::Long::Box(nativeArray[i]));
    }
    wantParams.SetParam(key, ao);
    return true;
}

ani_boolean EtsWantParams::NativeSetArrayLongParam(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    return SetArrayLong(env, keyString, value, *params);
}

bool EtsWantParams::SetArrayBoolean(ani_env *env, const std::string &key, ani_object value,
    AAFwk::WantParams &wantParams)
{
    ani_boolean isUndefined = true;
    ani_status status = env->Reference_IsUndefined(value, &isUndefined);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Reference_IsUndefined status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::WANT, "value is undefined");
        return false;
    }

    ani_double valLength = 0.0;
    status = env->Object_GetPropertyByName_Double(value, "length", &valLength);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Object_GetPropertyByName_Double status: %{public}d", status);
        return false;
    }
    int32_t length = static_cast<int32_t>(valLength);

    auto array = reinterpret_cast<ani_array_boolean>(value);
    std::vector<ani_boolean> nativeArray(length);
    status = env->Array_GetRegion_Boolean(array, 0, length, nativeArray.data());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Array_GetRegion_Boolean status: %{public}d", status);
        return false;
    }

    sptr<AAFwk::IArray> ao = sptr<AAFwk::Array>::MakeSptr(length, AAFwk::g_IID_IBoolean);
    for (int i = 0; i < length; i++) {
        ao->Set(i, AAFwk::Boolean::Box(nativeArray[i]));
    }
    wantParams.SetParam(key, ao);
    return true;
}

ani_boolean EtsWantParams::NativeSetArrayBooleanParam(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    return SetArrayBoolean(env, keyString, value, *params);
}

bool EtsWantParams::SetArrayWantParams(ani_env *env, const std::string &key, ani_object value,
    AAFwk::WantParams &wantParams)
{
    ani_boolean isUndefined = true;
    ani_status status = env->Reference_IsUndefined(value, &isUndefined);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Reference_IsUndefined status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        TAG_LOGE(AAFwkTag::WANT, "value is undefined");
        return false;
    }

    ani_double valLength = 0.0;
    status = env->Object_GetPropertyByName_Double(value, "length", &valLength);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Object_GetPropertyByName_Double status: %{public}d", status);
        return false;
    }
    int32_t length = static_cast<int32_t>(valLength);

    auto array = reinterpret_cast<ani_array_long>(value);
    std::vector<ani_long> nativeArray(length);
    status = env->Array_GetRegion_Long(array, 0, length, nativeArray.data());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Array_GetRegion_Long status: %{public}d", status);
        return false;
    }

    sptr<AAFwk::IArray> ao = sptr<AAFwk::Array>::MakeSptr(length, AAFwk::g_IID_IWantParams);
    for (int i = 0; i < length; i++) {
        auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeArray[i]);
        if (params == nullptr) {
            TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
            return false;
        }
        ao->Set(i, AAFwk::WantParamWrapper::Box(*params));
    }
    wantParams.SetParam(key, ao);
    return true;
}

ani_boolean EtsWantParams::NativeSetArrayWantParams(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    return SetArrayWantParams(env, keyString, value, *params);
}

ani_boolean EtsWantParams::NativeSetRemoteObjectParam(ani_env *env, ani_object, ani_long nativeWantParams,
    ani_string key, ani_object value)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null env");
        return false;
    }

    auto selfToken = IPCSkeleton::GetSelfTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        TAG_LOGW(AAFwkTag::WANT, "not system app");
        return false;
    }

    auto *params = reinterpret_cast<AAFwk::WantParams *>(nativeWantParams);
    if (params == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null nativeWantParams");
        return false;
    }

    std::string keyString;
    if (!GetStdString(env, key, keyString)) {
        TAG_LOGE(AAFwkTag::WANT, "get key failed");
        return false;
    }

    auto remoteObject = AniGetNativeRemoteObject(env, value);
    if (remoteObject == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null remoteObject");
        return false;
    }
    params->SetParam(keyString, AAFwk::RemoteObjectWrap::Box(remoteObject));
    return true;
}

ani_status BindNativeFunctions(ani_env *aniEnv)
{
    TAG_LOGD(AAFwkTag::WANT, "call");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null ani env");
        return ANI_INVALID_ARGS;
    }

    ani_class nativeWantParamsCls = nullptr;
    auto status = aniEnv->FindClass(ETS_NATIVE_WANT_PARAMS_CLASS_NAME, &nativeWantParamsCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "FindClass NativeWantParams failed status: %{public}d", status);
        return status;
    }

    std::array nativeFuncs = {
        ani_native_function{
            "nativeCreate", ":J",
            reinterpret_cast<void *>(EtsWantParams::NativeCreate)
        },
        ani_native_function{
            "nativeSetStringParam", "JLstd/core/String;Lstd/core/String;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetStringParam)
        },
        ani_native_function{
            "nativeSetDoubleParam", "JLstd/core/String;D:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetDoubleParam)
        },
        ani_native_function{
            "nativeSetIntParam", "JLstd/core/String;I:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetIntParam)
        },
        ani_native_function{
            "nativeSetLongParam", "JLstd/core/String;J:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetLongParam)
        },
        ani_native_function{
            "nativeSetBooleanParam", "JLstd/core/String;Z:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetBooleanParam)
        },
        ani_native_function{
            "nativeSetWantParams", "JLstd/core/String;J:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetWantParams)
        },
        ani_native_function{
            "nativeSetArrayStringParam", "JLstd/core/String;Lescompat/Array;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetArrayStringParam)
        },
        ani_native_function{
            "nativeSetArrayDoubleParam", "JLstd/core/String;Lescompat/Array;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetArrayDoubleParam)
        },
        ani_native_function{
            "nativeSetArrayIntParam", "JLstd/core/String;Lescompat/Array;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetArrayIntParam)
        },
        ani_native_function{
            "nativeSetArrayLongParam", "JLstd/core/String;Lescompat/Array;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetArrayLongParam)
        },
        ani_native_function{
            "nativeSetArrayBooleanParam", "JLstd/core/String;Lescompat/Array;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetArrayBooleanParam)
        },
        ani_native_function{
            "nativeSetArrayWantParams", "JLstd/core/String;Lescompat/Array;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetArrayWantParams)
        },
        ani_native_function{
            "nativeSetRemoteObjectParam", "JLstd/core/String;L@ohos/rpc/rpc/RemoteObject;:Z",
            reinterpret_cast<void *>(EtsWantParams::NativeSetRemoteObjectParam)
        },
    };
    status = aniEnv->Class_BindNativeMethods(nativeWantParamsCls, nativeFuncs.data(), nativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Class_BindNativeMethods failed status: %{public}d", status);
        return status;
    }

    ani_class nativeWantParamsCleanerCls = nullptr;
    status = aniEnv->FindClass(ETS_NATIVE_WANT_PARAMS_CLEANER_CLASS_NAME, &nativeWantParamsCleanerCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "FindClass NativeWantParams failed status: %{public}d", status);
        return status;
    }
    std::array cleanerNativeFuncs = {
        ani_native_function{
            "nativeDestroy", "J:V",
            reinterpret_cast<void *>(EtsWantParams::NativeDestroy)
        },
    };
    status = aniEnv->Class_BindNativeMethods(nativeWantParamsCleanerCls, cleanerNativeFuncs.data(),
        cleanerNativeFuncs.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "Class_BindNativeMethods failed status: %{public}d", status);
        return status;
    }
    return ANI_OK;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::WANT, "ANI_Constructor");
    ani_env *env = nullptr;
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "null vm");
        return ANI_NOT_FOUND;
    }
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::WANT, "GetEnv failed status: %{public}d, or null env", status);
        return status;
    }
    if ((status = BindNativeFunctions(env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANT, "BindNativeFunctions failed status: %{public}d", status);
        return status;
    }
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace OHOS::AppExecFwk
