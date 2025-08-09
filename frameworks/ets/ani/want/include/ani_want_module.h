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

#ifndef OHOS_ABILITY_RUNTIME_ANI_WANT_MODULE_H
#define OHOS_ABILITY_RUNTIME_ANI_WANT_MODULE_H

#include "ani.h"
#include "want_params.h"

namespace OHOS::AppExecFwk {
class EtsWantParams {
public:
    EtsWantParams() = default;
    ~EtsWantParams() = default;

    static ani_long NativeCreate(ani_env *env, ani_object);
    static void NativeDestroy(ani_env *env, ani_object, ani_long nativeWantParams);
    static ani_boolean NativeSetStringParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_string value);
    static ani_boolean NativeSetDoubleParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_double value);
    static ani_boolean NativeSetIntParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_int value);
    static ani_boolean NativeSetLongParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_long value);
    static ani_boolean NativeSetBooleanParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_boolean value);
    static ani_boolean NativeSetWantParams(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_long value);

    static ani_boolean NativeSetArrayStringParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_object value);
    static ani_boolean NativeSetArrayDoubleParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_object value);
    static ani_boolean NativeSetArrayIntParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_object value);
    static ani_boolean NativeSetArrayLongParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_object value);
    static ani_boolean NativeSetArrayBooleanParam(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_object value);
    static ani_boolean NativeSetArrayWantParams(ani_env *env, ani_object, ani_long nativeWantParams, ani_string key,
        ani_object value);

    static ani_boolean NativeSetRemoteObjectParam(ani_env *env, ani_object, ani_long nativeWantParams,
        ani_string key, ani_object value);

private:
    static bool SetArrayString(ani_env *env, const std::string &key, ani_object value,
        AAFwk::WantParams& wantParams);
    static bool SetArrayDouble(ani_env *env, const std::string &key, ani_object value,
        AAFwk::WantParams& wantParams);
    static bool SetArrayInt(ani_env *env, const std::string &key, ani_object value,
        AAFwk::WantParams& wantParams);
    static bool SetArrayLong(ani_env *env, const std::string &key, ani_object value,
        AAFwk::WantParams& wantParams);
    static bool SetArrayBoolean(ani_env *env, const std::string &key, ani_object value,
        AAFwk::WantParams& wantParams);
    static bool SetArrayWantParams(ani_env *env, const std::string &key, ani_object value,
        AAFwk::WantParams& wantParams);
};
} // namespace OHOS::AppExecFwk
#endif // OHOS_ABILITY_RUNTIME_ANI_WANT_MODULE_H
