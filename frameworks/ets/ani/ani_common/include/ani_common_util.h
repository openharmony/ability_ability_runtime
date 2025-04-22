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

#ifndef OHOS_ABILITY_RUNTIME_ANI_COMMON_UTIL_H
#define OHOS_ABILITY_RUNTIME_ANI_COMMON_UTIL_H

#include "sts_runtime.h"
namespace OHOS {
namespace AppExecFwk {

bool GetDoubleOrUndefined(ani_env *env, ani_object param, const char *name, ani_double &value);
bool GetBoolOrUndefined(ani_env *env, ani_object param, const char *name);
bool GetStringOrUndefined(ani_env *env, ani_object param, const char *name, std::string &res);
bool GetIntByName(ani_env *env, ani_object param, const char *name, int &value);
bool GetStringArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<std::string> &res);

bool GetStdString(ani_env *env, ani_string str, std::string &res);

ani_string GetAniString(ani_env *env, const std::string &str);
bool GetRefFieldByName(ani_env *env, ani_object param, const char *name, ani_ref &ref);

ani_object createDouble(ani_env *env, ani_double value);
ani_object createBoolean(ani_env *env, ani_boolean value);
ani_object createInt(ani_env *env, ani_int value);
ani_object createLong(ani_env *env, ani_long value);
bool SetFieldString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, const std::string &value);
bool SetFieldBoolean(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, bool value);
bool SetFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int value);
bool SetOptionalFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int value);
bool SetFieldArrayString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, const std::vector<std::string> &values);
bool SetFieldRef(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, ani_ref value);
bool AniStringToStdString(ani_env *env, ani_string aniString, std::string &stdString);

bool GetPropertyRef(ani_env *env, ani_object obj, const char *name, ani_ref &ref, ani_boolean &isUndefined);
bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ANI_COMMON_UTIL_H
