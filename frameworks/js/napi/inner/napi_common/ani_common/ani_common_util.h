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
#define SETTER_METHOD_NAME(property) "<set>" #property

bool GetIntOrUndefined(ani_env *env, ani_object param, const char *name, int &value);
double GetDoubleOrUndefined(ani_env *env, ani_object param, const char *name);
bool GetBoolOrUndefined(ani_env *env, ani_object param, const char *name);
bool GetStringOrUndefined(ani_env *env, ani_object param, const char *name, std::string &res);
bool GetIntByName(ani_env *env, ani_object param, const char *name, int &value);
bool GetStringArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<std::string> &res);

bool GetStdString(ani_env *env, ani_string str, std::string &res);

ani_string GetAniString(ani_env *env, const std::string &str);
ani_array_ref GetAniArrayString(ani_env *env, const std::vector<std::string> &values);

bool SetFieldString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, const std::string &value);
bool SetFieldDouble(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, double value);
bool SetFieldBoolean(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, bool value);
bool SetFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int value);
bool SetFieldArrayString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, const std::vector<std::string> &values);

void ClassSetter(ani_env* env, ani_class cls, ani_object object, const char* setterName, ...);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ANI_COMMON_UTIL_H
