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

#ifndef OHOS_ABILITY_RUNTIME_ANICOMMON_WANT_H
#define OHOS_ABILITY_RUNTIME_ANICOMMON_WANT_H

#include <map>
#include <string>
#include <vector>

#include "native_engine/native_engine.h"
#include "sts_runtime.h"
#include "want.h"
#include "want_params.h"

namespace OHOS {
namespace AppExecFwk {

ani_object WrapWant(ani_env *env, const AAFwk::Want &want);
ani_object WrapWantParams(ani_env *env, ani_class cls, const AAFwk::WantParams &wantParams);

bool UnwrapWant(ani_env *env, ani_object param, AAFwk::Want &want);

std::string GetStdString(ani_env *env, ani_string str);
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ANICOMMON_WANT_H
