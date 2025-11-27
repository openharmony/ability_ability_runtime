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
#ifndef OHOS_ANI_UTILS_H
#define OHOS_ANI_UTILS_H

#include <memory>
#include <map>
#include <string>
#include "taihe/runtime.hpp"

namespace ani_utils {

ani_status AniCreateInt(ani_env* env, int32_t value, ani_object& result);
void AniExecuteFunc(ani_vm* vm, const std::function<void(ani_env*)> func);

} //namespace ani_utils
#endif

