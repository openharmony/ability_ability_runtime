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
 * See the License for the specific language governing perns and
 * limitations under the License.
 */

#ifndef OHOS_ABILITY_RUNTIME_ANI_COMMON_CHILD_PROCESS_PARAM
#define OHOS_ABILITY_RUNTIME_ANI_COMMON_CHILD_PROCESS_PARAM

#include "ani.h"
#include "child_process_args.h"
#include "child_process_options.h"

namespace OHOS {
namespace AppExecFwk {
bool UnwrapChildProcessArgs(ani_env* env, ani_object object, ChildProcessArgs &args,
    std::string &errorMsg);
bool UnwrapChildProcessFds(ani_env* env, ani_object object, std::map<std::string, int32_t> &map, std::string &errorMsg);
ani_object WrapChildProcessArgs(ani_env* env, ChildProcessArgs &args);
bool UnwrapChildProcessOptions(ani_env* env, ani_object object, ChildProcessOptions &options,
    std::string &errorMsg);
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ANI_COMMON_CHILD_PROCESS_PARAM