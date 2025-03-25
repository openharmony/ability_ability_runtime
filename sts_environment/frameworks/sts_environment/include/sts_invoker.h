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

#ifndef OHOS_ABILITY_RUNTIME_STS_INVOKER_H
#define OHOS_ABILITY_RUNTIME_STS_INVOKER_H

#include "sts_interface.h"
#include <cstddef>
#include <cstdint>
#include <csignal>
#include "ani.h"

namespace OHOS {
using PostTaskType = bool(*)(void*);
using HasHigherPriorityType = bool(*)();

struct STSUncaughtExceptionInfo;

struct STSRuntimeAPI {
    ets_int (*ETS_GetDefaultVMInitArgs)(EtsVMInitArgs *vmArgs);
    ets_int (*ETS_GetCreatedVMs)(EtsVM **vmBuf, ets_size bufLen, ets_size *nVms);
    ani_status (*ANI_GetCreatedVMs)(ani_vm **vms_buffer, ani_size vms_buffer_length, ani_size *result);
    ani_status (*ANI_CreateVM)(const ani_options *options, uint32_t version, ani_vm **result);
};
}
#endif //OHOS_ABILITY_RUNTIME_STS_INVOKER_H
