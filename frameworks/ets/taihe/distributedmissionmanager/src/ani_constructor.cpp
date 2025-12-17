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
#include "ohos.distributedmissionmanager.ani.hpp"
#include "ContinueCallback.ani.hpp"
#include "MissionCallbacks.ani.hpp"
#include "ContinuableInfo.ani.hpp"
#include "MissionParameter.ani.hpp"
#include "ContinueDeviceInfo.ani.hpp"
#include "MissionDeviceInfo.ani.hpp"
#include "ContinueMissionInfo.ani.hpp"
#if __has_include(<ani.h>)
#include <ani.h>
#elif __has_include(<ani/ani.h>)
#include <ani/ani.h>
#else
#error "ani.h not found. Please ensure the Ani SDK is correctly installed."
#endif
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        return ANI_ERROR;
    }
    ani_status status = ANI_OK;
    if (ANI_OK != ohos::distributedmissionmanager::ANIRegister(env)) {
        std::cerr << "Error from ohos::data::distributedmissionmanager::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != ContinueCallback::ANIRegister(env)) {
        std::cerr << "Error from ContinueCallback::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != MissionCallbacks::ANIRegister(env)) {
        std::cerr << "Error from MissionCallbacks::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != ContinuableInfo::ANIRegister(env)) {
        std::cerr << "Error from ContinuableInfo::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != MissionParameter::ANIRegister(env)) {
        std::cerr << "Error from MissionParameter::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != ContinueDeviceInfo::ANIRegister(env)) {
        std::cerr << "Error from ContinueDeviceInfo::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != MissionDeviceInfo::ANIRegister(env)) {
        std::cerr << "Error from MissionDeviceInfo::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    if (ANI_OK != ContinueMissionInfo::ANIRegister(env)) {
        std::cerr << "Error from ContinueMissionInfo::ANIRegister" << std::endl;
        status = ANI_ERROR;
    }
    *result = ANI_VERSION_1;
    return status;
}
