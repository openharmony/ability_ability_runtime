/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "abilitymanager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "ability_manager_service.h"
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
}
const std::u16string ABILITYMGR_INTERFACE_TOKEN = u"ohos.aafwk.AbilityManager";

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    uint32_t code = GetU32Data(data) % (AbilityManagerInterfaceCode::GET_ABILITY_TOKEN + AbilityManagerInterfaceCode::SET_ROOT_SCENE_SESSION);
    if (code >AbilityManagerInterfaceCode::GET_ABILITY_TOKEN) {
        code = AbilityManagerInterfaceCode::GET_ABILITY_TOKEN;
    } else if (code > AbilityManagerInterfaceCode::SHARE_DATA_DONE && code != AbilityManagerInterfaceCode::GET_ABILITY_TOKEN) {
        code = AbilityManagerInterfaceCode::ACQUIRE_SHARE_DATA +
            (code % (AbilityManagerInterfaceCode::SHARE_DATA_DONE - AbilityManagerInterfaceCode::ACQUIRE_SHARE_DATA + 1));
    } else if (code > AbilityManagerInterfaceCode::VERIFY_PERMISSION) {
        code = AbilityManagerInterfaceCode::GET_TOP_ABILITY +
            (code % (AbilityManagerInterfaceCode::VERIFY_PERMISSION - AbilityManagerInterfaceCode::GET_TOP_ABILITY + 1));
    } else if (code > AbilityManagerInterfaceCode::GET_DLP_CONNECTION_INFOS) {
        code = AbilityManagerInterfaceCode::REGISTER_WMS_HANDLER +
            (code % (AbilityManagerInterfaceCode::GET_DLP_CONNECTION_INFOS - AbilityManagerInterfaceCode::REGISTER_WMS_HANDLER + 1));
    } else if (code > AbilityManagerInterfaceCode::FORCE_TIMEOUT) {
        code = AbilityManagerInterfaceCode::DUMP_STATE +
            (code % (AbilityManagerInterfaceCode::FORCE_TIMEOUT - AbilityManagerInterfaceCode::DUMP_STATE + 1));
    } else if (code > AbilityManagerInterfaceCode::GET_TOP_ABILITY_TOKEN) {
        code = AbilityManagerInterfaceCode::START_ABILITY +
            (code % (AbilityManagerInterfaceCode::GET_TOP_ABILITY_TOKEN - AbilityManagerInterfaceCode::START_ABILITY + 1));
    } else if (code > AbilityManagerInterfaceCode::SET_ROOT_SCENE_SESSION) {
        code = AbilityManagerInterfaceCode::TERMINATE_ABILITY +
            (code % (AbilityManagerInterfaceCode::SET_ROOT_SCENE_SESSION - AbilityManagerInterfaceCode::TERMINATE_ABILITY + 1));
    }

    MessageParcel parcel;
    parcel.WriteInterfaceToken(ABILITYMGR_INTERFACE_TOKEN);
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AbilityManagerService>::GetInstance()->OnRemoteRequest(code, parcel, reply, option);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

