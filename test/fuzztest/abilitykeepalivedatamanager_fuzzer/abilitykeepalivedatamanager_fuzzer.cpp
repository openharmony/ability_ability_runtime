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

#include "abilitykeepalivedatamanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ability_keep_alive_data_manager.h"
#undef private

#include "ability_fuzz_util.h"
#include "distributed_kv_data_manager.h"
#include "keep_alive_info.h"

using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    DistributedKv::Status status;
    KeepAliveStatus aliveStatus;
    KeepAliveInfo info;
    std::vector<KeepAliveInfo> infoList;
    FuzzedDataProvider fdp(data, size);
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, STRING_MAX_LENGTH);
    for (size_t i = 0; i < arraySize; ++i) {
        AbilityFuzzUtil::GetRandomKeepAliveInfo(fdp, info);
        infoList.emplace_back(info);
    }
    status = DistributedKv::Status::DATA_CORRUPTED;
    AbilityKeepAliveDataManager::GetInstance().RestoreKvStore(status);
    status = DistributedKv::Status::SUCCESS;
    AbilityKeepAliveDataManager::GetInstance().RestoreKvStore(status);
    AbilityKeepAliveDataManager::GetInstance().GetKvStore();
    AbilityKeepAliveDataManager::GetInstance().CheckKvStore();
    info.appType = KeepAliveAppType::UNSPECIFIED;
    AbilityKeepAliveDataManager::GetInstance().InsertKeepAliveData(info);
    AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveData(info);
    AbilityKeepAliveDataManager::GetInstance().QueryKeepAliveApplications(info, infoList);
    AbilityKeepAliveDataManager::GetInstance().DeleteKeepAliveData(info);
    AbilityKeepAliveDataManager::GetInstance().DeleteKeepAliveDataWithSetterId(info);
    AbilityKeepAliveDataManager::GetInstance().ConvertKeepAliveStatusToValue(info);
    DistributedKv::Value value;
    AbilityFuzzUtil::GetRandomKeepAliveStatus(fdp, aliveStatus);
    AbilityKeepAliveDataManager::GetInstance().ConvertKeepAliveStatusFromValue(value, aliveStatus);
    DistributedKv::Key key;
    AbilityKeepAliveDataManager::GetInstance().ConvertKeepAliveInfoFromKey(key);
    AbilityKeepAliveDataManager::GetInstance().IsEqualSetterId(key, info);
    AbilityKeepAliveDataManager::GetInstance().IsEqual(key, info);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}