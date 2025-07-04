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

#include "abilityresidentprocessrdb_fuzzer.h"

#include <charconv>
#include <fuzzer/FuzzedDataProvider.h>
#include "hilog_tag_wrapper.h"
#include "parser_util.h"

#define private public
#include "ability_resident_process_rdb.h"
#include "rdb_data_manager.h"
#undef private

using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    struct AmsRdbConfig amsRdbConfig;
    AmsResidentProcessRdbCallBack amsCallback(amsRdbConfig);
    std::unique_ptr<RdbDataManager> rdbMgr =
        std::make_unique<RdbDataManager>(amsRdbConfig);
    rdbMgr->Init(amsCallback);
    int currentVersion;
    int targetVersion;
    std::string databaseFile;
    std::string bundleName;
    bool enable;
    FuzzedDataProvider fdp(data, size);
    currentVersion = fdp.ConsumeIntegral<int32_t>();
    targetVersion = fdp.ConsumeIntegral<int32_t>();
    databaseFile = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    enable = fdp.ConsumeBool();
    amsCallback.OnCreate(*(rdbMgr->rdbStore_.get()));
    amsCallback.OnUpgrade(*(rdbMgr->rdbStore_.get()), currentVersion, targetVersion);
    amsCallback.OnDowngrade(*(rdbMgr->rdbStore_.get()), currentVersion, targetVersion);
    amsCallback.OnOpen(*(rdbMgr->rdbStore_.get()));
    amsCallback.onCorruption(databaseFile);
    AmsResidentProcessRdb::GetInstance().Init();
    AmsResidentProcessRdb::GetInstance().UpdateResidentProcessEnable(bundleName, enable);
    AmsResidentProcessRdb::GetInstance().RemoveData(bundleName);
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

