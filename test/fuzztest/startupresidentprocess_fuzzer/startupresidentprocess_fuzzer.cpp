/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "startupresidentprocess_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_record.h"
#include "app_mgr_client.h"
#include "configuration.h"
#include "parcel.h"
#include "securec.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::shared_ptr<AppMgrClient> appMgrClient = std::make_shared<AppMgrClient>();
    if (!appMgrClient) {
        return false;
    }

    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    std::string stringData = fdp->ConsumeRandomLengthString();
    Parcel parcel;
    parcel.WriteString(stringData);
    sptr<AppExecFwk::BundleInfo> bundleInfo = AppExecFwk::BundleInfo::Unmarshalling(parcel);
    bundleInfos.emplace_back(*bundleInfo);
    appMgrClient->StartupResidentProcess(bundleInfos);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

