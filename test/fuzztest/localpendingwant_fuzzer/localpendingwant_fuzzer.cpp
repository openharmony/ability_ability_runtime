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

#include "localpendingwant_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "local_pending_want.h"
#include "parcel.h"

using namespace OHOS::AbilityRuntime::WantAgent;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
const std::string GET_BUNDLE_INFO_PERMISSION = "ohos.permission.GET_BUNDLE_INFO";
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::string bundleName;
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    int32_t operType;
    sptr<CompletedDispatcher> callBack;
    std::shared_ptr<AAFwk::WantParams> extraInfo;
    Parcel paramsParcel;
    FuzzedDataProvider fdp(data, size);
    paramsParcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    paramsParcel.WriteInt32(fdp.ConsumeIntegral<int32_t>());
    AAFwk::WantParams* params = AAFwk::WantParams::Unmarshalling(paramsParcel);
    if (params) {
        extraInfo = std::make_shared<AAFwk::WantParams>(*params);
    }
    TriggerInfo paramsInfo(GET_BUNDLE_INFO_PERMISSION, extraInfo, want, 0);
    sptr<IRemoteObject> callerToken;
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    operType = fdp.ConsumeIntegral<int32_t>();
    LocalPendingWant localPendingWant = LocalPendingWant(bundleName, want, operType);
    localPendingWant.GetBundleName();
    localPendingWant.SetBundleName(bundleName);
    localPendingWant.GetUid();
    localPendingWant.GetType();
    localPendingWant.SetType(operType);
    localPendingWant.GetWant();
    localPendingWant.SetWant(want);
    localPendingWant.GetHashCode();
    localPendingWant.GetTokenId();
    localPendingWant.Send(callBack, paramsInfo, callerToken);
    localPendingWant.Marshalling(paramsParcel);
    std::shared_ptr<LocalPendingWant> localWant = std::make_shared<LocalPendingWant>(bundleName, want, operType);
    std::shared_ptr<LocalPendingWant> otherWant = std::make_shared<LocalPendingWant>(bundleName, want, operType);
    localPendingWant.IsEquals(localWant, otherWant);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}