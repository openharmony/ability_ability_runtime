/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_ABILITY_SCHEDULER_FOR_OBESERVER_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_ABILITY_SCHEDULER_FOR_OBESERVER_H

#include "gmock/gmock.h"

#include "ability_scheduler_stub.h"

#include <iremote_object.h>
#include <iremote_stub.h>

namespace OHOS {
namespace AppExecFwk {
// copy AbilityThread class
class MockAbilitySchedulerStub : public AAFwk::AbilitySchedulerStub {
public:
    MockAbilitySchedulerStub() = default;
    virtual ~MockAbilitySchedulerStub() = default;
    MOCK_METHOD3(ScheduleAbilityTransaction, bool(const AAFwk::Want&, const AAFwk::LifeCycleStateInfo&,
        sptr<AAFwk::SessionInfo>));
    MOCK_METHOD1(ScheduleShareData, void(const int32_t &uniqueId));
    MOCK_METHOD3(SendResult, void(int, int, const AAFwk::Want&));
    MOCK_METHOD1(ScheduleConnectAbility, void(const AAFwk::Want&));
    MOCK_METHOD1(ScheduleDisconnectAbility, void(const AAFwk::Want&));
    MOCK_METHOD0(SchedulePrepareTerminateAbility, bool());
    MOCK_METHOD3(ScheduleCommandAbility, void(const AAFwk::Want&, bool, int));
    MOCK_METHOD3(ScheduleCommandAbilityWindow, void(const AAFwk::Want &, const sptr<AAFwk::SessionInfo> &,
        AAFwk::WindowCommand));
    MOCK_METHOD0(ScheduleSaveAbilityState, void());
    MOCK_METHOD1(ScheduleRestoreAbilityState, void(const PacMap&));
    MOCK_METHOD1(ScheduleUpdateConfiguration, void(const AppExecFwk::Configuration&));
    MOCK_METHOD2(GetFileTypes, std::vector<std::string>(const Uri&, const std::string&));
    MOCK_METHOD2(OpenFile, int(const Uri&, const std::string&));
    MOCK_METHOD2(OpenRawFile, int(const Uri&, const std::string&));
    MOCK_METHOD2(Insert, int(const Uri&, const NativeRdb::ValuesBucket&));
    MOCK_METHOD3(Update, int(const Uri&, const NativeRdb::ValuesBucket&, const NativeRdb::DataAbilityPredicates&));
    MOCK_METHOD2(Delete, int(const Uri&, const NativeRdb::DataAbilityPredicates&));
    MOCK_METHOD3(Query, std::shared_ptr<NativeRdb::AbsSharedResultSet>(const Uri&,
        std::vector<std::string>&, const NativeRdb::DataAbilityPredicates&));
    MOCK_METHOD4(Call, std::shared_ptr<PacMap>(const Uri&, const std::string&, const std::string&, const PacMap&));
    MOCK_METHOD1(GetType, std::string(const Uri&));
    MOCK_METHOD2(Reload, bool(const Uri&, const PacMap&));
    MOCK_METHOD2(BatchInsert, int(const Uri&, const std::vector<NativeRdb::ValuesBucket>&));
    MOCK_METHOD1(DenormalizeUri, Uri(const Uri&));
    MOCK_METHOD1(NormalizeUri, Uri(const Uri&));
    MOCK_METHOD2(ScheduleRegisterObserver, bool(const Uri& uri,
        const sptr<AAFwk::IDataAbilityObserver>& dataObserver));
    MOCK_METHOD2(ScheduleUnregisterObserver, bool(const Uri& uri,
        const sptr<AAFwk::IDataAbilityObserver>& dataObserver));
    MOCK_METHOD1(ScheduleNotifyChange, bool(const Uri& uri));
    MOCK_METHOD1(ExecuteBatch, std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>>(
        const std::vector<std::shared_ptr<AppExecFwk::DataAbilityOperation>>& operation));
    MOCK_METHOD1(NotifyContinuationResult, void(int32_t result));
    MOCK_METHOD2(ContinueAbility, void(const std::string& deviceId, uint32_t versionCode));
    MOCK_METHOD2(DumpAbilityInfo, void(const std::vector<std::string>& params, std::vector<std::string>& info));
    virtual void CallRequest()
    {
        return;
    }
    virtual void OnExecuteIntent(const Want &want)
    {
        return;
    }
    virtual int CreateModalUIExtension(const Want &want) override
    {
        return 0;
    }
    virtual void UpdateSessionToken(sptr<IRemoteObject> sessionToken) override {}

    virtual void ScheduleCollaborate(const Want &want) override {}

    virtual void ScheduleAbilityRequestFailure(const std::string &requestId, const AppExecFwk::ElementName &element,
        const std::string &message) override
    {}

    virtual void ScheduleAbilityRequestSuccess(const std::string &requestId,
        const AppExecFwk::ElementName &element) override
    {}

    virtual void ScheduleAbilitiesRequestDone(const std::string &requestKey, int32_t resultCode) override
    {}
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif /* MOCK_OHOS_ABILITY_RUNTIME_MOCK_ABILITY_SCHEDULER_FOR_OBESERVER_H */
