/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_ABILITY_SCHEDULER_H
#define MOCK_OHOS_ABILITY_RUNTIME_ABILITY_SCHEDULER_H

#include "ability_scheduler_stub.h"
#include "ability_record.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class AbilityScheduler
 * AbilityScheduler is used to schedule ability kit lifecycle.
 */
class AbilityScheduler : public AbilitySchedulerStub, virtual RefBase {
public:
    AbilityScheduler();
    virtual ~AbilityScheduler();

     /*
     * ScheduleAbilityTransaction,  schedule ability to transform life state.
     *
     * @param Want, Special Want for service type's ability.
     * @param targetState, The lifecycle state to be transformed
     * @param sessionInfo, The session info
     */
    bool ScheduleAbilityTransaction(const Want& want, const LifeCycleStateInfo& targetState,
        sptr<SessionInfo> sessionInfo = nullptr) override;

    /*
     * ScheduleShareData,  schedule ability to share data.
     *
     * @param uniqueId, Indicates the uniqueId returned after the ability is started.
     */
    void ScheduleShareData(const int32_t &uniqueId) override;

    /*
     * SendResult, Send result to app when ability is terminated with result want.
     *
     * @param requestCode, the requestCode of the ability to start.
     * @param resultCode, the resultCode of the ability to terminate.
     * @param resultWant, the want of the ability to terminate.
     */
    void SendResult(int requestCode, int resultCode, const Want& resultWant) override;

    const AbilityResult& GetResult() const;

    /*
     * ScheduleConnectAbility,  schedule service ability to connect.
     *
     * @param want, Special Want for service type's ability.
     */
    void ScheduleConnectAbility(const Want& want) override;

    /*
     * ScheduleDisconnectAbility, schedule service ability to disconnect.
     */
    void ScheduleDisconnectAbility(const Want& want) override;

    bool SchedulePrepareTerminateAbility() override;

    /*
     * ScheduleCommandAbility, schedule service ability to command.
     */
    void ScheduleCommandAbility(const Want& want, bool restart, int startId) override;

    void ScheduleCommandAbilityWindow(const Want &want, const sptr<SessionInfo> &sessionInfo,
        WindowCommand winCmd) override;

    void ScheduleSaveAbilityState() override;

    void ScheduleRestoreAbilityState(const PacMap& inState) override;

    /**
     * @brief Obtains the MIME types of files supported.
     *
     * @param uri Indicates the path of the files to obtain.
     * @param mimeTypeFilter Indicates the MIME types of the files to obtain. This parameter cannot be null.
     *
     * @return Returns the matched MIME types. If there is no match, null is returned.
     */
    std::vector<std::string> GetFileTypes(const Uri& uri, const std::string& mimeTypeFilter) override;

    /**
     * @brief Opens a file in a specified remote path.
     *
     * @param uri Indicates the path of the file to open.
     * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
     * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
     * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing data,
     *  or "rwt" for read and write access that truncates any existing file.
     *
     * @return Returns the file descriptor.
     */
    int OpenFile(const Uri& uri, const std::string& mode) override;

    /**
     * @brief Inserts a single data record into the database.
     *
     * @param uri Indicates the path of the data to operate.
     * @param value  Indicates the data record to insert. If this parameter is null, a blank row will be inserted.
     *
     * @return Returns the index of the inserted data record.
     */
    int Insert(const Uri& uri, const NativeRdb::ValuesBucket& value) override;

    /**
     * @brief Updates data records in the database.
     *
     * @param uri Indicates the path of data to update.
     * @param value Indicates the data to update. This parameter can be null.
     * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
     *
     * @return Returns the number of data records updated.
     */
    int Update(const Uri& uri, const NativeRdb::ValuesBucket& value,
        const NativeRdb::DataAbilityPredicates& predicates) override;

    /**
     * @brief Deletes one or more data records from the database.
     *
     * @param uri Indicates the path of the data to operate.
     * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
     *
     * @return Returns the number of data records deleted.
     */
    int Delete(const Uri& uri, const NativeRdb::DataAbilityPredicates& predicates) override;

    /**
     * @brief Deletes one or more data records from the database.
     *
     * @param uri Indicates the path of data to query.
     * @param columns Indicates the columns to query. If this parameter is null, all columns are queried.
     * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
     *
     * @return Returns the query result.
     */
    std::shared_ptr<NativeRdb::AbsSharedResultSet> Query(
        const Uri& uri, std::vector<std::string>& columns, const NativeRdb::DataAbilityPredicates& predicates) override;

    /**
     * @brief Calls the method of the Data ability.
     *
     * @param uri Indicates the Data ability of the method to call.
     * @param method Indicates the method to call.
     * @param arg Indicates the parameter of the String type.
     * @param pacMap Defines a PacMap object for storing a series of values.
     *
     * @return Returns the call result.
     */
    std::shared_ptr<AppExecFwk::PacMap> Call(
        const Uri& uri, const std::string& method, const std::string& arg, const AppExecFwk::PacMap& pacMap) override;

    std::string GetType(const Uri& uri) override;

    /**
     * @brief This is like openFile, open a file that need to be able to return sub-sections of files，often assets
     * inside of their .hap.
     *
     * @param uri Indicates the path of the file to open.
     * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
     * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
     * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing
     * data, or "rwt" for read and write access that truncates any existing file.
     *
     * @return Returns the RawFileDescriptor object containing file descriptor.
     */
    int OpenRawFile(const Uri& uri, const std::string& mode) override;

    /**
     * @brief Reloads data in the database.
     *
     * @param uri Indicates the position where the data is to reload. This parameter is mandatory.
     * @param extras Indicates the PacMap object containing the additional parameters to be passed in this call. This
     * parameter can be null. If a custom Sequenceable object is put in the PacMap object and will be transferred across
     * processes, you must call BasePacMap.setClassLoader(ClassLoader) to set a class loader for the custom object.
     *
     * @return Returns true if the data is successfully reloaded; returns false otherwise.
     */
    bool Reload(const Uri& uri, const PacMap& extras) override;

    /**
     * @brief Inserts multiple data records into the database.
     *
     * @param uri Indicates the path of the data to operate.
     * @param values Indicates the data records to insert.
     *
     * @return Returns the number of data records inserted.
     */
    int BatchInsert(const Uri& uri, const std::vector<NativeRdb::ValuesBucket>& values) override;

    /**
     * @brief Converts the given uri that refer to the Data ability into a normalized URI. A normalized URI can be used
     * across devices, persisted, backed up, and restored. It can refer to the same item in the Data ability even if the
     * context has changed. If you implement URI normalization for a Data ability, you must also implement
     * denormalizeUri(ohos.utils.net.Uri) to enable URI denormalization. After this feature is enabled, URIs passed to
     * any method that is called on the Data ability must require normalization verification and denormalization. The
     * default implementation of this method returns null, indicating that this Data ability does not support URI
     * normalization.
     *
     * @param uri Indicates the Uri object to normalize.
     *
     * @return Returns the normalized Uri object if the Data ability supports URI normalization; returns null otherwise.
     */
    Uri NormalizeUri(const Uri& uri) override;

    /**
     * @brief Converts the given normalized uri generated by normalizeUri(ohos.utils.net.Uri) into a denormalized one.
     * The default implementation of this method returns the original URI passed to it.
     *
     * @param uri uri Indicates the Uri object to denormalize.
     *
     * @return Returns the denormalized Uri object if the denormalization is successful; returns the original Uri passed
     * to this method if there is nothing to do; returns null if the data identified by the original Uri cannot be found
     * in the current environment.
     */
    Uri DenormalizeUri(const Uri& uri) override;

    /**
     * @brief Registers an observer to DataObsMgr specified by the given Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     * @param dataObserver, Indicates the IDataAbilityObserver object.
     *
     * @return Return true if success. otherwise return false.
     */
    virtual bool ScheduleRegisterObserver(const Uri& uri, const sptr<IDataAbilityObserver>& dataObserver) override
    {
        return true;
    };

    /**
     * @brief Deregisters an observer used for DataObsMgr specified by the given Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     * @param dataObserver, Indicates the IDataAbilityObserver object.
     *
     * @return Return true if success. otherwise return false.
     */
    virtual bool ScheduleUnregisterObserver(const Uri& uri, const sptr<IDataAbilityObserver>& dataObserver) override
    {
        return true;
    };

    /**
     * @brief Notifies the registered observers of a change to the data resource specified by Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     *
     * @return Return true if success. otherwise return false.
     */
    virtual bool ScheduleNotifyChange(const Uri& uri) override
    {
        return true;
    };
    virtual std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>> ExecuteBatch(
        const std::vector<std::shared_ptr<AppExecFwk::DataAbilityOperation>>& operations) override
    {
        return std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>>();
    };
    virtual void NotifyContinuationResult(int32_t result) override
    {};
    virtual void ContinueAbility(const std::string& deviceId, uint32_t versionCode) override
    {};
    virtual void DumpAbilityInfo(const std::vector<std::string>& params, std::vector<std::string>& info) override
    {};
    virtual void CallRequest() override
    {
        return;
    };
    virtual void OnExecuteIntent(const Want &want) override
    {};
    virtual int CreateModalUIExtension(const Want &want) override
    {
        return 0;
    };
    virtual void UpdateSessionToken(sptr<IRemoteObject> sessionToken) override {}

    virtual void ScheduleCollaborate(const Want &want) override {}

    virtual void ScheduleAbilityRequestFailure(const std::string &requestId, const AppExecFwk::ElementName &element,
        const std::string &message, int32_t resultCode) override
    {}

    virtual void ScheduleAbilityRequestSuccess(const std::string &requestId,
        const AppExecFwk::ElementName &element) override
    {}

    virtual void ScheduleAbilitiesRequestDone(const std::string &requestKey, int32_t resultCode) override
    {}
private:
    AbilityResult result_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_ABILITY_SCHEDULER_H
