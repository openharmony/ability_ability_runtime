/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_DATA_ABILITY_RECORD_H
#define OHOS_ABILITY_RUNTIME_DATA_ABILITY_RECORD_H

#include <list>
#include <string>
#include <memory>
#include <mutex>
#include <chrono>
#include "cpp/mutex.h"
#include "cpp/condition_variable.h"

#include "ability_record.h"
#include "data_ability_caller_recipient.h"

namespace OHOS {
namespace AAFwk {
class DataAbilityRecord : public std::enable_shared_from_this<DataAbilityRecord> {
public:
    explicit DataAbilityRecord(const AbilityRequest &req);
    virtual ~DataAbilityRecord();

public:
    /**
     * @brief Start loading the data ability
     * @return ERR_OK if successful, error code otherwise
     */
    int StartLoading();

    /**
     * @brief Wait for data ability to finish loading
     * @param mutex The mutex to lock while waiting
     * @param timeout Maximum duration to wait
     * @return ERR_OK if loaded successfully, error code otherwise
     */
    int WaitForLoaded(ffrt::mutex &mutex, const std::chrono::system_clock::duration &timeout);

    /**
     * @brief Get the ability scheduler
     * @return Pointer to the ability scheduler interface
     */
    sptr<IAbilityScheduler> GetScheduler();

    /**
     * @brief Attach ability scheduler
     * @param scheduler The scheduler to attach
     * @return ERR_OK if successful, error code otherwise
     */
    int Attach(const sptr<IAbilityScheduler> &scheduler);

    /**
     * @brief Handle state transition completion
     * @param state The new state after transition
     * @return ERR_OK if successful, error code otherwise
     */
    int OnTransitionDone(int state);

    /**
     * @brief Add a client to this data ability
     * @param client The client remote object to add
     * @param tryBind Whether to try binding to the client
     * @param isNotHap Whether the client is not a HAP application
     * @return ERR_OK if successful, error code otherwise
     */
    int AddClient(const sptr<IRemoteObject> &client, bool tryBind, bool isNotHap);

    /**
     * @brief Remove a client from this data ability
     * @param client The client remote object to remove
     * @param isNotHap Whether the client is not a HAP application
     * @return ERR_OK if successful, error code otherwise
     */
    int RemoveClient(const sptr<IRemoteObject> &client, bool isNotHap);

    /**
     * @brief Remove multiple clients associated with an ability record
     * @param client The ability record whose clients should be removed (nullptr for all)
     * @return ERR_OK if successful, error code otherwise
     */
    int RemoveClients(const std::shared_ptr<AbilityRecord> &client = nullptr);

    /**
     * @brief Get the count of connected clients
     * @param client Specific client to count (nullptr for all clients)
     * @return Number of connected clients
     */
    size_t GetClientCount(const sptr<IRemoteObject> &client = nullptr) const;

    /**
     * @brief Kill all bound client processes
     * @return ERR_OK if successful, error code otherwise
     */
    int KillBoundClientProcesses();

    /**
     * @brief Get the ability request that created this record
     * @return Reference to the ability request
     */
    const AbilityRequest &GetRequest() const;

    /**
     * @brief Get the associated ability record
     * @return Shared pointer to the ability record
     */
    std::shared_ptr<AbilityRecord> GetAbilityRecord();

    /**
     * @brief Get the token of this data ability
     * @return Remote object token
     */
    sptr<IRemoteObject> GetToken();

    /**
     * @brief Dump data ability record information to log
     */
    void Dump() const;

    /**
     * @brief Dump data ability record information to vector
     * @param info Output vector to store dump information
     */
    void Dump(std::vector<std::string> &info) const;

private:
    using IRemoteObjectPtr = sptr<IRemoteObject>;
    using AbilityRecordPtr = std::shared_ptr<AbilityRecord>;

    struct ClientInfo {
        IRemoteObjectPtr client;
        bool tryBind;
        bool isNotHap;
        int32_t clientPid = 0;
    };
    /**
     * @brief Handle scheduler death event
     * @param remote Weak pointer to the dead remote object
     * @note This is called when the ability scheduler dies unexpectedly
     */
    void OnSchedulerDied(const wptr<IRemoteObject> &remote);

    /**
     * @brief Get the process ID of a dead caller
     * @param remote Pointer to the dead remote object
     * @return Process ID of the dead caller
     */
    int32_t GetDiedCallerPid(const sptr<IRemoteObject> &remote);

private:
    sptr<IAbilityScheduler> scheduler_ {};
    sptr<IRemoteObject::DeathRecipient> callerDeathRecipient_;  // caller binderDied Recipient
    std::list<ClientInfo> clients_ {};
    ffrt::condition_variable loadedCond_ {};
    AbilityRequest request_ {};
    AbilityRecordPtr ability_ {};
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_DATA_ABILITY_RECORD_H
