/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_USER_CONTROLLER_H
#define OHOS_ABILITY_RUNTIME_USER_CONTROLLER_H

#include <unordered_map>
#include <memory>
#include "cpp/mutex.h"

#include "user_event_handler.h"
#include "refbase.h"

namespace OHOS {
namespace AAFwk {
class IUserCallback;

const int32_t USER_ID_NO_HEAD = 0;
const int32_t USER_ID_DEFAULT = 100;

enum UserState {
    STATE_BOOTING = 0,
    STATE_STARTED,
    STATE_STOPPING,
    STATE_SHUTDOWN
};

class UserItem {
public:
    explicit UserItem(int32_t id);
    virtual ~UserItem();

    int32_t GetUserId();
    void SetState(const UserState &state);
    UserState GetState();

private:
    int32_t userId_;
    UserState curState_ = STATE_BOOTING;
    UserState lastState_ = STATE_BOOTING;
};

class UserEvent : public EventDataBase {
public:
    virtual ~UserEvent() = default;
    int32_t oldUserId;
    int32_t newUserId;
    std::shared_ptr<UserItem> userItem;
};

class UserController : public std::enable_shared_from_this<UserController> {
public:
    UserController();
    virtual ~UserController();

    void Init();

    /**
     * Start user, if it is not running..
     *
     * @param userId id of started user.
     * @param isForeground whether user should brout to foreground.
     * @return 0 if the user has been successfully started.
     */
    int StartUser(int32_t userId, sptr<IUserCallback> callback, bool isAppRecovery = false);

    /**
     * Stop user, if it is running..
     *
     * @param userId id of started user.
     * @return 0 if the user has been successfully started.
     */
    int32_t StopUser(int32_t userId);

    /**
     * Logout user, if it is running..
     *
     * @param userId id of Logout user.
     * @return 0 if the user has been successfully Logout.
     */
    int32_t LogoutUser(int32_t userId, sptr<IUserCallback> callback = nullptr);

    int32_t GetCurrentUserId();

    std::shared_ptr<UserItem> GetUserItem(int32_t userId);

    void ProcessEvent(const EventWrap &event);

    int32_t GetFreezingNewUserId() const;

    void SetFreezingNewUserId(int32_t userId);

    void ClearAbilityUserItems(int32_t userId);

private:
    bool IsCurrentUser(int32_t userId);
    bool IsExistOsAccount(int32_t userId) const;
    std::shared_ptr<UserItem> GetOrCreateUserItem(int32_t userId);
    void SetCurrentUserId(int32_t userId);
    int MoveUserToForeground(int32_t oldUserId, int32_t newUserId, sptr<IUserCallback> callback,
        bool isAppRecovery = false);
    void UserBootDone(std::shared_ptr<UserItem> &item);
    void BroadcastUserBackground(int32_t userId);
    void BroadcastUserForeground(int32_t userId);
    void BroadcastUserStopping(int32_t userId);
    void BroadcastUserStopped(int32_t userId);

    void SendSystemUserStart(int32_t userId);
    void SendSystemUserCurrent(int32_t oldUserId, int32_t newUserId);
    void SendReportUserSwitch(int32_t oldUserId, int32_t newUserId,
        std::shared_ptr<UserItem> &usrItem);
    void SendUserSwitchTimeout(int32_t oldUserId, int32_t newUserId,
        std::shared_ptr<UserItem> &usrItem);
    void SendContinueUserSwitch(int32_t oldUserId, int32_t newUserId,
        std::shared_ptr<UserItem> &usrItem);
    void SendUserSwitchDone(int32_t userId);

    void HandleSystemUserStart(int32_t userId);
    void HandleSystemUserCurrent(int32_t oldUserId, int32_t newUserId);
    void HandleReportUserSwitch(int32_t oldUserId, int32_t newUserId,
        std::shared_ptr<UserItem> &usrItem);
    void HandleUserSwitchTimeout(int32_t oldUserId, int32_t newUserId,
        std::shared_ptr<UserItem> &usrItem);
    void HandleContinueUserSwitch(int32_t oldUserId, int32_t newUserId,
        std::shared_ptr<UserItem> &usrItem);
    void HandleUserSwitchDone(int32_t userId);
    int32_t StartNoHeadUser(int32_t userId, sptr<IUserCallback> callback) const;

private:
    int32_t currentUserId_ = USER_ID_NO_HEAD;
    int32_t freezingNewUserId_ = -1;
    std::shared_ptr<UserEventHandler> eventHandler_;
    std::unordered_map<int32_t, std::shared_ptr<UserItem>> userItems_;
    ffrt::mutex userLock_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_USER_CONTROLLER_H
