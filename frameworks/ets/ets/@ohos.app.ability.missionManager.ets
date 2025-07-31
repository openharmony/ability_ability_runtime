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
import { BusinessError, AsyncCallback } from '@ohos.base';
import { MissionInfo as _MissionInfo } from 'application.MissionInfo';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace missionManager {
  loadLibrary("missionmanager_ani.z")
  export native function nativeClearAllMissions(callback: AsyncCallbackWrapper<void>): void;
  export native function nativeGetMissionInfo(deviceId: string, missionId: int,
    callback: AsyncCallbackWrapper<MissionInfo>): void;

  export function clearAllMissions(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      missionManager.nativeClearAllMissions(myCall);
    });
  }

  export function clearAllMissions(): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError | null) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          missionManager.nativeClearAllMissions(myCall);
        });
      });
    return p;
  }

  export function getMissionInfo(deviceId: string, missionId: int, callback: AsyncCallback<MissionInfo>): void {
    let myCall = new AsyncCallbackWrapper<MissionInfo>(callback);
    taskpool.execute((): void => {
      missionManager.nativeGetMissionInfo(deviceId, missionId, myCall);
    });
  }

  export function getMissionInfo(deviceId: string, missionId: int): Promise<MissionInfo> {
    let p =
      new Promise<MissionInfo>((resolve: (data: MissionInfo) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<MissionInfo>((err: BusinessError | null, data: MissionInfo | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as MissionInfo);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          missionManager.nativeGetMissionInfo(deviceId, missionId, myCall);
        });
      });
    return p;
  }

  export type MissionInfo = _MissionInfo;
}