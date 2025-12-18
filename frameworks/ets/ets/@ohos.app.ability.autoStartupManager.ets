/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import AutoStartupCallback from 'application.AutoStartupCallback';
import AutoStartupInfo from 'application.AutoStartupInfo';
import { AsyncCallback, BusinessError } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace autoStartupManager {
  loadLibrary("auto_startup_manager.z")
   
  export native function nativeOnApplicationAutoStartupStateChangeSync(type: string, callback: AutoStartupCallback): void;
  export native function nativeOffApplicationAutoStartupStateChangeSync(type: string, callback?: AutoStartupCallback): void;
  export native function nativeSetApplicationAutoStartup(info: AutoStartupInfo, callback: AsyncCallbackWrapper<void>): void;
  export native function autoStartupInfoCheck(info: AutoStartupInfo): void;
  export native function nativeCancelApplicationAutoStartup(info: AutoStartupInfo, callback: AsyncCallbackWrapper<void>): void;
  export native function nativeQueryAllAutoStartupApplications(callback: AsyncCallbackWrapper<Array<AutoStartupInfo>>): void;
  export native function nativeCheckCallerIsSystemApp(): void;

  export function onSystemAutoStartup(callback: AutoStartupCallback): void {
    autoStartupManager.nativeOnApplicationAutoStartupStateChangeSync('systemAutoStartup', callback);
  }

  export function offSystemAutoStartup(callback?: AutoStartupCallback): void {
    autoStartupManager.nativeOffApplicationAutoStartupStateChangeSync('systemAutoStartup', callback);
  }

  export function setApplicationAutoStartup(info: AutoStartupInfo, callback: AsyncCallback<void>): void {
    autoStartupManager.autoStartupInfoCheck(info);
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      autoStartupManager.nativeSetApplicationAutoStartup(info, myCall);
    });
  }

  export function setApplicationAutoStartup(info: AutoStartupInfo): Promise<void> {
    autoStartupManager.autoStartupInfoCheck(info);
    let p = new Promise<void>((resolve: (data: undefined)=>void, reject:(err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        autoStartupManager.nativeSetApplicationAutoStartup(info, myCall);
      });
    });
    return p;
  }

  export function cancelApplicationAutoStartup(info: AutoStartupInfo, callback: AsyncCallback<void>): void {
    autoStartupManager.autoStartupInfoCheck(info);
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      autoStartupManager.nativeCancelApplicationAutoStartup(info, myCall);
    });
  }

  export function cancelApplicationAutoStartup(info: AutoStartupInfo): Promise<void> {
    autoStartupManager.autoStartupInfoCheck(info);
    let p = new Promise<void>((resolve: (data: undefined)=>void, reject:(err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        autoStartupManager.nativeCancelApplicationAutoStartup(info, myCall);
      });
    });
    return p;
  }

  export function queryAllAutoStartupApplications(callback: AsyncCallback<Array<AutoStartupInfo>>): void {
    autoStartupManager.nativeCheckCallerIsSystemApp();
    let myCall = new AsyncCallbackWrapper<Array<AutoStartupInfo>>(callback);
    taskpool.execute((): void => {
      autoStartupManager.nativeQueryAllAutoStartupApplications(myCall);
    });
  }

  export function queryAllAutoStartupApplications(): Promise<Array<AutoStartupInfo>> {
    autoStartupManager.nativeCheckCallerIsSystemApp();
    let p = new Promise<Array<AutoStartupInfo>>((resolve: (data: Array<AutoStartupInfo>) => void,
      reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<Array<AutoStartupInfo>>((err: BusinessError | null,
        data: Array<AutoStartupInfo> | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as Array<AutoStartupInfo>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        autoStartupManager.nativeQueryAllAutoStartupApplications(myCall);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}