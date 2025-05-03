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

import Context from 'application.Context'
import EnvironmentCallback from '@ohos.app.ability.EnvironmentCallback';
import { BusinessError, AsyncCallback } from '@ohos.base'
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import Want from '@ohos.app.ability.Want';

export default class ApplicationContext extends Context {
  public native nativekillAllProcessesSync(clearPageStack: boolean, callback: AsyncCallbackWrapper<void>): void;
  public native nativeOnSync(type: 'environment', callback: EnvironmentCallback): number;
  public native nativeOffSync(type: 'environment', callbackId: number, callback: AsyncCallbackWrapper<void>): void;
  public native nativepreloadUIExtensionAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  public native setSupportedProcessCacheSync(isSupported: boolean): void;

  setSupportedProcessCache(isSupported: boolean): void {
    taskpool.execute((): void => {
      this.setSupportedProcessCacheSync(isSupported);
    });
  }

  on(type: 'environment', callback: EnvironmentCallback): number {
    return this.nativeOnSync(type, callback);
  }

  off(type: 'environment', callbackId: number, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeOffSync(type, callbackId, myCall);
    });
  }

  off(type: 'environment', callbackId: number): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeOffSync(type, callbackId, myCall);
        });
      });
    return p;
  }

  preloadUIExtensionAbility(want: Want): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativepreloadUIExtensionAbilitySync(want, myCall);
        });
      });
    return p;
  }

  killAllProcesses(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativekillAllProcessesSync(false, myCall);
    });
  }

  killAllProcesses(): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativekillAllProcessesSync(false, myCall);
        });
      });
    return p;
  }

  killAllProcesses(clearPageStack: boolean): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativekillAllProcessesSync(clearPageStack, myCall);
        });
      });
    return p;
  }
}